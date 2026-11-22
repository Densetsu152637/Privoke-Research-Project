//! Routing of `PrivokeRuntimeService` calls between the Rust analysis worker (stage 17) and the Python worker.
//!
//! Both workers speak the same W1 frames, so the controller (and the analysis service) can hold one pool of each and
//! send every call to the worker that serves it. A route is decided by the RPC path and, for `AnalyzePrompt`, by the
//! layer selection, and only ever to a worker that is known to serve exactly that: the Python worker is the answer for
//! anything the Rust worker does not claim. The claim is a [`Capabilities`] value, so a later stage that ports another
//! part changes one constant, not the router.
//!
//! A route is decided **per request**, from what the request itself says: the layer selection and the presence gate of an
//! `AnalyzePrompt`, the model of a `DetectAnnotationPresence`, the training admission header of a gradient RPC. What only
//! the model's own metadata can tell (an artifact that declares an optimizer or diagnostics policy, a row without an
//! explicit target) the Rust worker finds out before it executes anything and answers `UNSUPPORTED_ROUTE`; [`call_routed`]
//! then sends the same call to the Python worker. Nothing has run when that answer is sent, so a call is never executed
//! twice.
//!
//! A Rust worker that is down, or that fails after it started executing, is a failed call, not a silent fallback: the
//! routing table says which engine owns the call.

use std::future::Future;

use privoke_contracts::proto::v1::{AnalyzePromptRequest, DetectAnnotationPresenceRequest};

/// The gRPC service whose paths are routed.
pub const SERVICE: &str = "privoke.v1.PrivokeRuntimeService";

/// The worker that serves a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// The Python worker (`worker_main.py` behind `worker_shim.py`).
    Python,
    /// The Rust worker (`privoke-runtime-worker`).
    Rust,
}

/// A `PrivokeRuntimeService` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rpc {
    /// `AnalyzePrompt`.
    AnalyzePrompt,
    /// `DetectAnnotationPresence`.
    DetectAnnotationPresence,
    /// `Health`.
    Health,
    /// `ComputeSemanticGradients`.
    ComputeSemanticGradients,
    /// `ComputeUnderlyingModelGradients`.
    ComputeUnderlyingModelGradients,
    /// `ComputePresenceGradients`.
    ComputePresenceGradients,
}

impl Rpc {
    /// The method for a gRPC path (`/privoke.v1.PrivokeRuntimeService/AnalyzePrompt`). Anything else is `None`.
    pub fn from_path(path: &str) -> Option<Self> {
        let method = path.strip_prefix('/')?.strip_prefix(SERVICE)?.strip_prefix('/')?;
        Some(match method {
            "AnalyzePrompt" => Self::AnalyzePrompt,
            "DetectAnnotationPresence" => Self::DetectAnnotationPresence,
            "Health" => Self::Health,
            "ComputeSemanticGradients" => Self::ComputeSemanticGradients,
            "ComputeUnderlyingModelGradients" => Self::ComputeUnderlyingModelGradients,
            "ComputePresenceGradients" => Self::ComputePresenceGradients,
            _ => return None,
        })
    }
}

/// What a worker serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// `AnalyzePrompt` with the regex layer.
    pub regex: bool,
    /// `AnalyzePrompt` with the NER layer.
    pub ner: bool,
    /// `AnalyzePrompt` with the semantic layer (and the semantic model fetch behind it).
    pub semantic: bool,
    /// `DetectAnnotationPresence` and the sparse presence gate of `AnalyzePrompt`. The worker reads the presence models
    /// from its model roots, like the semantic ones.
    pub presence: bool,
    /// The gradient RPCs, for the request shapes the Rust worker serves (see [`route_gradients`]); the rest it declines
    /// before it executes them. The worker reads the models from its model roots.
    pub gradients: bool,
}

impl Capabilities {
    /// What the Rust worker serves: `Health`, the regex and NER layers, and, when it is given model roots (see
    /// [`Capabilities::without_models`] and [`Capabilities::with_semantic`]), presence and the gradient RPCs.
    pub const RUST: Self = Self { regex: true, ner: true, semantic: false, presence: true, gradients: true };

    /// The Rust worker with the semantic layer, which it has when it is given model roots.
    #[must_use]
    pub const fn with_semantic(mut self) -> Self {
        self.semantic = true;
        self
    }

    /// The Rust worker started without model roots: everything that reads a model is the Python worker's.
    #[must_use]
    pub const fn without_models(mut self) -> Self {
        self.semantic = false;
        self.presence = false;
        self.gradients = false;
        self
    }
}

/// `PRETRAINED_CONTEXT_MODEL_ID`: the pretrained contextual encoder, a semantic model the Rust worker serves (RUST-S17B)
/// when it has model roots and the encoder assets; without the assets it answers the layer's error, as the Python worker
/// does (which does not serve that model at all).
#[cfg(test)]
const PRETRAINED_CONTEXT_MODEL_ID: &str = "privoke-pretrained-context-minilm";

/// The scratch presence models, which only the Python worker names (and then refuses, as no W1 worker serves them).
const SCRATCH_PRESENCE_PREFIX: &str = "privoke-scratch-presence-";

/// The engine for an `AnalyzePrompt`: the layer selection decides, except that a
/// scratch presence gate is Python's whatever the layers are, and a sparse presence gate is the Rust worker's only when it
/// serves both the semantic layer and presence.
pub fn route_analysis(rust: Option<Capabilities>, request: &AnalyzePromptRequest) -> Engine {
    if let Some(gate) = &request.semantic_presence_gate {
        let served = rust.is_some_and(|capabilities| capabilities.semantic && capabilities.presence);
        if !served || gate.model_id.starts_with(SCRATCH_PRESENCE_PREFIX) {
            return Engine::Python;
        }
    }
    route(rust, Rpc::AnalyzePrompt, &request.layers)
}

/// The engine for a `DetectAnnotationPresence`: the Rust worker serves the sparse presence models; a scratch model is
/// Python's.
pub fn route_presence(rust: Option<Capabilities>, request: &DetectAnnotationPresenceRequest) -> Engine {
    if request.model_id.starts_with(SCRATCH_PRESENCE_PREFIX) {
        return Engine::Python;
    }
    route(rust, Rpc::DetectAnnotationPresence, &request.layers)
}

/// The objective admission of the summed-margin objective (`expected_objective` of schema 2).
const SUM_MARGIN_OBJECTIVE: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
/// The objectives a backtracking admission (schema 1) may name that the Rust worker serves.
const BACKTRACKING_OBJECTIVES: [&str; 3] = ["legacy_sum_category", "class_balanced_contextual_v1", SUM_MARGIN_OBJECTIVE];
/// The TRAIN diagnostics policy.
const DIAGNOSTICS_POLICY: &str = "train_before_candidate_v1";
/// The backtracking policy.
const BACKTRACKING_POLICY: &str = "full_train_backtracking_v1";
/// The longest admission header the Python parser reads.
const MAX_ADMISSION_BYTES: usize = 2_048;

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// True when a training admission header is one of the two records the Rust worker serves:
///
/// * the objective-only record (schema 2): exactly the keys `schema`, `expected_objective` (the summed-margin objective)
///   and `expected_diagnostics_policy` (null or the TRAIN diagnostics policy);
/// * the backtracking record (schema 1): exactly the keys `schema`, `expected_objective` (legacy, class-balanced or
///   summed-margin), `expected_diagnostics_policy` (the TRAIN diagnostics policy), `expected_backtracking_policy` and
///   `expected_backtracking_preparation_sha256` (64 lower-case hexadecimal digits).
///
/// Every other header (FULL Adam, retention, window, or anything malformed) is Python's to read.
pub fn admission_is_served(header: &str) -> bool {
    if header.len() > MAX_ADMISSION_BYTES {
        return false;
    }
    let Ok(serde_json::Value::Object(record)) = serde_json::from_str::<serde_json::Value>(header) else { return false };
    let text = |key: &str| record.get(key).and_then(serde_json::Value::as_str);
    let diagnostics = record.get("expected_diagnostics_policy");
    match record.get("schema").and_then(serde_json::Value::as_i64) {
        Some(2) => {
            record.len() == 3
                && text("expected_objective") == Some(SUM_MARGIN_OBJECTIVE)
                && diagnostics.is_some_and(|value| value.is_null() || value.as_str() == Some(DIAGNOSTICS_POLICY))
        }
        Some(1) => {
            record.len() == 5
                && text("expected_objective").is_some_and(|objective| BACKTRACKING_OBJECTIVES.contains(&objective))
                && diagnostics.and_then(serde_json::Value::as_str) == Some(DIAGNOSTICS_POLICY)
                && text("expected_backtracking_policy") == Some(BACKTRACKING_POLICY)
                && text("expected_backtracking_preparation_sha256").is_some_and(is_sha256)
        }
        _ => false,
    }
}

/// The engine for a gradient RPC. `admission` is the value of the `x-privoke-training-admission-v1` header, when the
/// request carries one. `ComputePresenceGradients` has no header; the other two go to Rust with no header, the
/// objective-only one (schema 2) or the backtracking one (schema 1), and to Python with any other.
pub fn route_gradients(rust: Option<Capabilities>, rpc: Rpc, admission: Option<&str>) -> Engine {
    let to_rust = match rpc {
        Rpc::ComputePresenceGradients => true,
        Rpc::ComputeSemanticGradients | Rpc::ComputeUnderlyingModelGradients => admission.is_none_or(admission_is_served),
        Rpc::AnalyzePrompt | Rpc::DetectAnnotationPresence | Rpc::Health => false,
    };
    if to_rust { route(rust, rpc, &[]) } else { Engine::Python }
}

/// The `ERROR` frame code a Rust worker sends for a request it declines **before executing anything**.
pub const UNSUPPORTED_ROUTE: &str = "UNSUPPORTED_ROUTE";
/// The same refusal for a layer selection (`AnalyzePrompt`).
pub const UNSUPPORTED_LAYERS: &str = "UNSUPPORTED_LAYERS";

/// True for the error codes of a call that was refused before it ran, which may be sent to the other engine.
pub fn is_refusal(code: &str) -> bool {
    code == UNSUPPORTED_ROUTE || code == UNSUPPORTED_LAYERS
}

/// A failed attempt on one engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt<E> {
    /// The worker refused the call before executing it; the error is what it said.
    Refused(E),
    /// The call failed (it may have started executing); it is never sent anywhere else.
    Failed(E),
}

/// Makes a call on the engine the route names. When the Rust worker refuses it before executing anything
/// ([`Attempt::Refused`]), the same call is made once on the Python worker; every other failure is the call's result.
pub async fn call_routed<T, E, F, Fut>(first: Engine, mut call: F) -> Result<T, E>
where
    F: FnMut(Engine) -> Fut,
    Fut: Future<Output = Result<T, Attempt<E>>>,
{
    match call(first).await {
        Ok(value) => Ok(value),
        Err(Attempt::Failed(error)) => Err(error),
        Err(Attempt::Refused(error)) if first == Engine::Python => Err(error),
        Err(Attempt::Refused(_)) => match call(Engine::Python).await {
            Ok(value) => Ok(value),
            Err(Attempt::Failed(error) | Attempt::Refused(error)) => Err(error),
        },
    }
}

/// The `DetectionLayer` enum values the layers use.
const REGEX: i32 = 2;
const NER: i32 = 3;
const SEMANTIC: i32 = 4;

fn serves(capabilities: Capabilities, layers: &[i32]) -> bool {
    // An empty selection, the runtime layer and any value this router does not know are never routed to Rust: the
    // Python worker rejects the first two with `INVALID_LAYERS` and answers the third as the oracle does.
    !layers.is_empty()
        && layers.iter().all(|layer| match *layer {
            REGEX => capabilities.regex,
            NER => capabilities.ner,
            SEMANTIC => capabilities.semantic,
            _ => false,
        })
}

/// The engine for a call. `rust` is what the Rust worker serves, or `None` when no Rust worker is configured.
pub fn route(rust: Option<Capabilities>, rpc: Rpc, layers: &[i32]) -> Engine {
    let Some(capabilities) = rust else { return Engine::Python };
    let to_rust = match rpc {
        Rpc::Health => true,
        Rpc::AnalyzePrompt => serves(capabilities, layers),
        Rpc::DetectAnnotationPresence => capabilities.presence && layers == [SEMANTIC],
        Rpc::ComputeSemanticGradients | Rpc::ComputeUnderlyingModelGradients | Rpc::ComputePresenceGradients => capabilities.gradients,
    };
    if to_rust { Engine::Rust } else { Engine::Python }
}

/// How `PRIVOKE_RUNTIME_ANALYSIS_ENGINE` selects the engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Python only (the default): no Rust worker is started.
    Python,
    /// The Rust worker for what it serves, the Python worker for the rest.
    Rust,
}

impl Selection {
    /// Reads the setting: `python` (default) or `rust`, in any case.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(|text| text.trim().to_ascii_lowercase()).as_deref() {
            None | Some("" | "python") => Ok(Self::Python),
            Some("rust") => Ok(Self::Rust),
            Some(other) => Err(format!("PRIVOKE_RUNTIME_ANALYSIS_ENGINE must be python or rust, not {other:?}.")),
        }
    }

    /// The capabilities of the Rust worker under this selection.
    pub fn rust_capabilities(self) -> Option<Capabilities> {
        (self == Self::Rust).then_some(Capabilities::RUST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_the_service_methods() {
        assert_eq!(Rpc::from_path("/privoke.v1.PrivokeRuntimeService/AnalyzePrompt"), Some(Rpc::AnalyzePrompt));
        assert_eq!(Rpc::from_path("/privoke.v1.PrivokeRuntimeService/ComputePresenceGradients"), Some(Rpc::ComputePresenceGradients));
        assert_eq!(Rpc::from_path("/privoke.v1.PrivokeRuntimeControlService/Status"), None);
        assert_eq!(Rpc::from_path("/privoke.v1.PrivokeRuntimeService/Nope"), None);
        assert_eq!(Rpc::from_path("privoke.v1.PrivokeRuntimeService/Health"), None);
    }

    #[test]
    fn without_a_rust_worker_everything_is_python() {
        for rpc in [Rpc::AnalyzePrompt, Rpc::Health, Rpc::ComputeSemanticGradients] {
            assert_eq!(route(None, rpc, &[REGEX]), Engine::Python);
        }
    }

    #[test]
    fn analysis_goes_to_rust_only_for_layers_it_serves() {
        let rust = Some(Capabilities::RUST);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[REGEX]), Engine::Rust);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[NER, REGEX]), Engine::Rust);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[SEMANTIC]), Engine::Python);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[REGEX, NER, SEMANTIC]), Engine::Python);
        // Never an implicit pipeline, and never a value the router does not know.
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[]), Engine::Python);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[1]), Engine::Python);
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[0, REGEX]), Engine::Python);
    }

    fn gate(model_id: &str) -> Option<privoke_contracts::proto::v1::SemanticPresenceGate> {
        Some(privoke_contracts::proto::v1::SemanticPresenceGate { model_id: model_id.to_string(), threshold: None })
    }

    #[test]
    fn semantic_goes_to_rust_only_when_it_has_models_and_no_unserved_gate() {
        let with_models = Some(Capabilities::RUST.with_semantic());
        let request = |layers: Vec<i32>| AnalyzePromptRequest { layers, ..AnalyzePromptRequest::default() };
        assert_eq!(route_analysis(with_models, &request(vec![SEMANTIC])), Engine::Rust);
        assert_eq!(route_analysis(with_models, &request(vec![REGEX, NER, SEMANTIC])), Engine::Rust);
        assert_eq!(route_analysis(Some(Capabilities::RUST), &request(vec![SEMANTIC])), Engine::Python);
        let mut context = request(vec![SEMANTIC]);
        context.semantic_model_id = PRETRAINED_CONTEXT_MODEL_ID.to_string();
        assert_eq!(route_analysis(with_models, &context), Engine::Rust, "the contextual encoder is a semantic model of the Rust worker");
        assert_eq!(route_analysis(Some(Capabilities::RUST), &context), Engine::Python, "no model roots: Python");
        assert_eq!(route_analysis(with_models, &request(vec![])), Engine::Python);
    }

    #[test]
    fn a_sparse_presence_gate_goes_to_rust_with_models_and_a_scratch_gate_never_does() {
        let with_models = Some(Capabilities::RUST.with_semantic());
        let gated = |model_id: &str, layers: Vec<i32>| AnalyzePromptRequest {
            layers,
            semantic_model_id: "privoke-balanced".to_string(),
            semantic_presence_gate: gate(model_id),
            ..AnalyzePromptRequest::default()
        };
        for layers in [vec![SEMANTIC], vec![REGEX, SEMANTIC]] {
            assert_eq!(route_analysis(with_models, &gated("privoke-presence-efficient", layers.clone())), Engine::Rust);
            assert_eq!(route_analysis(with_models, &gated("privoke-scratch-presence-efficient-head-only", layers.clone())), Engine::Python);
            // No model roots, or no Rust worker: the Python worker.
            assert_eq!(
                route_analysis(Some(Capabilities::RUST.without_models()), &gated("privoke-presence-efficient", layers.clone())),
                Engine::Python
            );
            assert_eq!(route_analysis(None, &gated("privoke-presence-efficient", layers)), Engine::Python);
        }
        // Without the presence capability a gate is Python's even when the semantic layer is served.
        let no_presence = Some(Capabilities { presence: false, ..Capabilities::RUST.with_semantic() });
        assert_eq!(route_analysis(no_presence, &gated("privoke-presence-efficient", vec![SEMANTIC])), Engine::Python);
        // An empty selection is never the Rust worker's, gate or not.
        assert_eq!(route_analysis(with_models, &gated("privoke-presence-efficient", vec![])), Engine::Python);
    }

    #[test]
    fn presence_inference_goes_to_rust_for_a_semantic_only_selection_on_a_sparse_model() {
        let rust = Some(Capabilities::RUST.with_semantic());
        let request = |model_id: &str, layers: Vec<i32>| DetectAnnotationPresenceRequest {
            model_id: model_id.to_string(),
            layers,
            ..DetectAnnotationPresenceRequest::default()
        };
        assert_eq!(route_presence(rust, &request("privoke-presence-balanced", vec![SEMANTIC])), Engine::Rust);
        assert_eq!(route_presence(rust, &request("privoke-scratch-presence-quality-full-encoder", vec![SEMANTIC])), Engine::Python);
        for layers in [vec![], vec![REGEX], vec![REGEX, SEMANTIC]] {
            assert_eq!(route_presence(rust, &request("privoke-presence-balanced", layers)), Engine::Python);
        }
        assert_eq!(
            route_presence(Some(Capabilities::RUST.without_models()), &request("privoke-presence-balanced", vec![SEMANTIC])),
            Engine::Python
        );
        assert_eq!(route_presence(None, &request("privoke-presence-balanced", vec![SEMANTIC])), Engine::Python);
    }

    const OBJECTIVE_ONLY: &str = "{\"schema\": 2, \"expected_objective\": \"class_balanced_contextual_sum_category_decision_margin_v1\", \"expected_diagnostics_policy\": null}";
    const WITH_DIAGNOSTICS: &str = "{\"schema\": 2, \"expected_objective\": \"class_balanced_contextual_sum_category_decision_margin_v1\", \"expected_diagnostics_policy\": \"train_before_candidate_v1\"}";
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn backtracking(objective: &str, sha: &str) -> String {
        format!(
            "{{\"schema\": 1, \"expected_objective\": \"{objective}\", \"expected_diagnostics_policy\": \"train_before_candidate_v1\", \"expected_backtracking_policy\": \"full_train_backtracking_v1\", \"expected_backtracking_preparation_sha256\": \"{sha}\"}}"
        )
    }

    #[test]
    fn gradient_requests_are_routed_by_their_admission_header() {
        let rust = Some(Capabilities::RUST.with_semantic());
        let semantic = [Rpc::ComputeSemanticGradients, Rpc::ComputeUnderlyingModelGradients];
        for rpc in semantic {
            // No header, the objective-only header with or without the diagnostics policy, and the backtracking header
            // of each served objective: the Rust worker.
            assert_eq!(route_gradients(rust, rpc, None), Engine::Rust);
            assert_eq!(route_gradients(rust, rpc, Some(OBJECTIVE_ONLY)), Engine::Rust);
            assert_eq!(route_gradients(rust, rpc, Some(WITH_DIAGNOSTICS)), Engine::Rust);
            for objective in ["legacy_sum_category", "class_balanced_contextual_v1", SUM_MARGIN_OBJECTIVE] {
                assert_eq!(route_gradients(rust, rpc, Some(&backtracking(objective, SHA))), Engine::Rust, "{objective}");
            }
            // FULL Adam (3), retention (4), window (5), other objectives, a malformed backtracking record and garbage.
            for header in [
                backtracking("x", SHA),
                backtracking("class_balanced_contextual_mean_category_v1", SHA),
                backtracking("legacy_sum_category", "00"),
                backtracking("legacy_sum_category", &SHA.to_uppercase()),
                backtracking("legacy_sum_category", SHA).replace("full_train_backtracking_v1", "other_v1"),
                backtracking("legacy_sum_category", SHA).replace("\"train_before_candidate_v1\"", "null"),
                backtracking("legacy_sum_category", SHA).replace(", \"expected_backtracking_policy\": \"full_train_backtracking_v1\"", ""),
                "{\"schema\": 3, \"expected_optimizer\": \"full_projected_adam64_v1\"}".to_string(),
                "{\"schema\": 4}".to_string(),
                "{\"schema\": 5}".to_string(),
                "{\"schema\": 2, \"expected_objective\": \"class_balanced_contextual_v1\", \"expected_diagnostics_policy\": null}"
                    .to_string(),
                WITH_DIAGNOSTICS.replace("train_before_candidate_v1", "another_policy_v1"),
                OBJECTIVE_ONLY.replace("\"schema\": 2", "\"schema\": 1"),
                "not json".to_string(),
                "[]".to_string(),
                String::new(),
            ] {
                assert_eq!(route_gradients(rust, rpc, Some(&header)), Engine::Python, "{header}");
            }
            assert_eq!(route_gradients(None, rpc, None), Engine::Python);
            assert_eq!(route_gradients(Some(Capabilities::RUST.without_models()), rpc, None), Engine::Python);
            assert_eq!(route_gradients(Some(Capabilities::RUST.without_models()), rpc, Some(OBJECTIVE_ONLY)), Engine::Python);
            assert_eq!(route_gradients(None, rpc, Some(&backtracking("legacy_sum_category", SHA))), Engine::Python);
        }
        // Presence gradients read no header.
        assert_eq!(route_gradients(rust, Rpc::ComputePresenceGradients, None), Engine::Rust);
        assert_eq!(route_gradients(rust, Rpc::ComputePresenceGradients, Some("{\"schema\": 3}")), Engine::Rust);
        assert_eq!(route_gradients(Some(Capabilities::RUST.without_models()), Rpc::ComputePresenceGradients, None), Engine::Python);
        // Other methods are not gradient requests.
        assert_eq!(route_gradients(rust, Rpc::AnalyzePrompt, None), Engine::Python);
    }

    #[test]
    fn an_oversized_admission_header_is_pythons() {
        let padded = OBJECTIVE_ONLY.replace('}', &format!(", \"pad\": \"{}\"}}", "x".repeat(2_100)));
        assert!(padded.len() > MAX_ADMISSION_BYTES);
        assert!(!admission_is_served(&padded));
    }

    #[test]
    fn the_rust_worker_claims_presence_and_gradients_and_nothing_else_changed() {
        let claimed = Capabilities::RUST;
        assert_eq!((claimed.presence, claimed.gradients, claimed.semantic), (true, true, false));
        let without = Capabilities::RUST.without_models();
        assert_eq!((without.regex, without.ner, without.semantic, without.presence, without.gradients), (true, true, false, false, false));
        let rust = Some(Capabilities::RUST);
        assert_eq!(route(rust, Rpc::Health, &[]), Engine::Rust);
        assert_eq!(route(rust, Rpc::DetectAnnotationPresence, &[SEMANTIC]), Engine::Rust);
        assert_eq!(route(rust, Rpc::DetectAnnotationPresence, &[]), Engine::Python);
        for rpc in [Rpc::ComputeSemanticGradients, Rpc::ComputeUnderlyingModelGradients, Rpc::ComputePresenceGradients] {
            assert_eq!(route(rust, rpc, &[SEMANTIC]), Engine::Rust);
        }
        assert_eq!(route(rust, Rpc::AnalyzePrompt, &[SEMANTIC]), Engine::Python);
    }

    /// A stand-in for the two workers: counts the executions on each engine and refuses what it is told to refuse.
    struct Workers {
        rust_runs: std::sync::atomic::AtomicUsize,
        python_runs: std::sync::atomic::AtomicUsize,
        rust_answer: Result<&'static str, Attempt<&'static str>>,
    }

    impl Workers {
        fn new(rust_answer: Result<&'static str, Attempt<&'static str>>) -> Self {
            Self { rust_runs: 0.into(), python_runs: 0.into(), rust_answer }
        }

        async fn call(&self, engine: Engine) -> Result<&'static str, Attempt<&'static str>> {
            use std::sync::atomic::Ordering::SeqCst;
            match engine {
                Engine::Python => {
                    self.python_runs.fetch_add(1, SeqCst);
                    Ok("python")
                }
                Engine::Rust => {
                    // A refusal executes nothing; an answer or a failure after the start does.
                    if !matches!(self.rust_answer, Err(Attempt::Refused(_))) {
                        self.rust_runs.fetch_add(1, SeqCst);
                    }
                    self.rust_answer.clone()
                }
            }
        }

        fn runs(&self) -> (usize, usize) {
            use std::sync::atomic::Ordering::SeqCst;
            (self.rust_runs.load(SeqCst), self.python_runs.load(SeqCst))
        }
    }

    #[tokio::test]
    async fn a_refused_call_runs_once_on_python_and_never_twice() {
        let workers = Workers::new(Err(Attempt::Refused(UNSUPPORTED_ROUTE)));
        assert_eq!(call_routed(Engine::Rust, |engine| workers.call(engine)).await, Ok("python"));
        assert_eq!(workers.runs(), (0, 1));
    }

    #[tokio::test]
    async fn an_answered_call_is_not_repeated_and_a_failed_one_is_not_retried() {
        let answered = Workers::new(Ok("rust"));
        assert_eq!(call_routed(Engine::Rust, |engine| answered.call(engine)).await, Ok("rust"));
        assert_eq!(answered.runs(), (1, 0));
        let failed = Workers::new(Err(Attempt::Failed("DEADLINE_EXCEEDED")));
        assert_eq!(call_routed(Engine::Rust, |engine| failed.call(engine)).await, Err("DEADLINE_EXCEEDED"));
        assert_eq!(failed.runs(), (1, 0));
    }

    #[tokio::test]
    async fn a_call_routed_to_python_is_never_sent_to_rust() {
        let workers = Workers::new(Ok("rust"));
        assert_eq!(call_routed(Engine::Python, |engine| workers.call(engine)).await, Ok("python"));
        assert_eq!(workers.runs(), (0, 1));
    }

    #[test]
    fn only_a_refusal_code_may_be_sent_to_the_other_engine() {
        assert!(is_refusal("UNSUPPORTED_ROUTE") && is_refusal("UNSUPPORTED_LAYERS"));
        for code in ["INTERNAL", "DEADLINE_EXCEEDED", "INVALID_LAYERS", "RESPONSE_TOO_LARGE", ""] {
            assert!(!is_refusal(code), "{code}");
        }
    }

    #[test]
    fn the_engine_setting_is_python_unless_rust_is_named() {
        assert_eq!(Selection::parse(None), Ok(Selection::Python));
        assert_eq!(Selection::parse(Some(" ")), Ok(Selection::Python));
        assert_eq!(Selection::parse(Some("Rust")), Ok(Selection::Rust));
        assert!(Selection::parse(Some("both")).is_err());
        assert_eq!(Selection::Python.rust_capabilities(), None);
        assert_eq!(Selection::Rust.rust_capabilities(), Some(Capabilities::RUST));
        assert_eq!(Selection::Rust.rust_capabilities().map(|capabilities| capabilities.semantic), Some(false));
    }
}
