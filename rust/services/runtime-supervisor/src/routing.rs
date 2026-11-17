//! Routing of `PrivokeRuntimeService` calls between the Rust analysis worker (stage 17) and the Python worker.
//!
//! Both workers speak the same W1 frames, so the controller (and the analysis service) can hold one pool of each and
//! send every call to the worker that serves it. A route is decided by the RPC path and, for `AnalyzePrompt`, by the
//! layer selection, and only ever to a worker that is known to serve exactly that: the Python worker is the answer for
//! anything the Rust worker does not claim. The claim is a [`Capabilities`] value, so a later stage that ports another
//! part (the semantic layer, annotation presence, the gradient RPCs of stage 19) changes one constant, not the router.
//!
//! No call is retried on the other engine: a Rust worker that is down is a failed call, not a silent fallback, because
//! the routing table says which engine owns the call.

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
    /// `DetectAnnotationPresence`.
    pub presence: bool,
    /// The three gradient RPCs.
    pub gradients: bool,
}

impl Capabilities {
    /// What the Rust worker serves today (stage 17, checkpoint 1): `Health` and the regex and NER layers.
    pub const RUST: Self = Self { regex: true, ner: true, semantic: false, presence: false, gradients: false };
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
        Rpc::DetectAnnotationPresence => capabilities.presence,
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

    #[test]
    fn presence_and_gradients_stay_on_python_until_they_are_claimed() {
        let rust = Some(Capabilities::RUST);
        assert_eq!(route(rust, Rpc::Health, &[]), Engine::Rust);
        assert_eq!(route(rust, Rpc::DetectAnnotationPresence, &[SEMANTIC]), Engine::Python);
        for rpc in [Rpc::ComputeSemanticGradients, Rpc::ComputeUnderlyingModelGradients, Rpc::ComputePresenceGradients] {
            assert_eq!(route(rust, rpc, &[SEMANTIC]), Engine::Python);
        }
        let claimed = Some(Capabilities { semantic: true, presence: true, gradients: true, ..Capabilities::RUST });
        assert_eq!(route(claimed, Rpc::AnalyzePrompt, &[SEMANTIC]), Engine::Rust);
        assert_eq!(route(claimed, Rpc::DetectAnnotationPresence, &[SEMANTIC]), Engine::Rust);
        assert_eq!(route(claimed, Rpc::ComputeUnderlyingModelGradients, &[SEMANTIC]), Engine::Rust);
    }

    #[test]
    fn the_engine_setting_is_python_unless_rust_is_named() {
        assert_eq!(Selection::parse(None), Ok(Selection::Python));
        assert_eq!(Selection::parse(Some(" ")), Ok(Selection::Python));
        assert_eq!(Selection::parse(Some("Rust")), Ok(Selection::Rust));
        assert!(Selection::parse(Some("both")).is_err());
        assert_eq!(Selection::Python.rust_capabilities(), None);
        assert_eq!(Selection::Rust.rust_capabilities(), Some(Capabilities::RUST));
    }
}
