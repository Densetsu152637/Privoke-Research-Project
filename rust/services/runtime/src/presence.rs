//! Annotation presence in the worker: the sparse presence model read from the model roots, the `DetectAnnotationPresence`
//! RPC (`hosting/grpc_server.py`) and the models the semantic presence gate runs.
//!
//! The model is the stage 19 `privoke_training::presence::PresenceModel` (sparse TF-IDF, float32 parameters, float64
//! features and `fsum`), so a probability is the Python one up to libm differences in `ln`, `exp` and `sqrt`. The identity
//! the responses carry (version, artifact checksum, parameter fingerprint) is the provider snapshot's. The scratch
//! presence models are served by no W1 worker; asking for one is the same error the Python worker gives.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::proto::v1::DetectAnnotationPresenceRequest;
use privoke_training::presence::PresenceModel;

use crate::gate::is_scratch_presence_model;
use crate::request::py_strip;
use crate::store::{Artifact, ArtifactStore, LoadError, PRESENCE_ARCHITECTURE};
use crate::wire;

const PRESENCE_MODEL_ID_PREFIX: &str = "privoke-presence-";
const SEMANTIC_LAYER: i32 = 4;
const ABSENT: i32 = 1;
const PRESENT: i32 = 2;

/// A presence model with the identity its responses carry.
#[derive(Debug)]
pub struct LoadedPresence {
    /// The model.
    pub model: PresenceModel,
    /// `snapshot.model_id`.
    pub model_id: String,
    /// `snapshot.version`.
    pub version: String,
    /// `snapshot.metadata["artifact_checksum"]`.
    pub artifact_checksum: String,
    /// `snapshot.fingerprint`.
    pub parameter_fingerprint: String,
    /// The model's decision threshold.
    pub threshold: f64,
}

/// The `StreamedPresenceModel` checks, and the identity.
pub fn build_presence(artifact: &Artifact) -> Result<LoadedPresence, String> {
    if artifact.architecture != PRESENCE_ARCHITECTURE {
        return Err("Streamed model is not an annotation-presence artifact.".to_string());
    }
    let model = PresenceModel::from_artifact(&artifact.value).map_err(|error| error.to_string())?;
    let task = artifact.metadata.get("task").map(String::as_str);
    if task != Some("annotation_presence") {
        return Err("Streamed artifact is not the annotation-presence task.".to_string());
    }
    if artifact.model_id != format!("{PRESENCE_MODEL_ID_PREFIX}{}", model.profile) {
        return Err("Presence model ID does not match its profile.".to_string());
    }
    let checksum = &artifact.checksum;
    if checksum.len() != 64 || !checksum.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
        return Err("Presence stream is missing a valid artifact checksum.".to_string());
    }
    let declared: BTreeSet<&str> = artifact
        .metadata
        .get("trainable_parameters")
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .collect();
    let expected: BTreeSet<&str> =
        artifact.parameters.keys().filter(|name| name.starts_with("head.presence.")).map(String::as_str).collect();
    if declared != expected {
        return Err("Presence snapshot trainable manifest does not match its tensors.".to_string());
    }
    let fingerprint = parameter_fingerprint(&artifact.parameters, Some(&artifact.shapes)).map_err(|error| error.to_string())?;
    let threshold = model.threshold();
    Ok(LoadedPresence {
        model,
        model_id: artifact.model_id.clone(),
        version: artifact.version.clone(),
        artifact_checksum: artifact.checksum.clone(),
        parameter_fingerprint: fingerprint,
        threshold,
    })
}

/// The presence models of the worker's roots, rebuilt only when their bytes change.
#[derive(Debug)]
pub struct PresenceModels {
    store: Arc<ArtifactStore>,
    cache: Mutex<HashMap<String, (String, Arc<LoadedPresence>)>>,
}

impl PresenceModels {
    /// Presence models over a store.
    pub fn new(store: Arc<ArtifactStore>) -> Self {
        Self { store, cache: Mutex::new(HashMap::new()) }
    }

    /// The model for an id, or the text the Python worker reports.
    pub fn fetch(&self, requested: &str) -> Result<Arc<LoadedPresence>, String> {
        let (model_id, bytes) = self.store.read_bytes(requested).map_err(declined_as_message)?;
        let key = sha256_hex(&bytes);
        if let Some((cached_key, loaded)) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&model_id)
            && *cached_key == key
        {
            return Ok(Arc::clone(loaded));
        }
        let artifact = Artifact::parse(&model_id, &bytes).map_err(declined_as_message)?;
        let loaded = Arc::new(build_presence(&artifact)?);
        self.cache.lock().unwrap_or_else(PoisonError::into_inner).insert(model_id, (key, Arc::clone(&loaded)));
        Ok(loaded)
    }
}

/// A presence read that the Rust worker declines is, to the Python worker, a model that is not a presence artifact.
fn declined_as_message(error: LoadError) -> String {
    match error {
        LoadError::Message(text) => text,
        LoadError::Declined(_) => "Streamed model is not an annotation-presence artifact.".to_string(),
    }
}

/// `_validate_presence_model_id`.
pub fn validate_presence_model_id(model_id: &str) -> Result<(), String> {
    if !model_id.starts_with(PRESENCE_MODEL_ID_PREFIX)
        || model_id != py_strip(model_id)
        || model_id.chars().count() > 128
        || model_id.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
    {
        return Err("model_id must explicitly name a privoke-presence model.".to_string());
    }
    Ok(())
}

fn error_response(request_id: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::string(&mut out, 1, request_id);
    wire::string(&mut out, 10, text);
    out
}

/// `PrivokeRuntimeService.DetectAnnotationPresence`: the serialised `DetectAnnotationPresenceResponse`. Every failure is
/// the response's `error`. `clear_elapsed` leaves `elapsed_ms` out (the conformance comparison's normal form).
pub fn detect(models: &PresenceModels, message: &DetectAnnotationPresenceRequest, max_text_chars: usize, clear_elapsed: bool) -> Vec<u8> {
    let started = Instant::now();
    let fail = |text: &str| error_response(&message.request_id, text);
    if message.layers.as_slice() != [SEMANTIC_LAYER] {
        return fail("Presence inference requires explicit semantic-only layers.");
    }
    if !is_scratch_presence_model(&message.model_id)
        && let Err(text) = validate_presence_model_id(&message.model_id)
    {
        return fail(&text);
    }
    if py_strip(&message.request_id).is_empty() {
        return fail("request_id is required.");
    }
    if py_strip(&message.text).is_empty() {
        return fail("text is required.");
    }
    if message.text.chars().count() > max_text_chars {
        return fail(&format!("text may contain at most {max_text_chars} characters."));
    }
    let model = match models.fetch(&message.model_id) {
        Ok(model) => model,
        Err(text) => return fail(&text),
    };
    let probability = model.model.predict_probability(&message.text);
    let label = if probability >= model.threshold { PRESENT } else { ABSENT };
    let mut out = Vec::new();
    wire::string(&mut out, 1, &message.request_id);
    wire::string(&mut out, 2, &model.model_id);
    wire::string(&mut out, 3, &model.version);
    wire::double(&mut out, 4, probability);
    wire::double(&mut out, 5, model.threshold);
    wire::enumeration(&mut out, 6, label);
    wire::string(&mut out, 7, &model.artifact_checksum);
    wire::string(&mut out, 8, &model.parameter_fingerprint);
    if !clear_elapsed {
        wire::double(&mut out, 9, started.elapsed().as_secs_f64() * 1000.0);
    }
    let mut execution = Vec::new();
    wire::enumeration(&mut execution, 1, SEMANTIC_LAYER);
    wire::string(&mut execution, 2, "ok");
    wire::message(&mut out, 11, &execution);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_model_ids_follow_the_python_rule() {
        assert!(validate_presence_model_id("privoke-presence-efficient").is_ok());
        for bad in ["privoke-balanced", "privoke-presence-x ", " privoke-presence-x", "privoke-presence-a\u{7}b"] {
            assert!(validate_presence_model_id(bad).is_err(), "{bad:?}");
        }
        assert!(validate_presence_model_id(&format!("privoke-presence-{}", "x".repeat(120))).is_err());
    }

    #[test]
    fn a_failure_is_an_error_response_under_the_request_id() {
        let models = PresenceModels::new(Arc::new(ArtifactStore::new(Vec::new(), None)));
        let request = DetectAnnotationPresenceRequest {
            request_id: "r".into(),
            text: "x".into(),
            model_id: "privoke-presence-efficient".into(),
            layers: vec![4],
        };
        let bytes = detect(&models, &request, 10, true);
        assert_eq!(&bytes[..3], &[0x0a, 1, b'r']);
        assert!(String::from_utf8_lossy(&bytes).contains("is not available in the worker model roots."));
        let wrong = DetectAnnotationPresenceRequest { layers: vec![2], ..request };
        assert!(String::from_utf8_lossy(&detect(&models, &wrong, 10, true)).contains("explicit semantic-only layers"));
    }
}
