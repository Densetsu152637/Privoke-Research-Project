//! Building the wire messages from a loaded artifact: sorted tensors, response metadata, and 1024-value chunks.

use std::collections::BTreeMap;

use privoke_contracts::proto::v1::{ModelParameterChunk, ModelParametersResponse, Parameter, ParameterChunk};

use crate::artifact::{LoadedArtifact, PRESENCE_ARCHITECTURE, Tensor};
use crate::jsonx;
use crate::scratch::{SCRATCH_PRESENCE_ARCHITECTURE, ScratchConfig};

/// The service name reported in `served_by` and by `Health`.
pub const SERVICE_NAME: &str = "model-streaming-service";
/// Float values per streamed chunk.
pub const PARAMETER_CHUNK_VALUES: usize = 1024;

/// `parameterMessages`: tensors in name order, and the names of the trainable ones.
pub fn parameter_messages(tensors: &BTreeMap<String, Tensor>) -> (Vec<Parameter>, Vec<String>) {
    let mut parameters = Vec::with_capacity(tensors.len());
    let mut trainable = Vec::new();
    for (name, tensor) in tensors {
        parameters.push(Parameter {
            name: name.clone(),
            values: tensor.values.iter().map(|value| *value as f32).collect(),
            shape: tensor.shape.clone(),
        });
        if tensor.trainable {
            trainable.push(name.clone());
        }
    }
    (parameters, trainable)
}

/// `responseMetadata`.
pub fn response_metadata(artifact: &LoadedArtifact, consumer_id: &str, trainable_names: &[String]) -> BTreeMap<String, String> {
    let model = &artifact.artifact;
    let mut metadata = model.metadata().clone();
    metadata.insert("served_by".into(), SERVICE_NAME.into());
    metadata.insert("consumer_id".into(), consumer_id.into());
    metadata.insert("architecture".into(), model.architecture.clone());
    metadata.insert("model_config".into(), model.config.clone());
    metadata.insert("artifact_checksum".into(), model.checksum.clone());
    metadata.insert("artifact_file_checksum".into(), artifact.file_checksum.clone());
    metadata.insert("trainable_parameters".into(), trainable_names.join(","));
    if model.architecture == PRESENCE_ARCHITECTURE {
        // The catalog validated this exact immutable configuration before serving.
        if let Ok(fields) = jsonx::object_of(&model.config) {
            let string = |key: &str| jsonx::string(fields.get(key));
            if let (Ok(task), Ok(profile), Ok(normalization)) = (string("task"), string("profile"), string("normalization")) {
                metadata.insert("task".into(), task);
                metadata.insert("profile".into(), profile);
                metadata.insert("text_normalization".into(), normalization);
                metadata.insert("arithmetic".into(), "float32_parameters_float64_features_fsum_v1".into());
            }
        }
    }
    if model.architecture == SCRATCH_PRESENCE_ARCHITECTURE
        && let Ok(config) = ScratchConfig::decode(&model.config)
    {
        if let Some(compact) = jsonx::compact(&model.config) {
            metadata.insert("model_config".into(), compact);
        }
        metadata.insert("task".into(), config.task);
        metadata.insert("profile".into(), config.profile);
        metadata.insert("training_mode".into(), config.training_mode);
        metadata.insert("text_normalization".into(), config.normalization);
        metadata.insert("tokenizer".into(), config.tokenizer);
        metadata.insert("pooling".into(), config.pooling);
        metadata.insert("arithmetic".into(), config.arithmetic);
    }
    metadata
}

/// `parameterResponse`.
pub fn parameter_response(artifact: &LoadedArtifact, consumer_id: &str) -> ModelParametersResponse {
    let (parameters, trainable) = parameter_messages(&artifact.artifact.parameters);
    ModelParametersResponse {
        model_id: artifact.artifact.model_id.clone(),
        version: artifact.artifact.version.clone(),
        generated_at_unix: artifact.artifact.generated_at_unix,
        parameters,
        metadata: response_metadata(artifact, consumer_id, &trainable),
    }
}

/// `parameterChunkCount`.
pub fn parameter_chunk_count(parameters: &[Parameter]) -> usize {
    parameters.iter().map(|parameter| parameter.values.len().div_ceil(PARAMETER_CHUNK_VALUES)).sum()
}

/// `parameterChunk`: the metadata travels on the first chunk only.
pub fn parameter_chunk(
    response: &ModelParametersResponse,
    parameter: &Parameter,
    offset: usize,
    chunk_index: usize,
    total_chunks: usize,
) -> ModelParameterChunk {
    let end = (offset + PARAMETER_CHUNK_VALUES).min(parameter.values.len());
    let metadata = if chunk_index == 0 { response.metadata.clone() } else { BTreeMap::new() };
    ModelParameterChunk {
        model_id: response.model_id.clone(),
        version: response.version.clone(),
        generated_at_unix: response.generated_at_unix,
        parameter: Some(ParameterChunk {
            name: parameter.name.clone(),
            shape: parameter.shape.clone(),
            value_offset: offset as u32,
            values: parameter.values[offset..end].to_vec(),
        }),
        metadata,
        chunk_index: chunk_index as u32,
        total_chunks: total_chunks as u32,
    }
}

/// All chunks of a response, in wire order.
pub fn parameter_chunks(response: &ModelParametersResponse) -> Vec<ModelParameterChunk> {
    let total = parameter_chunk_count(&response.parameters);
    let mut chunks = Vec::with_capacity(total);
    for parameter in &response.parameters {
        let mut offset = 0;
        while offset < parameter.values.len() {
            chunks.push(parameter_chunk(response, parameter, offset, chunks.len(), total));
            offset += PARAMETER_CHUNK_VALUES;
        }
    }
    chunks
}
