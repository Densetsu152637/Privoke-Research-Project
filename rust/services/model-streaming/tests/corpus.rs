//! Stage 0 conformance corpus replay (`tests/conformance/model_streaming.json`, goal G5).
//!
//! The corpus was captured from the Go service. Every legacy catalog model, every negative request and (when the
//! prepared release store is present) every V3 manifest and asset must reproduce byte for byte: message digests, chunk
//! sequences and status details are all compared with no normalisation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use common::repo_root;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::{self, Value};
use privoke_contracts::proto::v1::{ModelAssetRequest, ModelParametersRequest};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::releases::{STANDARD_IDS, StandardReleases};
use privoke_model_streaming::response::parameter_chunks;
use privoke_model_streaming::service::ModelService;
use prost::Message;
use tonic::Code;

const PIN_REQUIRED: &str = "explicit standard model and manifest pin required";
const LEGACY_MODELS: [&str; 4] = ["privoke-balanced", "privoke-baseline", "privoke-efficient", "privoke-quality"];

fn corpus() -> Value {
    let text = std::fs::read_to_string(repo_root().join("tests/conformance/model_streaming.json")).unwrap();
    json::parse(&text).unwrap()
}

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    match value {
        Value::Object(map) => map.get(key).unwrap_or_else(|| panic!("missing key {key}")),
        other => panic!("not an object looking for {key}: {other:?}"),
    }
}

fn text(value: &Value) -> &str {
    match value {
        Value::String(text) => text,
        other => panic!("not a string: {other:?}"),
    }
}

fn unsigned(value: &Value) -> u64 {
    match value {
        Value::Int(digits) => digits.parse().unwrap(),
        other => panic!("not an integer: {other:?}"),
    }
}

fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

fn string_map(value: &Value) -> BTreeMap<String, String> {
    match value {
        Value::Object(map) => map.iter().map(|(key, item)| (key.clone(), text(item).to_string())).collect(),
        other => panic!("not an object: {other:?}"),
    }
}

fn shape(value: &Value) -> Vec<u32> {
    array(value).iter().map(|item| unsigned(item) as u32).collect()
}

fn f32_digest(values: &[f32]) -> String {
    let bytes: Vec<u8> = values.iter().flat_map(|value| value.to_le_bytes()).collect();
    sha256_hex(&bytes)
}

fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

struct Harness {
    service: ModelService,
    _models: tempfile::TempDir,
    with_releases: bool,
}

fn harness() -> Harness {
    let models = tempfile::tempdir().unwrap();
    for model in LEGACY_MODELS {
        // The corpus was recorded from a Windows checkout whose `models/*.json` carry CRLF, and the recorded
        // `artifact_file_checksum` and `model_config` embed those bytes. Git checks the same files out with LF on
        // Linux, so the replay always serves the CRLF form the corpus was captured from.
        let bytes = std::fs::read(common::model_path(&model["privoke-".len()..])).unwrap();
        std::fs::write(models.path().join(format!("{model}.json")), crlf(&bytes)).unwrap();
    }
    let mut catalog = Catalog::load(models.path(), "privoke-v3-balanced").unwrap();
    let mut with_releases = false;
    if let Some(directory) = common::release_dir_for_tests() {
        catalog.releases = Some(StandardReleases::open(&directory).unwrap());
        with_releases = true;
    }
    Harness { service: ModelService::new(Arc::new(catalog)), _models: models, with_releases }
}

/// The bytes with every line ending as CRLF, whichever form they arrive in.
fn crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 32);
    let mut previous = 0u8;
    for &byte in bytes {
        if byte == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(byte);
        previous = byte;
    }
    out
}

fn legacy_request(model: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: "conformance-consumer".into(), model_id: model.into() }
}

#[test]
fn health_matches_the_corpus() {
    let corpus = corpus();
    let harness = harness();
    let health = harness.service.health_core();
    assert_eq!(health.service, text(get(get(&corpus, "health"), "service")));
    if harness.with_releases {
        assert_eq!(health.status, text(get(get(&corpus, "health"), "status")));
    }
}

#[test]
fn legacy_catalog_models_stream_the_recorded_bytes() {
    let corpus = corpus();
    let harness = harness();
    let legacy = get(&corpus, "legacy");
    assert_eq!(array_len_of_object(legacy), LEGACY_MODELS.len());
    for model in LEGACY_MODELS {
        let record = get(legacy, model);
        let response = harness.service.get_model_parameters_core(&legacy_request(model)).unwrap();
        let unary = get(record, "get_model_parameters");
        assert_eq!(response.model_id, text(get(unary, "model_id")));
        assert_eq!(response.version, text(get(unary, "version")));
        assert_eq!(response.generated_at_unix as u64, unsigned(get(unary, "generated_at_unix")));
        assert_eq!(response.metadata, string_map(get(unary, "metadata")), "{model}: metadata");
        assert_eq!(sha256_hex(&response.encode_to_vec()), text(get(unary, "message_sha256")), "{model}: unary message bytes");
        let recorded = array(get(unary, "parameters"));
        assert_eq!(response.parameters.len(), recorded.len(), "{model}: tensor count");
        for (parameter, expected) in response.parameters.iter().zip(recorded) {
            assert_eq!(parameter.name, text(get(expected, "name")));
            assert_eq!(parameter.shape, shape(get(expected, "shape")));
            assert_eq!(parameter.values.len() as u64, unsigned(get(expected, "values")));
            assert_eq!(
                f32_digest(&parameter.values),
                text(get(expected, "values_sha256_f32le")),
                "{model}/{}: float32 bytes",
                parameter.name
            );
        }

        let stream = get(record, "stream");
        let chunks = parameter_chunks(&response);
        let rows = array(get(stream, "chunks"));
        assert_eq!(chunks.len() as u64, unsigned(get(stream, "chunk_count")), "{model}: chunk count");
        assert_eq!(chunks.len(), rows.len());
        let mut total_values = 0u64;
        let mut digests = String::new();
        for (chunk, row) in chunks.iter().zip(rows) {
            let parameter = chunk.parameter.as_ref().unwrap();
            assert_eq!(u64::from(chunk.chunk_index), unsigned(get(row, "chunk_index")));
            assert_eq!(u64::from(chunk.total_chunks), unsigned(get(row, "total_chunks")));
            assert_eq!(parameter.name, text(get(row, "name")));
            assert_eq!(parameter.shape, shape(get(row, "shape")));
            assert_eq!(u64::from(parameter.value_offset), unsigned(get(row, "value_offset")));
            assert_eq!(parameter.values.len() as u64, unsigned(get(row, "value_count")));
            assert_eq!(f32_digest(&parameter.values), text(get(row, "values_sha256_f32le")));
            assert_eq!(chunk.metadata, string_map(get(row, "metadata")), "{model}: chunk {} metadata", chunk.chunk_index);
            let digest = sha256_hex(&chunk.encode_to_vec());
            assert_eq!(digest, text(get(row, "message_sha256")), "{model}: chunk {} message bytes", chunk.chunk_index);
            digests.push_str(&digest);
            total_values += parameter.values.len() as u64;
        }
        assert_eq!(total_values, unsigned(get(stream, "total_values")), "{model}: total values");
        assert_eq!(sha256_hex(digests.as_bytes()), text(get(stream, "stream_sha256")), "{model}: stream digest");
        eprintln!("corpus legacy {model}: {} chunks, {total_values} values, stream digest matches", chunks.len());
    }
}

fn array_len_of_object(value: &Value) -> usize {
    match value {
        Value::Object(map) => map.len(),
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn recorded_requests_answer_with_the_recorded_status_and_details() {
    let corpus = corpus();
    let harness = harness();
    let mut replayed = 0;
    let mut skipped = Vec::new();
    for row in array(get(&corpus, "requests")) {
        let label = text(get(row, "label"));
        let rpc = text(get(row, "rpc"));
        let raw = base64::engine::general_purpose::STANDARD.decode(text(get(row, "request_b64"))).unwrap();
        let expected_status = text(get(row, "status"));
        let outcome: Result<Option<privoke_contracts::proto::v1::ModelPackageResponse>, tonic::Status> = match rpc {
            "GetModelParameters" | "StreamModelParameters" => {
                let request = ModelParametersRequest::decode(raw.as_slice()).unwrap();
                harness.service.get_model_parameters_core(&request).map(|_| None)
            }
            "GetModelPackage" => {
                if !harness.with_releases && label.contains("latest") || !harness.with_releases && label.contains("empty") {
                    skipped.push(label.to_string());
                    continue;
                }
                let request = ModelParametersRequest::decode(raw.as_slice()).unwrap();
                harness.service.get_model_package_core(&request).map(Some)
            }
            "StreamModelAsset" => {
                // Without the release store every asset request is refused at the pin check, so the rows the Go
                // service answered past the pin check (an allowlist verdict) need the store to reproduce.
                if !harness.with_releases && text(get(row, "details")) != PIN_REQUIRED {
                    skipped.push(label.to_string());
                    continue;
                }
                let request = ModelAssetRequest::decode(raw.as_slice()).unwrap();
                harness.service.check_asset_request(&request).map(|()| None)
            }
            other => panic!("unexpected rpc {other}"),
        };
        match outcome {
            Ok(package) => {
                assert_eq!(expected_status, "OK", "{label}: succeeded but the corpus recorded {expected_status}");
                if let Some(package) = package {
                    let summary = get(row, "response");
                    assert_eq!(package.model_id, text(get(summary, "model_id")), "{label}");
                    assert_eq!(package.architecture, text(get(summary, "architecture")), "{label}");
                    assert_eq!(package.manifest_sha256, text(get(summary, "manifest_sha256")), "{label}");
                    assert_eq!(package.assets.len() as u64, unsigned(get(summary, "assets")), "{label}");
                    assert_eq!(
                        sha256_hex(&package.encode_to_vec()),
                        text(get(row, "response_message_sha256")),
                        "{label}: package message bytes"
                    );
                }
            }
            Err(status) => {
                assert_eq!(code_name(status.code()), expected_status, "{label}: status");
                assert_eq!(status.message(), text(get(row, "details")), "{label}: details");
            }
        }
        replayed += 1;
    }
    let total = array(get(&corpus, "requests")).len();
    assert_eq!(replayed + skipped.len(), total, "every recorded request is replayed or skipped with a reason");
    assert!(replayed >= if harness.with_releases { 18 } else { 17 }, "only {replayed} recorded requests were replayed");
    if !skipped.is_empty() {
        eprintln!("corpus requests skipped (the prepared standard releases are not available): {}", skipped.join(", "));
    }
    eprintln!(
        "corpus requests: {replayed} of {} recorded requests replayed with identical status and details",
        array(get(&corpus, "requests")).len()
    );
}

#[test]
fn v3_packages_and_assets_stream_the_recorded_bytes() {
    let corpus = corpus();
    let harness = harness();
    if !harness.with_releases {
        eprintln!("the prepared standard releases are not available (set V3_TEST_RELEASE_DIR); the V3 byte replay is skipped");
        return;
    }
    let v3 = get(&corpus, "v3");
    let releases = harness.service.catalog().releases.as_ref().unwrap();
    let mut assets_replayed = 0;
    let mut chunks_replayed = 0u64;
    for model in STANDARD_IDS {
        let record = get(v3, model);
        let package = harness
            .service
            .get_model_package_core(&ModelParametersRequest { consumer_id: "conformance-consumer".into(), model_id: model.into() })
            .unwrap();
        let summary = get(record, "get_model_package");
        assert_eq!(package.model_id, text(get(summary, "model_id")));
        assert_eq!(package.architecture, text(get(summary, "architecture")));
        assert_eq!(package.manifest_sha256, text(get(summary, "manifest_sha256")));
        assert_eq!(package.manifest_sha256, text(get(record, "manifest_file_sha256")));
        assert_eq!(package.manifest_json, text(get(record, "manifest_json")).as_bytes(), "{model}: manifest bytes");
        assert_eq!(sha256_hex(&package.encode_to_vec()), text(get(summary, "message_sha256")), "{model}: package message bytes");
        let recorded_assets = array(get(summary, "assets"));
        assert_eq!(package.assets.len(), recorded_assets.len());
        for (asset, recorded) in package.assets.iter().zip(recorded_assets) {
            assert_eq!(asset.name, text(get(recorded, "name")));
            assert_eq!(asset.sha256, text(get(recorded, "sha256")));
            assert_eq!(asset.size_bytes, unsigned(get(recorded, "size_bytes")));
        }
        for asset in &package.assets {
            let expected = get(get(record, "stream_asset"), &asset.name);
            let mut rows = array(get(expected, "chunks")).iter();
            let mut digests = String::new();
            let mut total = 0u64;
            let mut whole = Vec::new();
            let mut count = 0u64;
            releases
                .stream_asset(model, &package.manifest_sha256, &asset.name, |chunk| {
                    let row = rows.next().expect("more chunks than recorded");
                    assert_eq!(chunk.offset, unsigned(get(row, "offset")));
                    assert_eq!(chunk.data.len() as u64, unsigned(get(row, "length")));
                    assert_eq!(sha256_hex(&chunk.data), text(get(row, "data_sha256")));
                    assert_eq!(chunk.total_bytes, unsigned(get(row, "total_bytes")));
                    assert_eq!(chunk.sha256, text(get(row, "sha256")));
                    assert_eq!(chunk.model_id, text(get(row, "model_id")));
                    assert_eq!(chunk.manifest_sha256, text(get(row, "manifest_sha256")));
                    assert_eq!(chunk.asset_name, text(get(row, "asset_name")));
                    let digest = sha256_hex(&chunk.encode_to_vec());
                    assert_eq!(digest, text(get(row, "message_sha256")), "{model}/{}: chunk at {}", asset.name, chunk.offset);
                    digests.push_str(&digest);
                    total += chunk.data.len() as u64;
                    whole.extend_from_slice(&chunk.data);
                    count += 1;
                    true
                })
                .unwrap();
            assert!(rows.next().is_none(), "{model}/{}: fewer chunks than recorded", asset.name);
            assert_eq!(count, unsigned(get(expected, "chunk_count")));
            chunks_replayed += count;
            assert_eq!(total, unsigned(get(expected, "bytes")));
            assert_eq!(sha256_hex(&whole), text(get(expected, "sha256")));
            assert_eq!(sha256_hex(digests.as_bytes()), text(get(expected, "stream_sha256")), "{model}/{}: stream digest", asset.name);
            assets_replayed += 1;
        }
    }
    assert_eq!(assets_replayed, 12);
    eprintln!("corpus v3: {assets_replayed} assets over {} models, {chunks_replayed} chunks, byte equal", STANDARD_IDS.len());
}
