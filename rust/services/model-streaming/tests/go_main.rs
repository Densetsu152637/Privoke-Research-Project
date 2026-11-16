//! Ports of `main_test.go`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{test_catalog, write_test_artifact};
use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::proto::v1::ModelParametersRequest;
use privoke_model_streaming::artifact;
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::jsonx;
use privoke_model_streaming::service::ModelService;
use tonic::Code;

fn service(catalog: Catalog) -> ModelService {
    ModelService::new(Arc::new(catalog))
}

fn request(model_id: &str) -> ModelParametersRequest {
    ModelParametersRequest { consumer_id: String::new(), model_id: model_id.to_string() }
}

// TestGetModelParametersLoadsPersistentArtifact
#[test]
fn get_model_parameters_loads_persistent_artifact() {
    let (_directory, path) = write_test_artifact();
    let server = service(test_catalog(&path));
    let response = server.get_model_parameters_core(&request("privoke-baseline")).unwrap();
    assert_eq!((response.model_id.as_str(), response.version.as_str()), ("privoke-baseline", "v1"));
    assert_eq!(response.parameters.len(), 26, "artifact tensor shape was not streamed");
}

// TestGetModelParametersResolvesLatestAlias
#[test]
fn get_model_parameters_resolves_latest_alias() {
    let (_directory, path) = write_test_artifact();
    let server = service(test_catalog(&path));
    let response = server.get_model_parameters_core(&request("latest")).unwrap();
    assert_eq!(response.model_id, "privoke-baseline");
}

// TestLoadModelCatalogDiscoversArtifacts
#[test]
fn load_model_catalog_discovers_artifacts() {
    let (directory, _path) = write_test_artifact();
    let catalog = Catalog::load(directory.path(), "privoke-baseline").unwrap();
    let loaded = catalog.load_model("latest").unwrap();
    assert_eq!(loaded.artifact.model_id, "privoke-baseline");
}

// TestGetModelParametersRejectsUnknownModel
#[test]
fn get_model_parameters_rejects_unknown_model() {
    let (_directory, path) = write_test_artifact();
    let server = service(test_catalog(&path));
    let error = server.get_model_parameters_core(&request("does-not-exist")).unwrap_err();
    assert_eq!(error.code(), Code::NotFound);
    assert_eq!(error.message(), "model \"does-not-exist\" is unavailable");
}

// TestGetModelParametersRejectsControlCharacters
#[test]
fn get_model_parameters_rejects_control_characters() {
    let (_directory, path) = write_test_artifact();
    let server = service(test_catalog(&path));
    let error = server
        .get_model_parameters_core(&ModelParametersRequest { consumer_id: "attacker\nforged-log".into(), model_id: String::new() })
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
}

// TestGetModelParametersRejectsInvalidArtifactChecksum
#[test]
fn get_model_parameters_rejects_invalid_artifact_checksum() {
    let (_directory, path) = write_test_artifact();
    let mut payload = jsonx::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    if let privoke_contracts::json::Value::Object(map) = &mut payload {
        map.insert("version".into(), common::text("tampered"));
    }
    std::fs::write(&path, canonical::to_bytes(&payload, Variant::Utf8Go).unwrap()).unwrap();
    let server = service(test_catalog(&path));
    let error = server.get_model_parameters_core(&request("")).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
}

// TestLoadRepositoryArtifact
#[test]
fn load_repository_artifact() {
    let loaded = artifact::load_model_artifact(&common::model_path("baseline"), "privoke-baseline").unwrap();
    assert!(!loaded.artifact.checksum.is_empty() && !loaded.file_checksum.is_empty());
}

// TestArtifactChecksumMatchesSharedPythonCanonicalJSON
#[test]
fn artifact_checksum_matches_shared_python_canonical_json() {
    let raw = r#"{"metadata":{"label":"café <safe>\u2028"},"checksum":"ignored"}"#;
    let checksum = artifact::calculate_artifact_checksum(&jsonx::parse(raw).unwrap()).unwrap();
    assert_eq!(checksum, "c35c226b69d388c8090e2021b143a1a693c67a9035d6e61469ce20fac540af87");
}
