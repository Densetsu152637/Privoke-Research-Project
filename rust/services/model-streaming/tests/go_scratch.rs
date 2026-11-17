//! Ports of `scratch_presence_test.go`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{fixture_path, fixture_text, scratch_fixture, tensor};
use privoke_contracts::proto::v1::ModelParametersRequest;
use privoke_model_streaming::artifact::{self, LoadedArtifact, ModelArtifact, validate_model_artifact};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::response::{parameter_chunk, parameter_response};
use privoke_model_streaming::scratch::{MAX_SCRATCH_CONFIG_BYTES, PROFILES, ScratchConfig, profile_dimensions, scratch_shapes};
use privoke_model_streaming::service::ModelService;
use tonic::Code;

// TestScratchSharedFixtureChecksumAndFirstChunkMetadata
#[test]
fn scratch_shared_fixture_checksum_and_first_chunk_metadata() {
    let mut artifact = scratch_fixture();
    let response = parameter_response(&artifact, "synthetic-test");
    let metadata = &response.metadata;
    assert!(
        metadata["task"] == "annotation_presence"
            && metadata["profile"] == "efficient"
            && metadata["training_mode"] == "head_only"
            && metadata["text_normalization"] == "detector_normalize_text_v1"
            && metadata["tokenizer"] == "legacy_sha256_bucket_tokens_v1"
            && metadata["pooling"] == "half_first_half_real_mean_v1"
            && metadata["arithmetic"] == "float32_numpy_encoder_clipped_sigmoid_v1",
        "scratch derived contract missing"
    );
    // Raw artifact whitespace must not inflate the bounded first-chunk config.
    let padded = format!("{{ {}{}", " ".repeat(MAX_SCRATCH_CONFIG_BYTES), &artifact.artifact.config[1..]);
    artifact.artifact.config = padded;
    let compact = parameter_response(&artifact, "synthetic-test").metadata;
    assert!(compact["model_config"].len() <= MAX_SCRATCH_CONFIG_BYTES, "scratch stream config not compact/bounded");
    assert_eq!(metadata["trainable_parameters"], "head.presence.bias,head.presence.weight", "scratch trainability not sorted/exact");
    assert!(
        !parameter_chunk(&response, &response.parameters[0], 0, 0, 2).metadata.is_empty()
            && parameter_chunk(&response, &response.parameters[0], 0, 1, 2).metadata.is_empty(),
        "metadata is not first-chunk-only"
    );
    let weights = &artifact.artifact.parameters["head.presence.weight"].values;
    assert!(weights[0].is_sign_negative() && weights[1] == f64::from(0.1f32), "float32 lexical fixture identity lost");
    for parameter in &response.parameters {
        if parameter.name == "head.presence.weight" {
            assert!(
                parameter.values[0].is_sign_negative() && parameter.values[1] == 0.1f32 && parameter.values[2] != 0.0,
                "protobuf float32 transport vector changed"
            );
        }
    }
}

// TestScratchRejectsWrongShapesModesAndProvenance
#[test]
fn scratch_rejects_wrong_shapes_modes_and_provenance() {
    type Mutation = Box<dyn Fn(&mut ModelArtifact)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("mode ID", Box::new(|a| a.model_id = "privoke-scratch-presence-efficient-full-encoder".into())),
        ("wrong architecture", Box::new(|a| a.architecture = artifact::EXPECTED_ARCHITECTURE.into())),
        ("legacy ID", Box::new(|a| a.model_id = "privoke-balanced".into())),
        ("epoch", Box::new(|a| drop(a.metadata_mut().insert("checkpoint_epoch".into(), "2".into())))),
        ("Unicode", Box::new(|a| drop(a.metadata_mut().insert("source_revision".into(), "\u{c3}\u{a9}".repeat(40))))),
        ("unknown metadata", Box::new(|a| drop(a.metadata_mut().insert("extra".into(), "x".into())))),
        ("noncanonical steps", Box::new(|a| drop(a.metadata_mut().insert("training_steps".into(), "0490".into())))),
        ("overflow", Box::new(|a| a.parameters.get_mut("head.presence.bias").unwrap().values[0] = 1e100)),
        ("not exact f32", Box::new(|a| a.parameters.get_mut("head.presence.bias").unwrap().values[0] = 0.1)),
        ("frozen flag", Box::new(|a| a.parameters.get_mut("token_embedding").unwrap().trainable = true)),
        ("shape", Box::new(|a| a.parameters.get_mut("head.presence.weight").unwrap().shape = vec![24])),
    ];
    for (name, mutate) in cases {
        let mut loaded = scratch_fixture();
        mutate(&mut loaded.artifact);
        assert!(validate_model_artifact(&loaded.artifact, "").is_err(), "invalid scratch object accepted: {name}");
    }
}

// TestScratchRawGuardsRunBeforeTypedDecode
#[test]
fn scratch_raw_guards_run_before_typed_decode() {
    let text = fixture_text("scratch-presence-efficient.json");
    let replace = |from: &str, to: &str| {
        assert!(text.contains(from), "fixture no longer contains {from}");
        text.replacen(from, to, 1)
    };
    let mut cases: BTreeMap<&str, String> = BTreeMap::new();
    cases.insert("duplicate root", replace(r#""schema_version":1"#, r#""schema_version":1,"schema_version":1"#));
    cases.insert(
        "duplicate architecture hiding scratch",
        replace(
            r#""architecture":"privoke_scratch_presence_transformer_v1""#,
            r#""architecture":"privoke_scratch_presence_transformer_v1","architecture":"privoke_tiny_transformer_v1""#,
        ),
    );
    cases.insert("missing flag", replace(r#","trainable":true"#, ""));
    cases.insert("null flag", replace(r#""trainable":true"#, r#""trainable":null"#));
    cases.insert("surrogate", replace(r#""source_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#, r#""source_revision":"\ud800""#));
    cases.insert("raw byte limit", format!("{}{text}", " ".repeat(artifact::MAX_ARTIFACT_BYTES)));
    cases.insert("unknown root", format!("{},\"extra\":1}}", text.trim().strip_suffix('}').unwrap()));
    for (name, content) in cases {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scratch.json");
        std::fs::write(&path, content).unwrap();
        assert!(artifact::load_model_artifact(&path, "").is_err(), "invalid raw scratch artifact accepted: {name}");
    }
}

// TestScratchAllProfilesAndOfflineModes
#[test]
fn scratch_all_profiles_and_offline_modes() {
    for profile in PROFILES {
        let dims = profile_dimensions(profile).unwrap();
        for mode in ["head_only", "end_to_end"] {
            let mut base = scratch_fixture().artifact;
            let config = ScratchConfig {
                task: "annotation_presence".into(),
                profile: profile.into(),
                training_mode: mode.into(),
                vocab_size: dims[0],
                hidden_size: dims[1],
                intermediate_size: dims[2],
                max_tokens: dims[3],
                num_layers: dims[4],
                num_attention_heads: dims[5],
                normalization: "detector_normalize_text_v1".into(),
                tokenizer: "legacy_sha256_bucket_tokens_v1".into(),
                pooling: "half_first_half_real_mean_v1".into(),
                arithmetic: "float32_numpy_encoder_clipped_sigmoid_v1".into(),
                threshold: 0.5,
            };
            base.config = config.to_json();
            let suffix = if mode == "end_to_end" { "full-encoder" } else { "head-only" };
            base.model_id = format!("privoke-scratch-presence-{profile}-{suffix}");
            base.parameters = BTreeMap::new();
            for (name, shape) in scratch_shapes(&config) {
                let size: usize = shape.iter().map(|d| *d as usize).product();
                let trainable = mode == "end_to_end" || name.starts_with("head.presence.");
                base.parameters.insert(name, tensor(&shape, vec![0.0; size], trainable));
            }
            validate_model_artifact(&base, &base.model_id).unwrap_or_else(|error| panic!("{profile}/{mode}: {error}"));
        }
    }
}

// TestScratchCatalogCannotBecomeLatestOnConstructionOrReload
#[test]
fn scratch_catalog_cannot_become_latest_on_construction_or_reload() {
    let loaded = scratch_fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("scratch.json");
    std::fs::copy(fixture_path("scratch-presence-efficient.json"), &path).unwrap();
    assert!(Catalog::load(directory.path(), &loaded.artifact.model_id).is_err(), "scratch selected latest");
    let id = loaded.artifact.model_id.clone();
    let mut catalog = Catalog::from_paths(&id, BTreeMap::from([(id.clone(), path)]));
    for requested in ["latest", "", id.as_str()] {
        assert!(catalog.load_model(requested).is_err(), "reload allowed scratch latest");
    }
    assert!(catalog.validate().is_err(), "validation allowed scratch latest");
    catalog.set_latest_model_id("privoke-balanced");
    catalog.load_model(&id).expect("explicit offline scratch inference rejected");
}

// TestScratchRequestConsumerContract
#[test]
fn scratch_request_consumer_contract() {
    // A catalog with nothing in it proves rejection precedes catalog access.
    let server = ModelService::new(Arc::new(Catalog::from_paths("privoke-balanced", BTreeMap::new())));
    let cases: [(&str, String, bool); 6] = [
        ("empty", String::new(), false),
        ("unicode", "consumer-\u{e9}".into(), false),
        ("control", "consumer\n".into(), false),
        ("delete", "consumer\u{7f}".into(), false),
        ("ASCII128", "a".repeat(128), true),
        ("ASCII129", "a".repeat(129), false),
    ];
    for profile in PROFILES {
        for suffix in ["head-only", "full-encoder"] {
            let model_id = format!("privoke-scratch-presence-{profile}-{suffix}");
            for (name, consumer, valid) in &cases {
                let request = ModelParametersRequest { model_id: model_id.clone(), consumer_id: consumer.clone() };
                let outcome = server.validate_request(&request);
                if *valid {
                    outcome.unwrap_or_else(|error| panic!("{model_id}/{name}: valid scratch consumer rejected: {error}"));
                    continue;
                }
                assert_eq!(outcome.unwrap_err().code(), Code::InvalidArgument, "{model_id}/{name}");
                assert_eq!(
                    server.get_model_parameters_core(&request).unwrap_err().code(),
                    Code::InvalidArgument,
                    "{model_id}/{name}: unary request did not reject before catalog access"
                );
            }
        }
    }
    for consumer in ["".to_string(), "consumer-\u{e9}".to_string(), "a".repeat(129)] {
        server
            .validate_request(&ModelParametersRequest { model_id: "privoke-balanced".into(), consumer_id: consumer })
            .expect("legacy consumer contract changed");
    }
    let _ = LoadedArtifact { artifact: ModelArtifact::default(), file_checksum: String::new() };
}
