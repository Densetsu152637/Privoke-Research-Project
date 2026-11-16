//! Ports of `scratch_catalog_live_test.go`: scratch models installed, replaced and removed while the service runs,
//! and the filesystem-boundary races around them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{fixture_bytes, tensor, write_test_artifact};
use privoke_contracts::proto::v1::{ModelParametersRequest, ModelParametersResponse};
use privoke_model_streaming::artifact::{self, decode_artifact_bytes};
use privoke_model_streaming::catalog::{Catalog, OpenHook};
use privoke_model_streaming::scratch::{PROFILES, ScratchConfig, profile_dimensions, scratch_shapes};
use privoke_model_streaming::service::ModelService;
use tonic::Code;

const LIVE_SCRATCH_ID: &str = "privoke-scratch-presence-efficient-head-only";

struct Live {
    server: ModelService,
    directory: tempfile::TempDir,
}

fn new_live_scratch_server() -> Live {
    let directory = tempfile::tempdir().unwrap();
    let (_baseline_dir, baseline_path) = write_test_artifact();
    std::fs::write(directory.path().join("privoke-baseline.json"), std::fs::read(baseline_path).unwrap()).unwrap();
    let catalog = Catalog::load(directory.path(), "privoke-baseline").expect("construct baseline catalog");
    Live { server: ModelService::new(Arc::new(catalog)), directory }
}

impl Live {
    fn path(&self) -> PathBuf {
        live_scratch_path(self.directory.path())
    }

    fn dir(&self) -> &Path {
        self.directory.path()
    }
}

fn scratch_live_artifact_bytes(epoch: u32) -> Vec<u8> {
    let dims = profile_dimensions("efficient").unwrap();
    scratch_live_artifact_for(LIVE_SCRATCH_ID, &config_for("efficient", "head_only", dims), epoch)
}

fn config_for(profile: &str, mode: &str, dims: [i64; 6]) -> ScratchConfig {
    ScratchConfig {
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
    }
}

fn scratch_live_artifact_for(model_id: &str, config: &ScratchConfig, epoch: u32) -> Vec<u8> {
    let mut model = decode_artifact_bytes(&fixture_bytes("scratch-presence-efficient.json")).unwrap();
    model.model_id = model_id.into();
    model.version = format!("v1.0.0+epoch.{epoch}");
    model.metadata_mut().insert("checkpoint_epoch".into(), epoch.to_string());
    model.config = config.to_json();
    model.parameters = BTreeMap::new();
    for (name, shape) in scratch_shapes(config) {
        let count: usize = shape.iter().map(|d| *d as usize).product();
        let trainable = config.training_mode == "end_to_end" || name == "head.presence.weight" || name == "head.presence.bias";
        model.parameters.insert(name, tensor(&shape, vec![0.0; count], trainable));
    }
    artifact::to_checked_bytes(&model).unwrap()
}

fn install_live_scratch(directory: &Path, raw: &[u8]) {
    std::fs::write(live_scratch_path(directory), raw).unwrap();
}

fn atomic_install_live_scratch(directory: &Path, raw: &[u8]) {
    let temporary = directory.join("scratch-install.tmp");
    std::fs::write(&temporary, raw).unwrap();
    std::fs::rename(&temporary, live_scratch_path(directory)).unwrap();
}

fn live_scratch_path(directory: &Path) -> PathBuf {
    directory.join(format!("{LIVE_SCRATCH_ID}.json"))
}

fn live_scratch_request() -> ModelParametersRequest {
    ModelParametersRequest { model_id: LIVE_SCRATCH_ID.into(), consumer_id: "catalog-live-test".into() }
}

fn get_live_scratch(server: &ModelService) -> ModelParametersResponse {
    server.get_model_parameters_core(&live_scratch_request()).unwrap_or_else(|error| panic!("scratch request failed: {error}"))
}

fn get_live_latest(server: &ModelService) -> String {
    server
        .get_model_parameters_core(&ModelParametersRequest { model_id: "latest".into(), consumer_id: String::new() })
        .unwrap_or_else(|error| panic!("latest request failed: {error}"))
        .model_id
}

fn assert_live_scratch_health(server: &ModelService, expected: &str) {
    assert_eq!(server.health_core().status, expected);
}

fn code_of(server: &ModelService, request: &ModelParametersRequest) -> Code {
    server.get_model_parameters_core(request).unwrap_err().code()
}

// TestScratchCatalogServesFileInstalledAfterConstruction
#[test]
fn scratch_catalog_serves_file_installed_after_construction() {
    let live = new_live_scratch_server();
    assert!(!live.server.catalog().contains(LIVE_SCRATCH_ID), "scratch ID was present before its file was installed");
    assert_eq!(live.server.catalog().model_ids(), vec!["privoke-baseline".to_string()], "unexpected initial catalog IDs");

    let raw = scratch_live_artifact_bytes(1);
    install_live_scratch(live.dir(), &raw);
    let response = get_live_scratch(&live.server);
    assert_eq!((response.model_id.as_str(), response.version.as_str()), (LIVE_SCRATCH_ID, "v1.0.0+epoch.1"));
    assert_eq!(
        response.metadata["artifact_file_checksum"],
        privoke_contracts::digest::sha256_hex(&raw),
        "served file checksum does not bind installed bytes"
    );
    assert!(live.server.catalog().contains(LIVE_SCRATCH_ID), "installed scratch ID is absent from catalog lookup");
    assert_eq!(get_live_latest(&live.server), "privoke-baseline", "scratch install changed latest");
}

// TestAllSixScratchIDsAreServedAfterCatalogConstruction
#[test]
fn all_six_scratch_ids_are_served_after_catalog_construction() {
    for profile in PROFILES {
        for mode in ["head_only", "end_to_end"] {
            let suffix = if mode == "end_to_end" { "full-encoder" } else { "head-only" };
            let model_id = format!("privoke-scratch-presence-{profile}-{suffix}");
            let live = new_live_scratch_server();
            let config = config_for(profile, mode, profile_dimensions(profile).unwrap());
            std::fs::write(live.dir().join(format!("{model_id}.json")), scratch_live_artifact_for(&model_id, &config, 1)).unwrap();
            let mut request = live_scratch_request();
            request.model_id = model_id.clone();
            let response = live
                .server
                .get_model_parameters_core(&request)
                .unwrap_or_else(|error| panic!("{model_id}: explicit scratch request failed: {error}"));
            assert_eq!((response.model_id.as_str(), response.version.as_str()), (model_id.as_str(), "v1.0.0+epoch.1"));
        }
    }
}

// TestScratchCatalogSeesAtomicReplacementAndRemoval
#[test]
fn scratch_catalog_sees_atomic_replacement_and_removal() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    assert_eq!(get_live_scratch(&live.server).version, "v1.0.0+epoch.1");

    let second = scratch_live_artifact_bytes(2);
    atomic_install_live_scratch(live.dir(), &second);
    let response = get_live_scratch(&live.server);
    assert_eq!(response.version, "v1.0.0+epoch.2");
    assert_eq!(
        response.metadata["artifact_file_checksum"],
        privoke_contracts::digest::sha256_hex(&second),
        "replacement response retained the previous file identity"
    );

    std::fs::remove_file(live.path()).unwrap();
    assert!(!live.server.catalog().contains(LIVE_SCRATCH_ID), "removed scratch ID remains in catalog lookup");
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::NotFound);
    assert_eq!(get_live_latest(&live.server), "privoke-baseline");
}

// TestScratchOptionalFilesDoNotBreakBaselineHealthButInvalidFilesDo
#[test]
fn scratch_optional_files_do_not_break_baseline_health_but_invalid_files_do() {
    let live = new_live_scratch_server();
    assert_live_scratch_health(&live.server, "SERVING");
    std::fs::write(live.path(), br#"{"not":"an artifact"}"#).unwrap();
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::Unavailable);
    assert_live_scratch_health(&live.server, "NOT_SERVING");
    std::fs::remove_file(live.path()).unwrap();
    assert_live_scratch_health(&live.server, "SERVING");
}

fn try_symlink(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    let result = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let result =
        if target.is_dir() { std::os::windows::fs::symlink_dir(target, link) } else { std::os::windows::fs::symlink_file(target, link) };
    result.is_ok()
}

// TestScratchCatalogRejectsSymlinkDirectoryAndWrongIdentity
#[test]
fn scratch_catalog_rejects_symlink_outside_catalog() {
    let live = new_live_scratch_server();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("outside.json");
    std::fs::write(&target, scratch_live_artifact_bytes(1)).unwrap();
    if !try_symlink(&target, &live.path()) {
        eprintln!("symlinks are unavailable on this platform; skipped");
        return;
    }
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::Unavailable);
    assert_live_scratch_health(&live.server, "NOT_SERVING");
}

#[test]
fn scratch_catalog_rejects_directory_at_canonical_filename() {
    let live = new_live_scratch_server();
    std::fs::create_dir(live.path()).unwrap();
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::Unavailable);
    assert_live_scratch_health(&live.server, "NOT_SERVING");
}

#[test]
fn scratch_catalog_rejects_wrong_model_identity() {
    let live = new_live_scratch_server();
    let wrong = "privoke-scratch-presence-efficient-full-encoder";
    std::fs::write(live.dir().join(format!("{wrong}.json")), fixture_bytes("scratch-presence-efficient.json")).unwrap();
    // A known filename cannot authorize a different ID inside its payload.
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::NotFound, "missing canonical ID");
    let mut request = live_scratch_request();
    request.model_id = wrong.into();
    assert_eq!(code_of(&live.server, &request), Code::Unavailable, "wrong identity");
}

// TestScratchCatalogRejectsUnknownAndTraversalIDs
#[test]
fn scratch_catalog_rejects_unknown_and_traversal_ids() {
    let live = new_live_scratch_server();
    std::fs::write(live.dir().join("privoke-scratch-presence-evil.json"), scratch_live_artifact_bytes(1)).unwrap();
    for model_id in ["privoke-scratch-presence-evil", "../privoke-baseline", "privoke-baseline/../../outside"] {
        let mut request = live_scratch_request();
        request.model_id = model_id.into();
        assert!(live.server.get_model_parameters_core(&request).is_err(), "unallowlisted model ID was served: {model_id}");
    }
    assert_eq!(get_live_latest(&live.server), "privoke-baseline", "unknown files changed latest");
}

// TestScratchCatalogPropagatesStatErrors
#[test]
fn scratch_catalog_propagates_stat_errors() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    live.server.catalog().set_scratch_lstat(Some(Arc::new(|root: &Path, name: &str| {
        if name == format!("{LIVE_SCRATCH_ID}.json") {
            return Err(std::io::Error::other("injected scratch stat failure"));
        }
        std::fs::symlink_metadata(root.join(name))
    })));
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::Unavailable);
    assert_live_scratch_health(&live.server, "NOT_SERVING");
}

/// Substitute `replacement` at the entry path for the duration of one open, then restore the original file.
fn substituting_open(
    path: PathBuf,
    backup: PathBuf,
    substitute: impl Fn(&Path) -> std::io::Result<()> + Send + Sync + 'static,
) -> OpenHook {
    let injected = AtomicBool::new(false);
    Arc::new(move |root: &Path, name: &str| {
        let open = || std::fs::File::open(root.join(name));
        if injected.swap(true, Ordering::SeqCst) {
            return open();
        }
        std::fs::rename(&path, &backup)?;
        if let Err(error) = substitute(&path) {
            let _ = std::fs::rename(&backup, &path);
            return Err(error);
        }
        let file = open();
        std::fs::remove_file(&path)?;
        std::fs::rename(&backup, &path)?;
        file
    })
}

// TestScratchCatalogRejectsInspectedFileABAReplacement
#[test]
fn scratch_catalog_rejects_inspected_file_aba_replacement() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    let path = live.path();
    let backup = PathBuf::from(format!("{}.captured", path.display()));
    let replacement = scratch_live_artifact_bytes(2);
    live.server
        .catalog()
        .set_scratch_open(Some(substituting_open(path.clone(), backup, move |target| std::fs::write(target, &replacement))));
    let error = live.server.catalog().load_model(LIVE_SCRATCH_ID).unwrap_err();
    assert!(error.0.contains("does not match the inspected regular file"), "ABA substitution rejected for the wrong reason: {error}");
    live.server.catalog().set_scratch_open(None);
    live.server.catalog().set_scratch_open(None);
    assert_eq!(get_live_scratch(&live.server).version, "v1.0.0+epoch.1", "restored original file version");
}

// TestScratchCatalogRejectsOutsideSymlinkSubstitutionDuringOpen
#[test]
fn scratch_catalog_rejects_outside_symlink_substitution_during_open() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    let outside_dir = tempfile::tempdir().unwrap();
    let outside = outside_dir.path().join("outside.json");
    std::fs::write(&outside, scratch_live_artifact_bytes(2)).unwrap();
    let probe = outside_dir.path().join("probe-link");
    if !try_symlink(&outside, &probe) {
        eprintln!("symlinks are unavailable on this platform; skipped");
        return;
    }
    let path = live.path();
    let backup = PathBuf::from(format!("{}.captured", path.display()));
    let target = outside.clone();
    live.server.catalog().set_scratch_open(Some(substituting_open(path, backup, move |link| {
        if try_symlink(&target, link) { Ok(()) } else { Err(std::io::Error::other("symlink failed")) }
    })));
    assert_eq!(code_of(&live.server, &live_scratch_request()), Code::Unavailable, "outside symlink substitution");
    live.server.catalog().set_scratch_open(None);
    assert_eq!(get_live_scratch(&live.server).version, "v1.0.0+epoch.1", "outside symlink changed the catalog response");
}

// TestScratchCatalogRejectsDirectoryPathSubstitution
#[test]
fn scratch_catalog_rejects_directory_path_substitution() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join(format!("{LIVE_SCRATCH_ID}.json")), scratch_live_artifact_bytes(2)).unwrap();
    std::fs::copy(live.dir().join("privoke-baseline.json"), outside.path().join("privoke-baseline.json")).unwrap();
    let directory = live.dir().to_path_buf();
    let captured = PathBuf::from(format!("{}.captured", directory.display()));
    if std::fs::rename(&directory, &captured).is_err() {
        eprintln!("the catalog directory cannot be renamed while it is pinned on this platform; skipped");
        return;
    }
    if !common::try_dir_link(outside.path(), &directory) {
        let _ = std::fs::rename(&captured, &directory);
        eprintln!("directory symlinks are unavailable on this platform; skipped");
        return;
    }
    let outcome = (code_of(&live.server, &live_scratch_request()), live.server.health_core().status);
    // Restore before asserting so the temporary directory can be cleaned up.
    let _ = std::fs::remove_dir(&directory).or_else(|_| std::fs::remove_file(&directory));
    // A junction is removed with `remove_dir`; nothing under the outside directory is touched.
    let _ = std::fs::rename(&captured, &directory);
    assert_eq!(outcome, (Code::Unavailable, "NOT_SERVING".to_string()), "directory substitution");
}

// TestScratchCatalogConcurrentReadsInstallAndRemove
#[test]
fn scratch_catalog_concurrent_reads_install_and_remove() {
    let live = new_live_scratch_server();
    install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1));
    let server = Arc::new(live.server.clone());
    let mut readers = Vec::new();
    for _ in 0..8 {
        let server = server.clone();
        readers.push(std::thread::spawn(move || {
            for _ in 0..30 {
                if let Err(error) = server.get_model_parameters_core(&live_scratch_request())
                    && !matches!(error.code(), Code::NotFound | Code::Unavailable)
                {
                    return Some(error);
                }
            }
            None
        }));
    }
    for iteration in 0..20u32 {
        if iteration % 2 == 0 {
            let _ = std::fs::remove_file(live.path());
            continue;
        }
        atomic_install_live_scratch(live.dir(), &scratch_live_artifact_bytes(1 + (iteration % 2)));
    }
    for reader in readers {
        if let Some(error) = reader.join().unwrap() {
            panic!("unexpected concurrent request error: {error}");
        }
    }
    let _ = std::fs::remove_file(live.path());
    assert_live_scratch_health(&live.server, "SERVING");
    assert!(!live.server.catalog().contains(LIVE_SCRATCH_ID), "removed ID remained in the live catalog");
}
