//! Ports of `standard_v3_test.go`.
//!
//! The release store is read from `V3_TEST_RELEASE_DIR`, or `models/standard-releases` of this checkout or of the main
//! checkout that owns the worktree. Without one the pinned-asset test reports itself skipped, as the Go test does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use common::write_test_artifact;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::{ModelAssetRequest, ModelParametersRequest};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::config::ServiceConfig;
use privoke_model_streaming::releases::{MODEL_ASSET_CHUNK_BYTES, STANDARD_IDS, StandardReleases, V3_ARCHITECTURE, standard_pin};
use privoke_model_streaming::service::ModelService;
use tonic::Code;

fn try_symlink(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    let result = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let result =
        if target.is_dir() { std::os::windows::fs::symlink_dir(target, link) } else { std::os::windows::fs::symlink_file(target, link) };
    result.is_ok()
}

// TestStandardV3DefaultAndMissingStoreFailClosed
#[test]
fn standard_v3_default_and_missing_store_fail_closed() {
    let config = ServiceConfig::from_lookup(|key| (key == "MODEL_LATEST_ID").then(String::new)).unwrap();
    assert_eq!(config.latest_model_id, "privoke-v3-balanced", "wrong standard default");
    assert!(StandardReleases::open(tempfile::tempdir().unwrap().path()).is_err(), "missing packages must fail admission");
    let server = ModelService::new(Arc::new(Catalog::from_paths(&config.latest_model_id, BTreeMap::new())));
    let error =
        server.get_model_parameters_core(&ModelParametersRequest { model_id: "latest".into(), consumer_id: String::new() }).unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition, "V3 must not enter legacy float RPC");
}

// TestStandardV3RejectsLinksTraversalAndUnpinnedManifests
#[test]
fn standard_v3_rejects_links_traversal_and_unpinned_manifests() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = directory.path().join("link");
    let links = common::try_dir_link(&target, &link);
    if links {
        assert!(StandardReleases::open(&link).is_err(), "release root symlink admitted");
    } else {
        eprintln!("directory links are unavailable on this platform; the link assertions are skipped");
    }
    let child = target.join("child");
    std::fs::create_dir(&child).unwrap();
    if links {
        assert!(StandardReleases::open(&link.join("child")).is_err(), "release ancestor symlink admitted");
    }
    let model = target.join("privoke-v3-efficient");
    std::fs::create_dir(&model).unwrap();
    std::fs::write(model.join("manifest.json"), "{}").unwrap();
    let releases = StandardReleases::unadmitted(&target);
    assert!(releases.manifest("privoke-v3-efficient").is_err(), "unpinned manifest admitted");
    for name in ["../manifest.json", "unknown"] {
        assert!(releases.open_asset("privoke-v3-efficient", name).is_err(), "unsafe asset admitted: {name}");
    }
    if try_symlink(&model.join("manifest.json"), &model.join("config.json")) {
        assert!(releases.open_asset("privoke-v3-efficient", "config.json").is_err(), "asset symlink admitted");
    }
}

// TestStandardV3ActualPinnedAssetsAndLegacyIsolation
#[test]
fn standard_v3_actual_pinned_assets_and_legacy_isolation() {
    let Some(directory) = common::release_dir_for_tests() else {
        eprintln!("set V3_TEST_RELEASE_DIR to the locally prepared immutable AU3 releases; skipped");
        return;
    };
    let releases = StandardReleases::open(&directory).unwrap();
    let (legacy_directory, _path) = write_test_artifact();
    let mut catalog = Catalog::load(legacy_directory.path(), "privoke-v3-balanced").unwrap();
    catalog.releases = Some(releases);
    let server = ModelService::new(Arc::new(catalog));
    // A mutable legacy publication cannot alter a configuration-owned V3 alias.
    server.catalog().load_model("privoke-baseline").unwrap();
    assert_eq!(server.catalog().latest_model_id(), "privoke-v3-balanced", "legacy load changed latest alias");

    let package_request = |model: &str| ModelParametersRequest { consumer_id: "unit".into(), model_id: model.into() };
    let latest = server.get_model_package_core(&package_request("latest")).unwrap();
    assert_eq!(latest.model_id, "privoke-v3-balanced");
    for id in STANDARD_IDS {
        let pin = standard_pin(id).unwrap();
        let package = server.get_model_package_core(&package_request(id)).unwrap();
        assert!(
            package.manifest_sha256 == pin && package.architecture == V3_ARCHITECTURE && package.assets.len() == 4,
            "wrong package identity"
        );
        for asset in &package.assets {
            let request = ModelAssetRequest {
                consumer_id: "unit".into(),
                model_id: id.into(),
                manifest_sha256: pin.into(),
                asset_name: asset.name.clone(),
            };
            server.check_asset_request(&request).unwrap();
            let releases = server.catalog().releases.as_ref().unwrap();
            let mut hash: Vec<u8> = Vec::new();
            let mut offset = 0u64;
            releases
                .stream_asset(id, pin, &asset.name, |chunk| {
                    assert!(
                        chunk.model_id == id
                            && chunk.manifest_sha256 == pin
                            && chunk.asset_name == asset.name
                            && chunk.sha256 == asset.sha256
                            && chunk.offset == offset
                            && chunk.total_bytes == asset.size_bytes
                            && !chunk.data.is_empty()
                            && chunk.data.len() <= MODEL_ASSET_CHUNK_BYTES,
                        "invalid wire chunk"
                    );
                    hash.extend_from_slice(&chunk.data);
                    offset += chunk.data.len() as u64;
                    true
                })
                .unwrap();
            assert!(offset == asset.size_bytes && sha256_hex(&hash) == asset.sha256, "asset wire hash/size mismatch");
        }
    }
    for name in ["../manifest.json", "manifest.json", "unknown"] {
        let request = ModelAssetRequest {
            model_id: latest.model_id.clone(),
            manifest_sha256: latest.manifest_sha256.clone(),
            asset_name: name.into(),
            ..Default::default()
        };
        assert_eq!(server.check_asset_request(&request).unwrap_err().code(), Code::InvalidArgument, "unsafe asset {name:?} admitted");
    }
    let legacy = server
        .get_model_parameters_core(&ModelParametersRequest { model_id: "privoke-baseline".into(), consumer_id: String::new() })
        .unwrap();
    assert_eq!(legacy.model_id, "privoke-baseline", "legacy control failed");
    let again = server.get_model_package_core(&package_request("latest")).unwrap();
    assert_eq!(again.manifest_sha256, latest.manifest_sha256, "legacy request changed V3 standard alias");
    server.catalog().validate().unwrap();
}
