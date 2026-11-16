//! Shared helpers for the ported Go tests: fixture paths, the Go test helper functions and a few JSON builders.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::json::Value;
use privoke_model_streaming::artifact::{self, ModelArtifact, Tensor};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::contextual::{self, STRATEGY_KEY};
use privoke_model_streaming::jsonx::{self, Object};

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn fixture_path(name: &str) -> PathBuf {
    repo_root().join("shared/python/tests/fixtures").join(name)
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap()
}

pub fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).unwrap()
}

pub fn model_path(profile: &str) -> PathBuf {
    repo_root().join("models").join(format!("privoke-{profile}.json"))
}

/// `contextualFixture`.
pub fn contextual_fixture() -> ModelArtifact {
    artifact::load_model_artifact_bytes(&fixture_bytes("contextual-last-block.json"), "contextual-training-fixture").unwrap().artifact
}

/// `taskQueryFixture`.
pub fn task_query_fixture() -> ModelArtifact {
    artifact::load_model_artifact_bytes(&fixture_bytes("contextual-task-query.json"), "contextual-training-fixture").unwrap().artifact
}

/// `presenceFixture`: decoded without validation, as Go's `json.Unmarshal` does.
pub fn presence_fixture() -> ModelArtifact {
    artifact::decode_artifact_bytes(&fixture_bytes("presence-efficient.json")).unwrap()
}

/// A profile artifact from `models/`, decoded without validation.
pub fn model_artifact(profile: &str) -> ModelArtifact {
    artifact::decode_artifact_bytes(&std::fs::read(model_path(profile)).unwrap()).unwrap()
}

pub fn pretrained_fixture() -> artifact::LoadedArtifact {
    artifact::load_model_artifact(&fixture_path("pretrained-context-minilm.json"), "privoke-pretrained-context-minilm").unwrap()
}

pub fn scratch_fixture() -> artifact::LoadedArtifact {
    artifact::load_model_artifact(&fixture_path("scratch-presence-efficient.json"), "privoke-scratch-presence-efficient-head-only").unwrap()
}

pub fn text(value: &str) -> Value {
    Value::String(value.to_string())
}

pub fn list(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|item| text(item)).collect())
}

pub fn int(value: i64) -> Value {
    Value::Int(value.to_string())
}

/// Parse the config, let `mutate` edit the top-level object, and write it back as compact JSON (Go's `rewriteConfig`).
pub fn rewrite_config(artifact: &mut ModelArtifact, mutate: impl FnOnce(&mut Object)) {
    let mut object = jsonx::object_of(&artifact.config).unwrap();
    mutate(&mut object);
    artifact.config = canonical::to_string(&Value::Object(object), Variant::Utf8).unwrap();
}

/// Edit a nested object (`config["branches"]["word"]`).
pub fn nested<'a>(object: &'a mut Object, path: &[&str]) -> &'a mut Object {
    let mut current = object;
    for key in path {
        let Some(Value::Object(next)) = current.get_mut(*key) else { panic!("missing object {key}") };
        current = next;
    }
    current
}

pub fn tensor(shape: &[u32], values: Vec<f64>, trainable: bool) -> Tensor {
    Tensor { shape: shape.to_vec(), values, trainable }
}

/// Make exactly the head tensors trainable and drop the strategy: the "unadapted" fixture variant.
pub fn make_unadapted(artifact: &mut ModelArtifact) {
    artifact.metadata_mut().remove(STRATEGY_KEY);
    let heads: Vec<String> = ["sensitivity", "visibility", "category"]
        .iter()
        .flat_map(|head| [format!("head.{head}.weight"), format!("head.{head}.bias")])
        .collect();
    for (name, tensor) in &mut artifact.parameters {
        tensor.trainable = heads.contains(name);
    }
}

/// `writeTestArtifact`: the contextual fixture reduced to the legacy head-only artifact `privoke-baseline`, written
/// with a valid checksum into a fresh directory.
pub fn write_test_artifact() -> (tempfile::TempDir, PathBuf) {
    let mut typed = contextual_fixture();
    typed.metadata_mut().remove(STRATEGY_KEY);
    let (heads, _) = contextual::contextual_trainable_names(&typed.config, "").unwrap();
    for (name, tensor) in &mut typed.parameters {
        tensor.trainable = heads.contains(name);
    }
    typed.model_id = "privoke-baseline".into();
    typed.version = "v1".into();
    typed.generated_at_unix = 1;
    let payload = artifact::to_checked_bytes(&typed).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("model.json");
    std::fs::write(&path, payload).unwrap();
    (directory, path)
}

/// `testCatalog`.
pub fn test_catalog(path: &Path) -> Catalog {
    Catalog::from_paths("privoke-baseline", BTreeMap::from([("privoke-baseline".to_string(), path.to_path_buf())]))
}

/// Link `link` to the directory `target`: a symlink where the platform allows it, otherwise (Windows without the
/// symlink privilege) a directory junction, which `symlink_metadata` also reports as a link.
pub fn try_dir_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|output| output.status.success())
    }
}

/// The prepared standard releases, from `V3_TEST_RELEASE_DIR`, this checkout, or the main checkout that owns this
/// worktree (`models/standard-releases` is ignored by Git, so a linked worktree does not hold it).
pub fn release_dir_for_tests() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("V3_TEST_RELEASE_DIR").filter(|value| !value.is_empty()) {
        return Some(path.into());
    }
    let local = repo_root().join("models/standard-releases");
    if local.is_dir() {
        return Some(local);
    }
    // A linked worktree's `.git` file names `<main>/.git/worktrees/<name>`.
    let pointer = std::fs::read_to_string(repo_root().join(".git")).ok()?;
    let git_dir = PathBuf::from(pointer.trim().strip_prefix("gitdir:")?.trim());
    let main = git_dir.parent()?.parent()?.parent()?.join("models/standard-releases");
    main.is_dir().then_some(main)
}
