//! The cloud binary must not contain the plaintext loopback listener.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn the_release_dependency_tree_has_no_plaintext_feature() {
    let output = Command::new(env!("CARGO"))
        .args(["tree", "--locked", "-p", "privoke-model-streaming", "-e", "features", "-e", "no-dev", "--manifest-path"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let tree = String::from_utf8_lossy(&output.stdout);
    assert!(tree.contains("privoke-transport"), "the transport crate is not in the tree");
    assert!(!tree.contains("workstation-loopback"), "the cloud binary links the plaintext loopback listener:\n{tree}");
}
