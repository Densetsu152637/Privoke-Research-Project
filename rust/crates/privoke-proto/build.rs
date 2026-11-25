//! Compile `shared/proto` with `protox` (a pure-Rust protoc) so that no `protoc` is needed on any host.

use std::path::PathBuf;

const PROTOS: &[&str] =
    &["privoke/v1/parameters.proto", "privoke/v1/runtime.proto", "privoke/v1/telemetry.proto", "privoke/experimental/v3.proto"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../../shared/proto").canonicalize()?;
    println!("cargo:rerun-if-changed={}", proto_root.display());

    let descriptors = protox::compile(PROTOS, [&proto_root])?;
    // BTreeMap keeps map fields in sorted key order, which matches Python's deterministic serialisation.
    tonic_prost_build::configure().btree_map(".").compile_fds(descriptors)?;
    Ok(())
}
