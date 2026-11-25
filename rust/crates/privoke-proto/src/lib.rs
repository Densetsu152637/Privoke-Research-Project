//! Protobuf and gRPC bindings for `shared/proto`, generated at build time with `protox` and `tonic-prost-build`.
//!
//! Map fields use `BTreeMap`, so encoding is key-ordered and equals Python's `SerializeToString(deterministic=True)`.

#![allow(clippy::all, missing_docs, missing_debug_implementations)]

// The module tree mirrors the protobuf packages because the generated code refers to its siblings with `super::`.
mod privoke {
    pub mod v1 {
        tonic::include_proto!("privoke.v1");
    }
    pub mod experimental {
        pub mod v3 {
            tonic::include_proto!("privoke.experimental.v3");
        }
    }
}

/// `privoke.experimental.v3` services and messages (checkpoint, training and V3 fuzzer services).
pub use privoke::experimental::v3 as experimental_v3;
/// `privoke.v1` services and messages.
pub use privoke::v1;
