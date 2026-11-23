//! Byte-exact ports of the PriVoke Python contracts that the Rust servers must reproduce.
//!
//! Every behaviour here is bound to the stage 0 conformance corpus (`tests/conformance/`), captured from the
//! reference Python and Go services:
//!
//! * [`json`] and [`canonical`]: Python-compatible canonical JSON in the four layouts the contracts use, with
//!   Python float `repr` ([`pyfloat`]).
//! * [`digest`]: artifact checksums, receipt keys and derived seeds.
//! * [`fingerprint`]: structurally framed tensor identity.
//! * [`v3`]: the pinned standard V3 manifest rules.
//! * [`pywire`]: protobuf bytes as Python's deterministic serialization writes them (the fuzzer request, V3-R8a).
//! * [`model_cache`]: which cached version of a model a client may load (stage V3-R4b).
//!
//! The protobuf bindings are re-exported as [`proto`].

pub mod canonical;
pub mod digest;
pub mod fingerprint;
pub mod json;
pub mod model_cache;
pub mod publication;
pub mod pyfloat;
pub mod pywire;
pub mod v3;

pub use privoke_proto as proto;
