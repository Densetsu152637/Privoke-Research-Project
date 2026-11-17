//! Certificate profile tooling for PriVoke: the operator's CA and the installation's enrolment.
//!
//! Operator side ([`ca`], [`registry_edit`]): create CAs, issue server, service and reporter certificates, sign
//! installation CSRs, revoke, publish CRLs, and keep the registry file current.
//!
//! Installation side ([`client`]): `enrol`, `renew`, `install_cert` and `status`. The supervisor will call these;
//! `privoke-pki` exposes the same operations on the command line.
//!
//! The profile is fixed: leaf certificates, `clientAuth` EKU only, one `urn:privoke:` URI SAN, 180-day validity for
//! installations.

pub mod ca;
pub mod client;
pub mod error;
pub mod files;
pub mod registry_edit;

pub use error::PkiError;
