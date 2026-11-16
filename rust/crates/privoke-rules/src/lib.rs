//! Regex rules, Presidio recognisers and canonical-text preprocessing of the PriVoke client
//! runtime, ported from `extension/client-runtime/src/regex` and `detection/preprocessing.py`.
//!
//! The crate reproduces the Python layer's output exactly: rule hits (name, span, signal,
//! classification) and the normalised text with its offset maps. All offsets are code point
//! indexes, as in Python.
//!
//! # Unicode version
//!
//! Python's text semantics depend on its Unicode database, not on Rust's. Every property the
//! port needs (`\w`, `\d`, `\s`, `str.lower()`, `str.upper()`, `isdigit`, `Cf`, combining
//! classes and the NFKC data) is generated from the reference interpreter into
//! [`unicode_tables`], whose version is [`unicode_tables::UNICODE_VERSION`] (Unicode 14.0.0,
//! CPython 3.11.9). The Rust engines are only ever shown text and patterns that use ASCII
//! plus a handful of stand-in characters (see [`pyre`]), so the Unicode version of the
//! `regex` crate does not matter.

pub mod classification;
pub mod detector;
pub mod gitleaks;
pub mod layer;
pub mod preprocessing;
mod presidio;
pub mod pyre;
pub mod pyunicode;
pub mod rules;
#[rustfmt::skip]
pub mod unicode_tables;
pub mod validators;

pub use detector::{Detector, DetectorError, RuleHit, RuleSetOptions};
pub use layer::{LayerHit, LayerOptions, LayerOutcome, analyse_regex_layer};
pub use preprocessing::{NormalizedText, RobustnessOptions, normalize_text, normalize_with_offsets};
