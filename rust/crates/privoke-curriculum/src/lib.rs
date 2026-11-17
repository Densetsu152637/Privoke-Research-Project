//! Curricula, frozen schedules and update aggregation of the PriVoke fuzzer, ported from
//! `services/privoke-fuzzer/src/{prompt_generation,training}` and `services/pretrained-v3/src/{fuzzer_training,audience_schedule}.py`
//! (stage 20).
//!
//! The crate is deterministic by construction: every sampler draws from [`pyrandom::Random`], an exact
//! reimplementation of CPython's `random.Random`, so a seed reproduces the Python selection, order, metadata and every
//! digest the recorded evidence pins.
//!
//! * [`pyrandom`]: MT19937 seeded like `random.seed`, with `random`, `getrandbits`, `_randbelow`, `choice`,
//!   `shuffle`, `sample`, `randrange`, `uniform` and `choices`.
//! * [`generator`], [`defaults`], [`templates`], [`prompt_seed`]: the legacy random prompt generator and the contextual
//!   role-quota sampler.
//! * [`taxonomy`], [`anchor`], [`benign`]: the taxonomy coverage partition and its two opt-in variants.
//! * [`audience`], [`privacy_heads`]: the AU3 audience coverage release and the PH3 fact-contrast rows.
//! * [`presence`], [`curriculum`], [`train_window`]: the binary presence curriculum, the durable synthetic curriculum
//!   allocation and the frozen BC01 training window.
//! * [`trainer`]: the pure half of the trainer (seeded augmentation, request validation, publication metadata).
//! * [`v3`]: the frozen common ordered streams of the V3 fits.
//!
//! Python's text semantics come from `privoke_rules::pyunicode`, never from Rust's `char` predicates.

pub mod anchor;
pub mod audience;
pub mod benign;
pub mod classification;
pub mod curriculum;
pub mod defaults;
pub mod error;
pub mod generator;
pub mod presence;
pub mod privacy_heads;
pub mod prompt_seed;
pub mod pyrandom;
pub mod taxonomy;
pub mod templates;
pub mod text;
pub mod train_window;
pub mod trainer;
pub mod types;
pub mod v3;
pub mod value;

pub use error::{Error, Result};
pub use pyrandom::Random;
pub use types::{BatchTrainingConfig, Example};
