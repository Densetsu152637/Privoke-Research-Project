//! The frozen schedules of the two samplers and the identity of the Python source closure.
//!
//! The schedules are [`privoke_curriculum::v3`] (stage 20): `schedule_bc01` over the pinned taxonomy and benign inputs, and
//! `build_au3` followed by `validate_au3` over the pinned audience release. Both record `source_hashes`, the digests of the
//! Python files that pin the sampler. The host that dispatches a request commits to the source record that includes them
//! (`source_commitment`), so the service takes them from the same repository bytes: `V3_SOURCE_ROOT` names a checkout of the
//! files `services/pretrained-v3/src/*.py`, `services/privoke-fuzzer/src/...` that the host hashed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_curriculum::audience::AudienceRelease;
use privoke_curriculum::v3::{self, AU3_SAMPLER, AU3_SOURCE_FILES, BC01_SAMPLER, BC01_SOURCE_FILES, Policy, Schedule, Sources};
use privoke_curriculum::value::{self, Value};

use crate::error::{Result, invalid};

/// The two frozen samplers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampler {
    /// `existing_taxonomy_benign_common_frozen_stream_v1`.
    Bc01,
    /// `audience_common_frozen_stream_v1`.
    Au3,
}

impl Sampler {
    /// The sampler's tag, as it appears in the source record, the fingerprint and `Health`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Bc01 => BC01_SAMPLER,
            Self::Au3 => AU3_SAMPLER,
        }
    }

    /// `V3_SAMPLING_STRATEGY`: only the two frozen samplers are admitted.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            BC01_SAMPLER => Ok(Self::Bc01),
            AU3_SAMPLER => Ok(Self::Au3),
            _ => invalid("Unknown configured v3 sampler."),
        }
    }
}

/// A sampler with its loaded inputs and the source digests it records.
#[derive(Debug, Clone)]
pub enum Schedules {
    /// BC01: the taxonomy dataset and the benign release.
    Bc01 {
        /// The pinned inputs.
        sources: Box<Sources>,
        /// The `source_hashes` member of the source record.
        source_hashes: Value,
    },
    /// AU3: the trusted audience release.
    Au3 {
        /// The pinned release.
        release: Box<AudienceRelease>,
        /// The `source_hashes` member of the source record.
        source_hashes: Value,
    },
}

impl Schedules {
    /// BC01 over inputs loaded by [`v3::load_sources`] or [`v3::load_sources_from`].
    pub fn bc01(sources: Sources, source_hashes: Value) -> Self {
        Self::Bc01 { sources: Box::new(sources), source_hashes }
    }

    /// AU3 over a trusted release.
    pub fn au3(release: AudienceRelease, source_hashes: Value) -> Self {
        Self::Au3 { release: Box::new(release), source_hashes }
    }

    /// Which sampler this is.
    pub fn sampler(&self) -> Sampler {
        match self {
            Self::Bc01 { .. } => Sampler::Bc01,
            Self::Au3 { .. } => Sampler::Au3,
        }
    }

    /// The pin the fingerprint carries besides the sampler name: the audience release digest (`BC01` has none).
    pub fn source_pin(&self) -> Option<&str> {
        match self {
            Self::Bc01 { .. } => None,
            Self::Au3 { release, .. } => Some(&release.sha256),
        }
    }

    /// `fuzzer_training.schedule(seed, policy, sampler=)`: the training rows, the guard rows and the source record.
    pub fn schedule(&self, seed: u64, policy: Policy) -> Result<Schedule> {
        match self {
            Self::Bc01 { sources, source_hashes } => Ok(v3::schedule_bc01(seed, policy, sources, source_hashes.clone())?),
            Self::Au3 { release, source_hashes } => {
                let built = v3::build_au3(seed, policy, release, source_hashes.clone())?;
                v3::validate_au3(&built, policy, release)?;
                Ok(built)
            }
        }
    }
}

/// The digests of the Python files that pin `sampler`, hashed under `root`.
pub fn python_source_hashes(root: &Path, sampler: Sampler) -> Result<Value> {
    let files: &[&str] = match sampler {
        Sampler::Bc01 => &BC01_SOURCE_FILES,
        Sampler::Au3 => &AU3_SOURCE_FILES,
    };
    Ok(v3::python_source_hashes(root, files)?)
}

/// The four BC01 inputs under `root`, as [`v3::load_sources_from`] takes them.
pub fn bc01_input_paths(root: &Path) -> BTreeMap<&'static str, PathBuf> {
    v3::INPUTS.iter().map(|(key, relative, _)| (*key, root.join(relative))).collect()
}

const CLOSURE_PREFIXES: [&str; 5] =
    ["shared/python", "shared/proto", "extension/client-runtime/src", "services/privoke-fuzzer/src", "services/pretrained-v3/src"];

/// Where the `source_closure` of `Health` comes from.
#[derive(Debug, Clone)]
pub enum Closure {
    /// `source_inventory()`: the digest of every `.py` and `.proto` file of the closure under a checkout.
    Root(PathBuf),
    /// A fixed identity (the tests).
    Fixed(String),
}

impl Closure {
    /// `source_identity()`.
    pub fn identity(&self) -> Result<String> {
        match self {
            Self::Fixed(identity) => Ok(identity.clone()),
            Self::Root(root) => {
                let inventory: BTreeMap<String, Value> =
                    inventory(root)?.into_iter().map(|(path, digest)| (path, value::string(&digest))).collect();
                Ok(value::digest_of(&Value::Object(inventory))?)
            }
        }
    }
}

fn collect(directory: &Path, root: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|name| name != "__pycache__") {
                    pending.push(path);
                }
            } else if path.is_file() && path.extension().is_some_and(|extension| extension == "py" || extension == "proto") {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                let name: Vec<String> = relative.components().map(|part| part.as_os_str().to_string_lossy().to_string()).collect();
                out.insert(name.join("/"), value::sha256(&std::fs::read(&path)?));
            }
        }
    }
    Ok(())
}

/// `source_inventory()`: repository-relative path to digest, for every source of the closure.
pub fn inventory(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for prefix in CLOSURE_PREFIXES {
        collect(&root.join(prefix), root, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn the_closure_covers_python_and_proto_sources_only() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        write(root, "shared/python/a.py", b"a");
        write(root, "shared/proto/privoke/v1/b.proto", b"b");
        write(root, "services/pretrained-v3/src/c.py", b"c");
        write(root, "services/pretrained-v3/src/__pycache__/c.py", b"cache");
        write(root, "services/pretrained-v3/src/notes.md", b"notes");
        write(root, "evaluation/ignored.py", b"outside");
        let found = inventory(root).unwrap();
        assert_eq!(
            found.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["services/pretrained-v3/src/c.py", "shared/proto/privoke/v1/b.proto", "shared/python/a.py"]
        );
        assert_eq!(found["shared/python/a.py"], value::sha256(b"a"));
        let first = Closure::Root(root.to_path_buf()).identity().unwrap();
        write(root, "shared/python/a.py", b"changed");
        assert_ne!(first, Closure::Root(root.to_path_buf()).identity().unwrap(), "a dirty helper changes the identity");
        assert_eq!(Closure::Fixed("x".into()).identity().unwrap(), "x");
    }

    #[test]
    fn only_the_two_frozen_samplers_are_admitted() {
        assert_eq!(Sampler::parse("audience_common_frozen_stream_v1").unwrap(), Sampler::Au3);
        assert_eq!(Sampler::parse("existing_taxonomy_benign_common_frozen_stream_v1").unwrap(), Sampler::Bc01);
        assert_eq!(Sampler::parse("legacy").unwrap_err().0, "Unknown configured v3 sampler.");
    }
}
