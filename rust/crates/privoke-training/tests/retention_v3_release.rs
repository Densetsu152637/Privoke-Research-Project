//! The V3 reference releases and the retention rule on the real standard releases, the approved bank and the routine calibration
//! candidates (stage V3-R9). Environment gated: nothing runs unless `PRIVOKE_V3_RETENTION_RELEASES` is set, so CI skips it; the
//! real weights and the bank (prompt text) are never part of the repository. Run in Docker with the data mounted read-only:
//!
//! ```text
//! MSYS_NO_PATHCONV=1 docker run --rm --name v3r9-<t> --cpus=8 -e CARGO_TARGET_DIR=target-docker-rel \
//!   -e PRIVOKE_V3_RETENTION_RELEASES=/data/models/standard-releases \
//!   -e PRIVOKE_V3_RETENTION_BANK=/data/evaluation/results/iterative_fuzzer_20261011/train-sensitive-retention/approved-train-bank.json \
//!   -e PRIVOKE_V3_RETENTION_TIERS=efficient -e PRIVOKE_V3_RETENTION_OUT=/out \
//!   -e PRIVOKE_V3_RETENTION_CANDIDATES=/data/models/experiments/v3r5_routine_20261123/std \
//!   -v <worktree>:/work -v <data>:/data:ro -v <out>:/out -w /work/rust rust:1.99.1-bookworm \
//!   cargo test -p privoke-training --release --locked --test retention_v3_release -- --nocapture
//! ```
//!
//! * `PRIVOKE_V3_RETENTION_RELEASES`: the directory holding `privoke-v3-<tier>` (the pinned standard releases).
//! * `PRIVOKE_V3_RETENTION_BANK`: the approved bank (must hash to `BANK_SHA256`).
//! * `PRIVOKE_V3_RETENTION_TIERS`: comma-separated tiers (default all three).
//! * `PRIVOKE_V3_RETENTION_OUT`: when set, the built release is written to `<out>/<tier>/{references,manifest}.json`.
//! * `PRIVOKE_V3_RETENTION_CANDIDATES`: a directory of `privoke-v3-<tier>-*.safetensors` candidates to judge (printed).
//!
//! Once the pins are recorded (`RELEASE_PINS`), the test requires the rebuilt manifest to hash to the pin of its tier.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use privoke_contracts::digest::sha256_hex;
use privoke_semantic::V3Model;
use privoke_semantic::safetensors;
use privoke_training::retention_v3::{RELEASE_PINS, RetentionRelease, build_production_release, production_spec};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn candidates(directory: &Path, tier: &str) -> Vec<PathBuf> {
    let prefix = format!("privoke-v3-{tier}-");
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            name.starts_with(&prefix) && name.ends_with(".safetensors")
        })
        .collect();
    files.sort();
    files
}

#[test]
fn the_reference_release_of_each_tier_is_reproducible_and_judges_the_routine_candidates() {
    let Some(releases) = env("PRIVOKE_V3_RETENTION_RELEASES") else {
        eprintln!("PRIVOKE_V3_RETENTION_RELEASES is unset: skipped");
        return;
    };
    let bank = std::fs::read(env("PRIVOKE_V3_RETENTION_BANK").expect("PRIVOKE_V3_RETENTION_BANK")).unwrap();
    let tiers: Vec<String> = env("PRIVOKE_V3_RETENTION_TIERS")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_else(|| vec!["efficient".into(), "balanced".into(), "quality".into()]);
    for tier in tiers {
        let directory = Path::new(&releases).join(format!("privoke-v3-{tier}"));
        let started = Instant::now();
        let built = build_production_release(&tier, &directory, &bank, &mut |_| {}).unwrap();
        let (manifest_sha, references_sha) = (built.manifest_sha256(), built.references_sha256());
        let eligible = built.rows.iter().filter(|row| row.eligible).count();
        eprintln!(
            "{tier}: built in {:.1}s, rows {}, eligible {eligible}, manifest {manifest_sha}, references {references_sha}",
            started.elapsed().as_secs_f64(),
            built.rows.len()
        );
        if let Some(out) = env("PRIVOKE_V3_RETENTION_OUT") {
            let target = Path::new(&out).join(&tier);
            std::fs::create_dir_all(&target).unwrap();
            std::fs::write(target.join("references.json"), built.references.as_bytes()).unwrap();
            std::fs::write(target.join("manifest.json"), built.manifest.as_bytes()).unwrap();
        }
        let pin = RELEASE_PINS.iter().find(|(name, _)| *name == tier).unwrap().1;
        let recorded = pin.bytes().any(|byte| byte != b'0');
        if recorded {
            assert_eq!(manifest_sha, pin, "{tier}: the rebuilt release is not the pinned one");
        } else {
            eprintln!("{tier}: no pin recorded yet");
        }
        let spec = production_spec(&tier).unwrap();
        let load_spec = privoke_training::retention_v3::ReleaseSpec { manifest_sha256: &manifest_sha, ..spec };
        let release = RetentionRelease::load(&bank, built.references.as_bytes(), built.manifest.as_bytes(), &load_spec).unwrap();
        assert_eq!(sha256_hex(built.manifest.as_bytes()), release.sha256);
        let teacher = V3Model::load_release(&directory, spec.model_id).unwrap();
        // The pinned release itself retains everything (it is the teacher).
        let own = release.assess(&teacher).unwrap();
        assert_eq!((own.violations, own.passes()), (0, true), "{tier}: the teacher regressed against its own references");
        eprintln!("{tier}: teacher retains {} of {} eligible rows", own.rows.len() - own.violations, own.rows.len());
        // A candidate that forgot its sensitive class (the S0 logit pushed up) regresses on every eligible row.
        let mut forgetful = safetensors::parse(&std::fs::read(directory.join("model.safetensors")).unwrap()).unwrap();
        forgetful.get_mut("heads.sensitivity_bias").unwrap().data[0] += 1_000.0;
        let forgot = release.assess(&teacher.with_tensors(forgetful).unwrap()).unwrap();
        eprintln!("{tier}: forgetful candidate violations {} of {} passes {}", forgot.violations, forgot.rows.len(), forgot.passes());
        assert!(!forgot.passes(), "{tier}: a candidate that reads everything as S0 must be refused");
        let Some(candidate_dir) = env("PRIVOKE_V3_RETENTION_CANDIDATES") else { continue };
        for file in candidates(Path::new(&candidate_dir), &tier) {
            let started = Instant::now();
            let tensors = safetensors::parse(&std::fs::read(&file).unwrap()).unwrap();
            let report = release.assess(&teacher.with_tensors(tensors).unwrap()).unwrap();
            let lost: Vec<&str> = report.rows.iter().filter(|row| row.violation).map(|row| row.id.as_str()).collect();
            eprintln!(
                "{tier}: {} violations {} of {} passes {} ({:.1}s) {lost:?}",
                file.file_name().unwrap().to_string_lossy(),
                report.violations,
                report.rows.len(),
                report.passes(),
                started.elapsed().as_secs_f64()
            );
        }
    }
}
