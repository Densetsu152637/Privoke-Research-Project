//! The V3 fit on a real local V3 package against the product's `fit` (`generate_v3_fit_golden.py real`). Skipped unless
//! `PRIVOKE_V3_FIT_GOLDEN` names the golden directory; `PRIVOKE_V3_PACKAGE` names the package directory (`config.json` and
//! `model.safetensors`, the ORIGINAL release the golden was made from) and `PRIVOKE_V3_VOCAB` its `vocab.txt`. The study data
//! stays out of Git and CI: the rows are deterministic synthetic prompts and the golden lives in an ignored directory.
//!
//! Both scopes run the pilot policy (two AdamW steps over 64 rows) through the validated [`privoke_training::v3_fit::fit`], that is
//! including `validate_execution` against the admitted tier (the 4-layer `efficient` model: 4,785,044 parameters). The
//! comparison is the tolerance category (Torch float32 against float64 over float32 weights): counts, blocks, phases and change
//! groups exact; losses and gradient norms within 1e-4; guard rows equal; candidate tensors within the optimizer's step bound with
//! the fraction within 1e-6 reported (at least 90 percent required).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_semantic::V3Model;
use privoke_semantic::safetensors::parse;
use privoke_training::v3_fit::{fit, validate_execution};
use serde_json::Value;

mod v3_fit_support;
use v3_fit_support::{compare, input, rows};

#[test]
fn the_fit_on_the_real_package_matches_the_product() {
    let (Some(golden_dir), Some(package), Some(vocab)) = (
        std::env::var_os("PRIVOKE_V3_FIT_GOLDEN").map(PathBuf::from),
        std::env::var_os("PRIVOKE_V3_PACKAGE").map(PathBuf::from),
        std::env::var_os("PRIVOKE_V3_VOCAB").map(PathBuf::from),
    ) else {
        eprintln!("v3 fit release parity skipped: PRIVOKE_V3_FIT_GOLDEN, PRIVOKE_V3_PACKAGE and PRIVOKE_V3_VOCAB are not all set");
        return;
    };
    let golden: Value = serde_json::from_slice(&std::fs::read(golden_dir.join("golden.json")).unwrap()).unwrap();
    let model = V3Model::from_files(&package.join("config.json"), &package.join("model.safetensors"), &vocab).unwrap();
    let base = parse(&std::fs::read(package.join("model.safetensors")).unwrap()).unwrap();
    assert_eq!(rows(&golden["train"]).len(), 64);
    for scope in ["heads", "full_encoder"] {
        let started = std::time::Instant::now();
        let result = fit(&model, &base, &input(&golden, scope), &|| true).unwrap();
        eprintln!("v3 fit {scope}: {:.1} s", started.elapsed().as_secs_f64());
        validate_execution(&result.evidence, false).unwrap();
        let exported = parse(&std::fs::read(golden_dir.join(format!("{scope}.safetensors"))).unwrap()).unwrap();
        compare(scope, &golden["scopes"][scope], &result, &exported, 0.9);
    }
}
