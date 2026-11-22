//! The window loop against the unchanged Python `window_training.compute` on a real, locally held release.
//!
//! Study data stays out of Git and out of CI: the golden is written by `evaluation/generate_window_golden.py` into an
//! ignored directory, and this test runs only when `PRIVOKE_WINDOW_GOLDEN` names it (it is skipped otherwise, so the
//! workspace stays green). `PRIVOKE_WINDOW_RELEASE` names the release directory (default
//! `/data/models/task_query_window_20261012/releases/host-v2/v1/42`, where the Docker command mounts it).
//!
//! Three comparisons, in the stage 19 categories:
//! 1. the release loads under its pins, and the schedule is Python's;
//! 2. the replay of Python's own 64 directions (float32, as recorded) through the Rust Adam recurrence, checkpoint scoring
//!    and selection: fingerprints, gradient and moment identities, clipped counts and the delta are bitwise Python's, the
//!    checkpoint counts and predictions are Python's, losses are within 1e-5 relative;
//! 3. the first Rust directions (base state) against Python's, and the whole loop with Rust gradients (tolerance category):
//!    the selected step and the outcome must agree, and the divergence of the trajectory is reported.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::net::TinyNet;
use privoke_training::window::{Directions, Release, Window, compute_directions, run, schedule};
use serde_json::Value;

type Values = BTreeMap<String, Vec<f64>>;

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn floats(bytes: &[u8]) -> Vec<f32> {
    let (chunks, _) = bytes.as_chunks::<4>();
    chunks.iter().map(|chunk| f32::from_le_bytes(*chunk)).collect()
}

fn split(values: &[f32], names: &[String], sizes: &[usize]) -> Values {
    let mut offset = 0;
    let mut out = Values::new();
    for (name, size) in names.iter().zip(sizes) {
        out.insert(name.clone(), values[offset..offset + size].iter().map(|v| f64::from(*v)).collect());
        offset += size;
    }
    out
}

fn relative(a: f64, b: f64) -> f64 {
    (a - b).abs() / b.abs().max(1.0)
}

#[test]
fn the_window_loop_matches_python_on_the_real_release() {
    let Some(golden) = std::env::var_os("PRIVOKE_WINDOW_GOLDEN").map(PathBuf::from) else {
        eprintln!("window release parity skipped: PRIVOKE_WINDOW_GOLDEN is not set");
        return;
    };
    let release_dir = std::env::var_os("PRIVOKE_WINDOW_RELEASE")
        .map_or_else(|| PathBuf::from("/data/models/task_query_window_20261012/releases/host-v2/v1/42"), PathBuf::from);
    let meta: Value = serde_json::from_slice(&read(&golden.join("meta.json"))).unwrap();
    let python_trace: Value = serde_json::from_slice(&read(&golden.join("trace.json"))).unwrap();
    let names: Vec<String> = meta["names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect();
    let sizes: Vec<usize> = meta["sizes"].as_array().unwrap().iter().map(|n| usize::try_from(n.as_u64().unwrap()).unwrap()).collect();
    let pins = &meta["pins"];
    let pin = |key: &str| pins[key].as_str().unwrap().to_string();

    // 1. The release under its pins, and the schedule.
    let (bank, references, manifest, teacher, window_bytes) = (
        read(&release_dir.join("bank.json")),
        read(&release_dir.join("references-v2.json")),
        read(&release_dir.join("component-manifest-v2.json")),
        read(&release_dir.join("original.json")),
        read(&release_dir.join("window.json")),
    );
    let window = Window::parse(&window_bytes, &pin("window")).expect("the window validates under its pin");
    let release =
        Release::load(&bank, &references, &manifest, &teacher, &pin("manifest"), &pin("teacher")).expect("the component release validates");
    let python_schedule: Vec<usize> =
        meta["schedule"].as_array().unwrap().iter().map(|n| usize::try_from(n.as_u64().unwrap()).unwrap()).collect();
    assert_eq!(schedule(&window.seed), python_schedule, "the block schedule");
    assert_eq!(release.references.len(), usize::try_from(meta["references"].as_u64().unwrap()).unwrap(), "the eligible references");
    eprintln!(
        "window release: {} window rows in 8 blocks, {} guard rows, {} eligible ORIGINAL references, schedule equal",
        window.rows().len(),
        window.guard.len(),
        release.references.len()
    );
    let artifact: Value = serde_json::from_slice(&teacher).unwrap();
    let total: usize = sizes.iter().sum();
    let directions = floats(&read(&golden.join("directions.f32")));
    assert_eq!(directions.len(), 128 * total, "the recorded directions");
    let recorded = |step: usize| -> (Values, Values) {
        let start = 2 * (step - 1) * total;
        (split(&directions[start..start + total], &names, &sizes), split(&directions[start + total..start + 2 * total], &names, &sizes))
    };
    let python_steps = python_trace["steps"].as_array().unwrap();

    // 2. Replay: Python's directions through the Rust recurrence, scoring and selection.
    let mut replay_step = 0;
    let replayed = run(&artifact, &window, &release, &mut |_| {
        replay_step += 1;
        let (main, auxiliary) = recorded(replay_step);
        let row = &python_steps[replay_step - 1];
        Ok(Directions {
            main,
            main_loss: row["main_loss"].as_f64().unwrap(),
            auxiliary,
            auxiliary_loss: row["auxiliary_loss"].as_f64().unwrap(),
        })
    })
    .expect("the replay runs");
    let rust_trace: Value = serde_json::from_str(&replayed.trace).unwrap();
    let (mut identical_steps, mut clipped_equal) = (0usize, 0usize);
    for (rust, python) in rust_trace["steps"].as_array().unwrap().iter().zip(python_steps) {
        let same = ["step", "block", "before", "after", "gradient", "moments", "delta"].iter().all(|key| rust[*key] == python[*key]);
        identical_steps += usize::from(same);
        clipped_equal += usize::from(rust["clipped"] == python["clipped"]);
    }
    eprintln!(
        "window replay: {identical_steps} of 64 steps with identical state fingerprints, gradient and moment identities and delta; clipped counts equal {clipped_equal} of 64"
    );
    let (mut counts_equal, mut predictions_equal, mut originals_equal, mut violations_equal, mut max_loss) =
        (0usize, 0usize, 0usize, 0usize, 0f64);
    let (mut fingerprints_equal, mut flipped_rows) = (0usize, 0usize);
    for (rust, python) in rust_trace["checkpoints"].as_array().unwrap().iter().zip(python_trace["checkpoints"].as_array().unwrap()) {
        counts_equal += usize::from(rust["counts"] == python["counts"]);
        predictions_equal += usize::from(rust["predictions"] == python["predictions"]);
        originals_equal += usize::from(rust["original_predictions"] == python["original_predictions"]);
        violations_equal +=
            usize::from(rust["violations"] == python["violations"] && rust["component_violations"] == python["component_violations"]);
        fingerprints_equal += usize::from(rust["fingerprint"] == python["fingerprint"]);
        max_loss = max_loss.max(relative(rust["loss"].as_f64().unwrap(), python["loss"].as_f64().unwrap()));
        let (a, b) = (rust["predictions"].as_array().unwrap(), python["predictions"].as_array().unwrap());
        flipped_rows += a.iter().zip(b).filter(|(x, y)| x[0] != y[0]).count();
    }
    eprintln!(
        "window checkpoints (9): fingerprints equal {fingerprints_equal}, counts equal {counts_equal}, window predictions equal {predictions_equal} ({flipped_rows} rows differ), ORIGINAL predictions equal {originals_equal}, violations equal {violations_equal}; max relative loss error {max_loss:.3e}"
    );
    let outcome_equal =
        (rust_trace["status"].clone(), rust_trace["reason"].clone(), rust_trace["selected_step"].clone(), rust_trace["selected"].clone())
            == (
                python_trace["status"].clone(),
                python_trace["reason"].clone(),
                python_trace["selected_step"].clone(),
                python_trace["selected"].clone(),
            );
    let terminal_equal = rust_trace["terminal"] == python_trace["terminal"] && rust_trace["published"] == python_trace["published"];
    eprintln!(
        "window replay outcome: {}/{} at step {} (Python {}/{} at step {}); outcome, selected and published fingerprints equal: {}; terminal equal: {terminal_equal}",
        replayed.status,
        replayed.reason,
        replayed.selected_step,
        python_trace["status"],
        python_trace["reason"],
        python_trace["selected_step"],
        outcome_equal
    );
    assert_eq!(identical_steps, 64, "the Adam recurrence replays bitwise");
    assert_eq!(clipped_equal, 64);
    assert_eq!(counts_equal, 9, "checkpoint counts");
    assert_eq!(violations_equal, 9, "ORIGINAL component violations");
    assert!(outcome_equal && terminal_equal, "selection outcome");
    assert!(max_loss <= 1e-5, "checkpoint losses within 1e-5 relative");
    for key in ["window_sha256", "references_sha256", "base", "weights", "main", "auxiliary", "work", "config"] {
        assert_eq!(rust_trace[key], python_trace[key], "trace field {key}");
    }
    let summary: Value = serde_json::from_str(&replayed.summary).unwrap();
    let python_summary: Value = serde_json::from_str(meta["summary"].as_str().unwrap()).unwrap();
    for key in python_summary.as_object().unwrap().keys().filter(|key| *key != "trace_sha256") {
        assert_eq!(summary[key], python_summary[key], "summary field {key}");
    }
    let exact = |outcome: &privoke_training::window::Outcome| outcome.metrics["candidate_train_exact_match_rate"];
    let python_metrics = &meta["metrics"];
    assert!((exact(&replayed) - python_metrics["candidate_train_exact_match_rate"].as_f64().unwrap()).abs() < 1e-12);
    let gradients = floats(&read(&golden.join("gradients.f32")));
    let rust_gradients: Vec<f32> = replayed.gradients.values().flatten().copied().collect();
    assert_eq!(rust_gradients.len(), gradients.len(), "the transported update");
    assert!(rust_gradients.iter().zip(&gradients).all(|(a, b)| a.to_bits() == b.to_bits()), "the transported update is bitwise Python's");
    eprintln!("window replay: transported update {} coordinates, all bitwise equal (a no_update run transports none)", gradients.len());

    // 3. Rust gradients: the first directions against Python's, then the whole loop.
    let net = TinyNet::from_artifact(&artifact).unwrap();
    let examples: Vec<_> = window.rows().into_iter().map(|row| privoke_training::window::example_of(row).unwrap()).collect();
    let balanced = privoke_training::objective::class_balanced(&examples).unwrap();
    let denominator = privoke_training::objective::fsum(balanced.iter().map(|e| e.weight)) / 8.0;
    let first = compute_directions(&privoke_training::window::Step {
        index: 1,
        block: python_schedule[0],
        net: &net,
        rows: &balanced[python_schedule[0] * 64..(python_schedule[0] + 1) * 64],
        denominator,
        references: &release.references,
    })
    .unwrap();
    let (python_main, python_aux) = recorded(1);
    for (label, rust, python) in [("main", &first.main, &python_main), ("component hinge", &first.auxiliary, &python_aux)] {
        let (mut n, mut within, mut bitwise, mut max_error) = (0usize, 0usize, 0usize, 0f64);
        for (name, values) in python {
            for (r, p) in rust[name].iter().zip(values) {
                n += 1;
                let error = (*r as f32 - *p as f32).abs();
                within += usize::from(f64::from(error) <= 1e-6 * p.abs().max(1.0));
                bitwise += usize::from((*r as f32).to_bits() == (*p as f32).to_bits());
                max_error = max_error.max(relative(*r, *p));
            }
        }
        eprintln!(
            "window first direction ({label}): {n} coordinates, {within} within 1e-6 (relative to max(1, |v|)), {bitwise} bitwise equal, max relative error {max_error:.3e}"
        );
        assert!(max_error <= 1e-4, "{label} direction at the base state");
    }
    eprintln!(
        "window first losses: main {:.6} (Python {:.6}), component hinge {:.3e} (Python {:.3e})",
        first.main_loss,
        python_steps[0]["main_loss"].as_f64().unwrap(),
        first.auxiliary_loss,
        python_steps[0]["auxiliary_loss"].as_f64().unwrap()
    );
    let full = run(&artifact, &window, &release, &mut compute_directions).expect("the Rust loop runs");
    let full_trace: Value = serde_json::from_str(&full.trace).unwrap();
    let equal_counts = full_trace["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .zip(python_trace["checkpoints"].as_array().unwrap())
        .filter(|(a, b)| a["counts"] == b["counts"])
        .count();
    let equal_steps = full_trace["steps"].as_array().unwrap().iter().zip(python_steps).filter(|(a, b)| a["after"] == b["after"]).count();
    eprintln!(
        "window Rust loop (tolerance category): {}/{} at step {} (Python {}/{} at step {}); checkpoints with Python's counts {equal_counts} of 9; steps with Python's exact state {equal_steps} of 64; violations per checkpoint {:?}",
        full.status,
        full.reason,
        full.selected_step,
        python_trace["status"],
        python_trace["reason"],
        python_trace["selected_step"],
        full.checkpoints.iter().map(|c| c.violations).collect::<Vec<_>>()
    );
    assert_eq!((full.status, full.selected_step), (replayed.status, replayed.selected_step), "the selection of the Rust loop");
}
