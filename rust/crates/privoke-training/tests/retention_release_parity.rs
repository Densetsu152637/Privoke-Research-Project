//! The retention loops against the unchanged Python route on the real balanced release held locally.
//!
//! Study data stays out of Git and CI: the golden is written by `evaluation/generate_retention_golden.py` into an ignored
//! directory and this test runs only when `PRIVOKE_RETENTION_GOLDEN` names it (skipped otherwise, so the workspace stays
//! green). `PRIVOKE_RETENTION_RELEASE` names the run directory `evaluation/results/iterative_fuzzer_20261011` (default
//! `/data/retention`), which holds the bank, the real balanced references and manifest and the ORIGINAL teacher.
//!
//! For each policy (gate and hinge): (1) the release loads under its pins; (2) the replay of Python's 64 recorded directions
//! through the Rust recurrence, audit and trace: the Adam steps are bitwise Python's, the safety rows, summary, metrics,
//! executions and transported update are Python's (floats within 1e-5 relative); (3) the first Rust directions against
//! Python's and the whole Rust loop (tolerance category). At the base state the hinge sits exactly on its kink (the references
//! were made from the same model), so the hinge direction there is reported, not asserted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_training::objective::Example;
use privoke_training::retention::{Auxiliary, Directions, HingeDiagnostics, Release, compute_directions, run};
use privoke_training::window::{Row, example_of};
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

fn rows(values: &Value) -> Vec<Example> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let frozen = Row {
                text: row["text"].as_str().unwrap().to_string(),
                packed: u16::try_from(row["packed"].as_u64().unwrap()).unwrap(),
                weight: row["weight"].as_f64().unwrap(),
                id: String::new(),
                group: String::new(),
                taxonomy: true,
            };
            example_of(&frozen).unwrap()
        })
        .collect()
}

fn compare_directions(label: &str, step: usize, rust: &Values, python: &Values) -> f64 {
    let (mut n, mut within, mut bitwise, mut max_error) = (0usize, 0usize, 0usize, 0f64);
    let mut tensors: Vec<(f64, String)> = Vec::new();
    for (name, values) in python {
        let mut worst = 0f64;
        for (r, p) in rust[name].iter().zip(values) {
            n += 1;
            let error = relative(*r, *p);
            within += usize::from(error <= 1e-6);
            bitwise += usize::from((*r as f32).to_bits() == (*p as f32).to_bits());
            worst = worst.max(error);
        }
        max_error = max_error.max(worst);
        tensors.push((worst, name.clone()));
    }
    tensors.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let worst: Vec<String> = tensors.iter().take(3).map(|(error, name)| format!("{name} max {error:.3e}")).collect();
    eprintln!(
        "retention direction at step {step} ({label}): {n} coordinates, {within} within 1e-6 (relative to max(1, |v|)), {bitwise} bitwise equal, max relative error {max_error:.3e}; worst tensors: {}",
        worst.join("; ")
    );
    max_error
}

/// Structural comparison of two trace records: integers, booleans, nulls and text exactly, floats within 1e-5 relative,
/// 64-digit fingerprints that hash computed values counted.
fn close(path: &str, got: &Value, want: &Value, hashes: &mut (usize, usize)) -> Result<(), String> {
    match (got, want) {
        (Value::Number(a), Value::Number(b)) => {
            if a.is_i64() != b.is_i64() {
                return Err(format!("{path}: {a} against {b} (an integer against a float)"));
            }
            if a.is_i64() {
                return if a == b { Ok(()) } else { Err(format!("{path}: {a} against {b}")) };
            }
            let (x, y) = (a.as_f64().unwrap(), b.as_f64().unwrap());
            if relative(x, y) <= 1e-5 { Ok(()) } else { Err(format!("{path}: {x} against {y}")) }
        }
        (Value::String(a), Value::String(b)) if a.len() == 64 && b.len() == 64 && a.bytes().all(|c| c.is_ascii_hexdigit()) => {
            hashes.0 += 1;
            hashes.1 += usize::from(a == b);
            Ok(())
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Err(format!("{path}: {} items against {}", a.len(), b.len()));
            }
            a.iter().zip(b).enumerate().try_for_each(|(index, (x, y))| close(&format!("{path}[{index}]"), x, y, hashes))
        }
        (Value::Object(a), Value::Object(b)) => {
            if a.keys().ne(b.keys()) {
                return Err(format!("{path}: keys {:?} against {:?}", a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>()));
            }
            a.iter().try_for_each(|(key, x)| close(&format!("{path}.{key}"), x, &b[key], hashes))
        }
        _ if got == want => Ok(()),
        _ => Err(format!("{path}: {got} against {want}")),
    }
}

#[test]
fn the_retention_loops_match_python_on_the_real_release() {
    let Some(golden) = std::env::var_os("PRIVOKE_RETENTION_GOLDEN").map(PathBuf::from) else {
        eprintln!("retention release parity skipped: PRIVOKE_RETENTION_GOLDEN is not set");
        return;
    };
    let root = std::env::var_os("PRIVOKE_RETENTION_RELEASE").map_or_else(|| PathBuf::from("/data/retention"), PathBuf::from);
    let references_dir = root.join("sensitive-retention-pilot/execution/references/balanced");
    let (bank, references, manifest, teacher) = (
        read(&root.join("train-sensitive-retention/approved-train-bank.json")),
        read(&references_dir.join("references.json")),
        read(&references_dir.join("manifest.json")),
        read(&root.join("block01/balanced/catalog/privoke-balanced.json")),
    );
    let artifact: Value = serde_json::from_slice(&teacher).unwrap();
    let request: Value = serde_json::from_slice(&read(&golden.join("rows.json"))).unwrap();
    let (main, guard) = (rows(&request["main"]), rows(&request["guard"]));
    let mut failures: Vec<String> = Vec::new();
    for (directory, policy) in
        [("gate", "full_projected_adam64_original_train_gate_v1"), ("hinge", "full_projected_adam64_original_train_hinge_v1")]
    {
        // One policy's failed assertion must not hide the other: each runs under its own unwind guard.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let dir = golden.join(directory);
            let meta: Value = serde_json::from_slice(&read(&dir.join("meta.json"))).unwrap();
            let python_trace: Value = serde_json::from_slice(&read(&dir.join("trace.json"))).unwrap();
            let pin = meta["pin"].as_str().unwrap().to_string();
            let release = Release::load(&bank, &references, &manifest, &teacher, &pin).expect("the retention release validates");
            eprintln!("retention {directory}: release loads, {} eligible ORIGINAL rows, manifest {pin}", release.references.len());
            let names: Vec<String> = meta["names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect();
            let sizes: Vec<usize> =
                meta["sizes"].as_array().unwrap().iter().map(|n| usize::try_from(n.as_u64().unwrap()).unwrap()).collect();
            let total: usize = sizes.iter().sum();
            let hinge = directory == "hinge";
            let per_step = if hinge { 2 } else { 1 };
            let directions = floats(&read(&dir.join("directions.f32")));
            assert_eq!(directions.len(), 64 * per_step * total, "the recorded directions");
            let recorded = |step: usize| -> (Values, Option<Values>) {
                let start = per_step * (step - 1) * total;
                let main = split(&directions[start..start + total], &names, &sizes);
                (main, hinge.then(|| split(&directions[start + total..start + 2 * total], &names, &sizes)))
            };
            let adam_steps = python_trace["adam"]["steps"].as_array().unwrap();
            let aux_steps = python_trace["auxiliary"]["steps"].as_array().unwrap();

            // Replay: Python's directions through the Rust recurrence, audit and trace.
            let mut step_no = 0;
            let replayed = run(&artifact, &release, policy, &main, &guard, &mut |step| {
                step_no += 1;
                let (main_direction, auxiliary) = recorded(step_no);
                if [1, 2, 3, 8, 16, 32, 64].contains(&step_no) {
                    let computed = compute_directions(step)?;
                    let error = compare_directions("main", step_no, &computed.main, &main_direction);
                    if error > 1e-5 {
                        failures.push(format!("{directory}: main direction at step {step_no}: relative error {error:.3e}"));
                    }
                    if let (Some(rust), Some(python)) = (&computed.auxiliary, &auxiliary) {
                        let error = compare_directions("hinge", step_no, &rust.direction, python);
                        if step_no > 1 && error > 1e-4 {
                            failures.push(format!("{directory}: hinge direction at step {step_no}: relative error {error:.3e}"));
                        }
                    }
                }
                let (main_loss, auxiliary) = match auxiliary {
                    Some(direction) => {
                        let row = &aux_steps[step_no - 1];
                        let parity = row["original_state_parity_scaled_error"].as_f64().unwrap_or(0.0);
                        (
                            row["main_loss"].as_f64().unwrap(),
                            Some(Auxiliary {
                                direction,
                                loss: row["auxiliary_loss"].as_f64().unwrap(),
                                diagnostics: HingeDiagnostics {
                                    active_rows: usize::try_from(row["active_rows"].as_u64().unwrap()).unwrap(),
                                    maximum_hinge: row["maximum_hinge"].as_f64().unwrap(),
                                    maximum_scaled_original_difference: parity,
                                },
                            }),
                        )
                    }
                    None => (adam_steps[step_no - 1]["loss"].as_f64().unwrap(), None),
                };
                Ok(Directions { main: main_direction, main_loss, auxiliary })
            })
            .expect("the replay runs");
            let rust_trace: Value = serde_json::from_str(&replayed.trace).unwrap();
            let identical = rust_trace["adam"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .zip(adam_steps)
                .enumerate()
                .filter(|(index, (rust, python))| {
                    let differing: Vec<&str> = ["step", "before", "after", "loss", "gradient", "moments", "delta", "clipped"]
                        .into_iter()
                        .filter(|key| rust[*key] != python[*key])
                        .collect();
                    for key in &differing {
                        eprintln!(
                            "retention {directory}: step {} field {key} differs: Rust {} against Python {}",
                            index + 1,
                            rust[*key],
                            python[*key]
                        );
                    }
                    differing.is_empty()
                })
                .count();
            let adam_equal = ["schema", "policy", "config", "base", "final", "delta", "counts", "train"]
                .iter()
                .all(|key| rust_trace["adam"][*key] == python_trace["adam"][*key]);
            eprintln!(
                "retention {directory} replay: {identical} of 64 Adam steps identical (fingerprints, loss, gradient and moment identities, delta, clipped); adam header equal: {adam_equal}"
            );
            let mut hashes = (0usize, 0usize);
            for key in ["safety", "base_safety", "auxiliary"] {
                if let Err(reason) = close(&format!("$.{key}"), &rust_trace[key], &python_trace[key], &mut hashes) {
                    failures.push(format!("{directory}: trace {key}: {reason}"));
                }
            }
            let flags = |trace: &Value, key: &str| -> Vec<bool> {
                trace[key].as_array().unwrap().iter().map(|row| row["violation"].as_bool().unwrap()).collect()
            };
            let (violations_equal, base_violations_equal) = (
                flags(&rust_trace, "safety") == flags(&python_trace, "safety"),
                flags(&rust_trace, "base_safety") == flags(&python_trace, "base_safety"),
            );
            eprintln!(
                "retention {directory} audit: {} eligible rows, violations equal {violations_equal}, base violations equal {base_violations_equal}",
                release.references.len()
            );
            assert_eq!(identical, 64, "the Adam recurrence replays bitwise");
            assert!(adam_equal && violations_equal && base_violations_equal);
            for key in ["schema", "policy", "manifest_sha256"] {
                assert_eq!(rust_trace[key], python_trace[key], "trace field {key}");
            }
            let python_metadata = meta["metadata"].as_object().unwrap();
            let worker_keys = ["artifact_checksum", "architecture", "model_config", "model_cache_key"];
            let mut rust_keys: Vec<&str> = replayed.metadata.keys().map(String::as_str).collect();
            rust_keys.sort_unstable();
            let mut wanted: Vec<&str> = python_metadata.keys().map(String::as_str).filter(|key| !worker_keys.contains(key)).collect();
            // The golden's metadata leaves the retained trace out (it is compared above as a trace).
            wanted.push("original_train_retention_trace_v1");
            wanted.sort_unstable();
            assert_eq!(rust_keys, wanted, "the metadata keys the loop writes");
            for (key, value) in &replayed.metadata {
                let want = python_metadata[key].as_str().unwrap();
                if key == "original_train_retention_summary_v1" {
                    let (a, b): (Value, Value) = (serde_json::from_str(value).unwrap(), serde_json::from_str(want).unwrap());
                    for field in b.as_object().unwrap().keys().filter(|field| *field != "trace_sha256") {
                        assert_eq!(a[field], b[field], "summary field {field}");
                    }
                } else {
                    assert_eq!(value, want, "metadata {key}");
                }
            }
            let python_metrics = meta["metrics"].as_object().unwrap();
            assert_eq!(replayed.metrics.keys().collect::<Vec<_>>(), python_metrics.keys().collect::<Vec<_>>(), "metric names");
            for (key, expected) in python_metrics {
                let (got, want) = (replayed.metrics[key], expected.as_f64().unwrap());
                assert!(relative(got, want) <= 1e-5, "metric {key}: {got} against {want}");
            }
            let python_executions: Vec<(String, usize)> = meta["executions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (e[0].as_str().unwrap().to_string(), usize::try_from(e[1].as_u64().unwrap()).unwrap()))
                .collect();
            assert_eq!(replayed.executions, python_executions, "the executed phases");
            let python_gradients = floats(&read(&dir.join("gradients.f32")));
            let rust_gradients: Vec<f32> = replayed.gradients.values().flatten().copied().collect();
            assert_eq!(rust_gradients.len(), python_gradients.len());
            assert!(
                rust_gradients.iter().zip(&python_gradients).all(|(a, b)| a.to_bits() == b.to_bits()),
                "the transported update is bitwise Python's"
            );
            eprintln!(
                "retention {directory} replay: {} metrics within 1e-5, {} executions, transported update {} coordinates bitwise equal, {} of {} trace fingerprints equal",
                python_metrics.len(),
                python_executions.len(),
                python_gradients.len(),
                hashes.1,
                hashes.0
            );

            // The Rust gradients drive the loop (tolerance category).
            let full = run(&artifact, &release, policy, &main, &guard, &mut compute_directions).expect("the Rust loop runs");
            let delta_error =
                full.gradients.values().flatten().zip(&python_gradients).map(|(a, b)| f64::from((a - b).abs())).fold(0f64, f64::max);
            let full_trace: Value = serde_json::from_str(&full.trace).unwrap();
            let rust_violations = flags(&full_trace, "safety").iter().filter(|v| **v).count();
            let python_violations = flags(&python_trace, "safety").iter().filter(|v| **v).count();
            eprintln!(
                "retention {directory} Rust loop (tolerance category): max transported-update difference {delta_error:.3e}; candidate exact {:.4} (Python {:.4}); candidate loss {:.4} (Python {:.4}); violations {rust_violations} (Python {python_violations})",
                full.metrics["candidate_train_exact_match_rate"],
                python_metrics["candidate_train_exact_match_rate"].as_f64().unwrap(),
                full.metrics["candidate_train_objective_loss"],
                python_metrics["candidate_train_objective_loss"].as_f64().unwrap()
            );
            if !hinge && delta_error > 1e-5 {
                failures.push(format!("{directory}: the Rust loop's transported update differs from Python's by {delta_error:.3e}"));
            }
        }));
        if outcome.is_err() {
            failures.push(format!("{directory}: an assertion failed (the message is above)"));
        }
    }
    assert!(failures.is_empty(), "comparisons: {failures:?}");
}
