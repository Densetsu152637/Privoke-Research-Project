//! Binds the finite-epsilon audit record to the Rust kernel's actual binary64 thresholds.
//!
//! `paper/research/rust-telemetry-epsilon-audit-20261117.json` (made by `evaluation/audit_rust_telemetry_epsilon.py`)
//! lists, for every audited event epsilon and dimension, the threshold bits the audit's exact arithmetic starts from.
//! This test recomputes every one of them with the crate's own `grr_kernel`, compares the bits, recomputes the number
//! `m` of 53-bit draws that answer truthfully, and then drives the real sampler (`generalized_randomized_response`)
//! at `J = 0`, `m - 1`, `m`, `m + 1` and `2^53 - 1`. The audit therefore describes this build's thresholds and decision
//! rule on every platform where the test passes; on a platform where it fails, the record does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use privoke_telemetry_client::{DIMENSIONS, ReplayRandom, domain, generalized_randomized_response, grr_kernel};
use serde_json::Value;

const GRID: u64 = 1 << 53;

fn record() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../paper/research/rust-telemetry-epsilon-audit-20261117.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("the audit record {} is missing: {error}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn float(bits: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(bits.as_str().unwrap(), 16).unwrap())
}

#[test]
fn the_audit_record_lists_the_dimensions_in_the_crates_order() {
    let record = record();
    let rows = record["event_epsilons"].as_array().unwrap();
    assert!(rows.len() >= 5);
    for row in rows {
        let names: Vec<&str> = row["coordinates"].as_array().unwrap().iter().map(|item| item["dimension"].as_str().unwrap()).collect();
        assert_eq!(names, DIMENSIONS.to_vec());
    }
}

#[test]
fn recomputed_thresholds_equal_the_audited_bits() {
    let record = record();
    let mut checked = 0;
    for row in record["event_epsilons"].as_array().unwrap() {
        let event = float(&row["event_epsilon_bits"]);
        for coordinate in row["coordinates"].as_array().unwrap() {
            let dimension = coordinate["dimension"].as_str().unwrap();
            let size = coordinate["domain_size"].as_u64().unwrap() as usize;
            assert_eq!(domain(dimension).unwrap().len(), size, "{dimension}");
            let epsilon = event / DIMENSIONS.len() as f64;
            assert_eq!(epsilon.to_bits(), float(&coordinate["per_dimension_epsilon_bits"]).to_bits(), "{dimension} at {event}");
            let kernel = grr_kernel(size, epsilon).unwrap();
            assert_eq!(
                kernel.truthful.to_bits(),
                float(&coordinate["truthful_bits"]).to_bits(),
                "truthful threshold of {dimension} at event epsilon {event}: {:?} against audited {}",
                kernel.truthful,
                coordinate["truthful_repr"]
            );
            assert_eq!(kernel.other.to_bits(), float(&coordinate["other_bits"]).to_bits(), "other probability of {dimension} at {event}");
            checked += 1;
        }
    }
    assert!(checked >= 25, "{checked} cells");
}

#[test]
fn the_sampler_flips_exactly_at_the_audited_grid_point() {
    let record = record();
    for row in record["event_epsilons"].as_array().unwrap() {
        let event = float(&row["event_epsilon_bits"]);
        for coordinate in row["coordinates"].as_array().unwrap() {
            let dimension = coordinate["dimension"].as_str().unwrap();
            let choices = domain(dimension).unwrap();
            let epsilon = event / DIMENSIONS.len() as f64;
            let kernel = grr_kernel(choices.len(), epsilon).unwrap();
            // m = ceil(p * 2^53); the scaling by a power of two is exact, so this is the exact integer.
            let m = (kernel.truthful * GRID as f64).ceil() as u64;
            assert_eq!(m.to_string(), coordinate["grid_points_below_threshold"].as_str().unwrap(), "{dimension} at {event}");
            assert!(0 < m && m < GRID);
            for (draw, truthful) in [(0, true), (m - 1, true), (m, false), (m + 1, false), (GRID - 1, false)] {
                // Seven bytes, big endian: the draw in the high 53 bits and noise in the dropped low three bits.
                let word = (draw << 3) | 0b101;
                let mut data = word.to_be_bytes()[1..].to_vec();
                // One more byte for the choice among the others: 0 is always below the bound and picks the first.
                data.push(0);
                let mut random = ReplayRandom::new(data);
                let value = choices[0];
                let output = generalized_randomized_response(value, choices, epsilon, &mut random).unwrap();
                if truthful {
                    assert_eq!(output, value, "J = {draw} must answer truthfully ({dimension} at {event}, m = {m})");
                    assert_eq!(random.remaining(), 1);
                } else {
                    assert_eq!(output, choices[1], "J = {draw} must not answer truthfully ({dimension} at {event}, m = {m})");
                    assert_eq!(random.remaining(), 0);
                }
            }
        }
    }
}
