//! Per-call parity of `privoke_curriculum::pyrandom` with CPython's `random`.
//!
//! `tests/golden/pyrandom.json` holds, for every seed and method, the SHA-256 of the little-endian stream of one
//! million draws, written by `evaluation/generate_curriculum_golden.py random`. Every stream here is produced by
//! the Rust method and hashed the same way, so one wrong draw anywhere in a million fails the digest.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use privoke_contracts::digest::sha256_hex;
use privoke_curriculum::pyrandom::Random;

const DRAWS: usize = 1_000_000;

fn golden() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/pyrandom.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn u64_stream(mut draw: impl FnMut() -> u64) -> String {
    let mut bytes = Vec::with_capacity(DRAWS * 8);
    for _ in 0..DRAWS {
        bytes.extend_from_slice(&draw().to_le_bytes());
    }
    sha256_hex(&bytes)
}

fn i64_stream(mut draw: impl FnMut() -> i64) -> String {
    let mut bytes = Vec::with_capacity(DRAWS * 8);
    for _ in 0..DRAWS {
        bytes.extend_from_slice(&draw().to_le_bytes());
    }
    sha256_hex(&bytes)
}

fn f64_stream(mut draw: impl FnMut() -> f64) -> String {
    let mut bytes = Vec::with_capacity(DRAWS * 8);
    for _ in 0..DRAWS {
        bytes.extend_from_slice(&draw().to_le_bytes());
    }
    sha256_hex(&bytes)
}

fn u32_hash(values: &[u32]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    sha256_hex(&bytes)
}

fn suffix_numbers(method: &str, prefix: &str) -> Vec<String> {
    method.strip_prefix(prefix).unwrap().split('_').map(str::to_string).collect()
}

fn run(seed: u64, method: &str) -> String {
    let mut rng = Random::new(seed);
    let cumulative = [1.0, 3.0, 6.5, 6.75, 16.75];
    if method == "random" {
        return f64_stream(|| rng.random());
    }
    if let Some(bits) = method.strip_prefix("getrandbits_") {
        let bits: u32 = bits.parse().unwrap();
        return u64_stream(|| rng.getrandbits(bits).unwrap());
    }
    if let Some(n) = method.strip_prefix("randbelow_") {
        let n: u64 = n.parse().unwrap();
        return u64_stream(|| rng.randbelow(n));
    }
    if let Some(length) = method.strip_prefix("choice_") {
        let items: Vec<u64> = (0..length.parse::<u64>().unwrap()).collect();
        return u64_stream(|| *rng.choice(&items).unwrap());
    }
    if let Some(length) = method.strip_prefix("shuffle_") {
        let length: usize = length.parse().unwrap();
        let mut items: Vec<u32> = (0..length as u32).collect();
        let mut out = Vec::new();
        for _ in 0..DRAWS / (length - 1) {
            rng.shuffle(&mut items);
            out.extend_from_slice(&items);
        }
        return u32_hash(&out);
    }
    if method.starts_with("sample_") {
        let parts = suffix_numbers(method, "sample_");
        let (n, k): (usize, usize) = (parts[0].parse().unwrap(), parts[1].parse().unwrap());
        let population: Vec<u32> = (0..n as u32).collect();
        let mut out = Vec::new();
        for _ in 0..DRAWS / k {
            out.extend(rng.sample(&population, k).unwrap());
        }
        return u32_hash(&out);
    }
    match method {
        "randrange_10" => i64_stream(|| rng.randrange_stop(10).unwrap()),
        "randrange_5_1000003" => i64_stream(|| rng.randrange(5, 1_000_003, 1).unwrap()),
        "randrange_m50_50_7" => i64_stream(|| rng.randrange(-50, 50, 7).unwrap()),
        "randrange_100_m100_m9" => i64_stream(|| rng.randrange(100, -100, -9).unwrap()),
        "randint_m3_3" => i64_stream(|| rng.randint(-3, 3).unwrap()),
        "uniform_0_1" => f64_stream(|| rng.uniform(0.0, 1.0)),
        "uniform_m3.5_7.25" => f64_stream(|| rng.uniform(-3.5, 7.25)),
        "choices_cum_5_k10" => {
            let mut out = Vec::new();
            for _ in 0..DRAWS / 10 {
                out.extend(rng.choices_cumulative(&cumulative, 10).unwrap().into_iter().map(|index| index as u32));
            }
            u32_hash(&out)
        }
        "choices_weights_5_k1" => {
            let mut out = Vec::new();
            for _ in 0..DRAWS {
                out.extend(rng.choices_weighted(&[1.0, 2.0, 3.5, 0.25, 10.0], 1).unwrap().into_iter().map(|index| index as u32));
            }
            u32_hash(&out)
        }
        "choices_uniform_17_k4" => {
            let mut out = Vec::new();
            for _ in 0..DRAWS / 4 {
                out.extend(rng.choices_uniform(17, 4).into_iter().map(|index| index as u32));
            }
            u32_hash(&out)
        }
        other => panic!("unknown golden method {other}"),
    }
}

#[test]
fn every_method_reproduces_cpython_for_a_million_draws() {
    let golden = golden();
    let entries = golden["entries"].as_array().unwrap();
    assert_eq!(golden["draws_per_method"].as_u64().unwrap() as usize, DRAWS);
    let mut checked = BTreeSet::new();
    for entry in entries {
        let seed = entry["seed"].as_u64().unwrap();
        let method = entry["method"].as_str().unwrap();
        let expected = entry["sha256"].as_str().unwrap();
        assert_eq!(run(seed, method), expected, "seed {seed} method {method}");
        checked.insert(method.to_string());
    }
    // Every method family the curricula use is covered.
    for family in [
        "random",
        "getrandbits_64",
        "randbelow_3",
        "choice_5",
        "shuffle_100",
        "sample_1000_20",
        "randrange_10",
        "uniform_0_1",
        "choices_cum_5_k10",
    ] {
        assert!(checked.contains(family), "{family} missing from the golden file");
    }
    assert_eq!(entries.len(), 4 * 36);
}

#[test]
fn string_and_bytes_seeds_use_version_two_seeding() {
    let golden = golden();
    let entries = golden["string_seeds"].as_array().unwrap();
    assert_eq!(entries.len(), 10);
    for entry in entries {
        let seed = entry["seed"].as_str().unwrap();
        let mut rng = if entry["kind"].as_str().unwrap() == "str" { Random::from_text(seed) } else { Random::from_bytes(seed.as_bytes()) };
        let draws = entry["draws"].as_u64().unwrap() as usize;
        let mut bytes = Vec::with_capacity(draws * 8);
        for _ in 0..draws {
            bytes.extend_from_slice(&rng.random().to_le_bytes());
        }
        assert_eq!(sha256_hex(&bytes), entry["sha256"].as_str().unwrap(), "seed {seed:?} kind {}", entry["kind"]);
    }
}

#[test]
fn a_negative_seed_uses_its_absolute_value() {
    let mut negative = Random::from_signed(-17);
    let mut positive = Random::new(17);
    for _ in 0..1000 {
        assert_eq!(negative.next_u32(), positive.next_u32());
    }
}

#[test]
fn refuses_what_cpython_refuses() {
    let mut rng = Random::new(1);
    assert!(rng.choice::<u8>(&[]).is_err());
    assert!(rng.sample(&[1, 2, 3], 4).is_err());
    assert!(rng.randrange(5, 5, 1).is_err());
    assert!(rng.randrange(0, 10, 0).is_err());
    assert!(rng.choices_cumulative(&[0.0], 1).is_err());
    assert!(rng.choices_cumulative(&[], 1).is_err());
}
