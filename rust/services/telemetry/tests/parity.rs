//! Parity with the Python service under the G5 telemetry rule: integer counts and stored marginals are exact, and
//! floating-point estimator outputs agree within 4 ULP.
//!
//! Three oracles are replayed:
//! * the stage 0 corpus `tests/conformance/telemetry.json` (195 packets through the handlers, stored marginals, the
//!   summary with its serialised hash, the empty summary and health);
//! * the telemetry-audit fixtures in `tests/fixtures/estimator_oracle.json`, produced by running the Python
//!   `TelemetryStore` over the packets of `evaluation/analysis/audit-telemetry-mechanism.py` (`store_parity`, 26
//!   estimates) and over 400 further epsilon strata that stress `exp`;
//! * a database the Python store wrote, which this service must open and extend (`python_written.sqlite3`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{fixture, repo_root, temp_store};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::proto::v1::telemetry_service_server::TelemetryService;
use privoke_contracts::proto::v1::{GetTelemetrySummaryRequest, GetTelemetrySummaryResponse, TelemetryHealthRequest, TelemetryPacket};
use privoke_telemetry::daily::DailyCap;
use privoke_telemetry::service::TelemetryCollector;
use privoke_telemetry::storage::{Summary, TelemetryStore};
use prost::Message;
use serde_json::Value;
use tonic::{Code, Request};

const TOLERANCE_ULPS: u64 = 4;

fn json(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn ulps(left: f64, right: f64) -> u64 {
    if left == right {
        return 0;
    }
    // Both estimates are clipped to [0, n], so they are non-negative and the bit patterns order like the values.
    assert!(left >= 0.0 && right >= 0.0 && left.is_finite() && right.is_finite(), "{left} vs {right}");
    left.to_bits().abs_diff(right.to_bits())
}

fn bits(text: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(text, 16).unwrap())
}

fn collector(store: TelemetryStore) -> TelemetryCollector {
    TelemetryCollector::new(store, DailyCap::new(u32::MAX))
}

/// Compare a computed summary with the recorded one: exact sample and observed counts, estimates within tolerance.
/// Returns (values compared, worst ULP distance).
fn compare_summary(actual: &Summary, expected: &Value) -> (usize, u64) {
    assert_eq!(actual.sample_count, expected["sample_count"].as_u64().unwrap());
    let dimensions = expected["dimensions"].as_array().unwrap();
    assert_eq!(actual.dimensions.len(), dimensions.len());
    let (mut compared, mut worst) = (0, 0);
    for (actual, expected) in actual.dimensions.iter().zip(dimensions) {
        assert_eq!(actual.dimension, expected["dimension"].as_str().unwrap());
        let values = expected["values"].as_array().unwrap();
        assert_eq!(actual.values.len(), values.len(), "{}", actual.dimension);
        for (actual, expected) in actual.values.iter().zip(values) {
            assert_eq!(actual.value, expected["value"].as_str().unwrap());
            assert_eq!(actual.observed_noisy_count, expected["observed_noisy_count"].as_u64().unwrap(), "{}", actual.value);
            let distance = ulps(actual.estimated_count, bits(expected["estimated_count_bits"].as_str().unwrap()));
            assert!(distance <= TOLERANCE_ULPS, "{} differs by {distance} ULP", actual.value);
            worst = worst.max(distance);
            compared += 1;
        }
    }
    (compared, worst)
}

fn packets_of(value: &Value) -> Vec<TelemetryPacket> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| TelemetryPacket {
            time_bucket: item["time_bucket"].as_str().unwrap().into(),
            action: item["action"].as_str().unwrap().into(),
            primary_category: item["primary_category"].as_str().unwrap().into(),
            risk_bucket: item["risk_bucket"].as_str().unwrap().into(),
            model_version: item["model_version"].as_str().unwrap().into(),
            privacy_mechanism: "grr_rr_v1".into(),
            privacy_epsilon: item["privacy_epsilon"].as_f64().unwrap(),
        })
        .collect()
}

#[tokio::test]
async fn corpus_records_marginals_summary_and_health_match_python() {
    let corpus = json(&repo_root().join("tests/conformance/telemetry.json"));
    let (directory, store) = temp_store();
    let service = collector(store.clone());

    // Every recorded request, through the real handler: same status and message as the Python collector.
    let records = corpus["records"].as_array().unwrap();
    let (mut accepted, mut rejected) = (0, 0);
    for record in records {
        let label = record["label"].as_str().unwrap();
        let bytes = STANDARD.decode(record["request_b64"].as_str().unwrap()).unwrap();
        let packet = TelemetryPacket::decode(bytes.as_slice()).unwrap();
        let result = service.record_telemetry(Request::new(packet)).await;
        match record["status"].as_str().unwrap() {
            "OK" => {
                let response = result.unwrap_or_else(|status| panic!("{label}: {status}")).into_inner();
                assert_eq!(response.accepted, record["response"]["accepted"].as_bool().unwrap(), "{label}");
                assert_eq!(response.message, record["response"]["message"].as_str().unwrap(), "{label}");
                accepted += 1;
            }
            "INVALID_ARGUMENT" => {
                let status = result.expect_err(label);
                assert_eq!(status.code(), Code::InvalidArgument, "{label}");
                assert_eq!(status.message(), record["details"].as_str().unwrap(), "{label}");
                rejected += 1;
            }
            other => panic!("{label}: unexpected recorded status {other}"),
        }
    }

    // Stored marginals are exact, row for row.
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let strata: Vec<(i64, i64)> = connection
        .prepare("SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let counts: Vec<(i64, String, String, i64)> = connection
        .prepare("SELECT epsilon_micros, dimension, value, observed_count FROM telemetry_counts ORDER BY epsilon_micros, dimension, value")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let expected_strata: Vec<(i64, i64)> =
        corpus["strata"].as_array().unwrap().iter().map(|row| (row[0].as_i64().unwrap(), row[1].as_i64().unwrap())).collect();
    let expected_counts: Vec<(i64, String, String, i64)> = corpus["counts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row[0].as_i64().unwrap(), row[1].as_str().unwrap().into(), row[2].as_str().unwrap().into(), row[3].as_i64().unwrap()))
        .collect();
    assert_eq!(strata, expected_strata);
    assert_eq!(counts, expected_counts);

    // The summary, through the handler: estimates within 4 ULP, counts exact, and (since the bits agree) the
    // deterministic serialisation hashes alike.
    let response = service.get_telemetry_summary(Request::new(GetTelemetrySummaryRequest {})).await.unwrap().into_inner();
    let expected = &corpus["summary"];
    assert_eq!(response.sample_count, expected["sample_count"].as_u64().unwrap());
    let mut compared = 0;
    let mut worst = 0;
    for (actual, expected) in response.dimensions.iter().zip(expected["dimensions"].as_array().unwrap()) {
        assert_eq!(actual.dimension, expected["dimension"].as_str().unwrap());
        assert_eq!(actual.values.len(), expected["values"].as_array().unwrap().len());
        for (actual, expected) in actual.values.iter().zip(expected["values"].as_array().unwrap()) {
            assert_eq!(actual.value, expected["value"].as_str().unwrap());
            assert_eq!(actual.observed_noisy_count, expected["observed_noisy_count"].as_u64().unwrap());
            let distance = ulps(actual.estimated_count, bits(expected["estimated_count_bits"].as_str().unwrap()));
            assert!(distance <= TOLERANCE_ULPS, "{} differs by {distance} ULP", actual.value);
            worst = worst.max(distance);
            compared += 1;
        }
    }
    let serialised = sha256_hex(&GetTelemetrySummaryResponse::encode_to_vec(&response));
    let identical_serialisation = serialised == expected["serialized_sha256"].as_str().unwrap();
    if worst == 0 {
        assert!(identical_serialisation, "bits agree but the serialised summary differs");
    }

    // An empty database: five dimensions, every estimate and observed count zero.
    let (_empty_directory, empty_store) = temp_store();
    let empty = collector(empty_store).get_telemetry_summary(Request::new(GetTelemetrySummaryRequest {})).await.unwrap().into_inner();
    assert_eq!(empty.sample_count, corpus["empty_summary"]["sample_count"].as_u64().unwrap());
    assert_eq!(empty.dimensions.len() as u64, corpus["empty_summary"]["dimensions"].as_u64().unwrap());
    assert!(
        empty.dimensions.iter().flat_map(|dimension| &dimension.values).all(|v| v.estimated_count == 0.0 && v.observed_noisy_count == 0)
    );

    let health = service.health(Request::new(TelemetryHealthRequest {})).await.unwrap().into_inner();
    assert_eq!(health.service, corpus["health"]["service"].as_str().unwrap());
    assert_eq!(health.status, corpus["health"]["status"].as_str().unwrap());

    eprintln!(
        "PARITY corpus: records={} (accepted {accepted}, rejected {rejected}) strata={} marginal_rows={} summary_values={compared} \
         worst_ulp={worst} serialized_summary_hash_identical={identical_serialisation}",
        records.len(),
        strata.len(),
        counts.len(),
    );
    assert_eq!((records.len(), accepted, rejected, strata.len(), counts.len(), compared), (195, 182, 13, 6, 155, 26));
    drop(directory);
}

#[test]
fn telemetry_audit_fixtures_match_the_python_store() {
    let oracle = json(&fixture("estimator_oracle.json"));
    let mut report = Vec::new();
    for name in ["audit_store_parity", "exp_stress"] {
        let case = &oracle[name];
        let (_directory, store) = temp_store();
        let packets = packets_of(&case["packets"]);
        for packet in &packets {
            store.record(packet).unwrap();
        }
        let summary = store.summary().unwrap();
        // `exp` is not correctly rounded, so each platform's libm gives its own bits. The Python store was run on
        // Windows (UCRT) for `summary` and on Linux (glibc) for `summary_glibc`; Rust calls the platform libm, so it
        // is compared with the Python run on the same libm, at the same tolerance.
        let recorded = if cfg!(windows) || name != "exp_stress" { &case["summary"] } else { &case["summary_glibc"] };
        let (compared, worst) = compare_summary(&summary, recorded);
        report.push(format!("{name}: packets={} values={compared} worst_ulp={worst}", packets.len()));
        if name == "audit_store_parity" {
            // The audit's own count: nine packets over three strata give 26 estimates.
            assert_eq!(compared as u64, case["python_compared_estimates"].as_u64().unwrap());
            assert_eq!(summary.sample_count, 9);
        } else {
            assert_eq!(packets.len(), 1200);
            assert_eq!(compared, 26);
        }
    }
    eprintln!("PARITY audit fixtures: {}", report.join("; "));
}

#[test]
fn a_database_written_by_the_python_store_opens_and_extends() {
    let oracle = json(&fixture("estimator_oracle.json"));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("telemetry-ldp-v1.sqlite3");
    std::fs::copy(fixture("python_written.sqlite3"), &path).unwrap();

    let store = TelemetryStore::open(&path).unwrap();
    let before = store.summary().unwrap();
    let (compared, worst) = compare_summary(&before, &oracle["audit_store_parity"]["summary"]);
    assert_eq!(compared, 26);

    // The Rust service adds a report to the Python-written database, in the same strata and rows.
    let packet = packets_of(&oracle["audit_store_parity"]["packets"]).remove(0);
    store.record(&packet).unwrap();
    let after = store.summary().unwrap();
    assert_eq!(after.sample_count, before.sample_count + 1);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let strata: i64 = connection.query_row("SELECT COUNT(*) FROM telemetry_strata", [], |row| row.get(0)).unwrap();
    assert_eq!(strata, 3, "the existing epsilon strata were reused");
    eprintln!("PARITY python-written database: opened, values={compared} worst_ulp={worst}, extended by one report");
}
