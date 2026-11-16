//! The Python service's tests (`services/telemetry-service/tests/test_security_validation.py`), ported one for one,
//! plus the malformed-packet cases that Python could not express without a wire client: truncated and non-UTF-8
//! protobuf, oversize messages and the legacy-database refusal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{code, packet, temp_store, valid_packet};
use privoke_contracts::proto::v1::telemetry_service_server::TelemetryService;
use privoke_contracts::proto::v1::{GetTelemetrySummaryRequest, TelemetryHealthRequest, TelemetryPacket};
use privoke_telemetry::daily::DailyCap;
use privoke_telemetry::service::TelemetryCollector;
use privoke_telemetry::storage::{StoreError, TelemetryStore};
use privoke_telemetry::validation::{allowed_values, validate_telemetry_packet};
use prost::Message;
use tonic::{Code, Request};

fn rejects(packet: &TelemetryPacket, text: &str) {
    let message = validate_telemetry_packet(packet).expect_err("the packet must be rejected");
    assert!(message.contains(text), "{message:?} does not mention {text:?}");
}

#[tokio::test]
async fn health_is_not_serving_when_storage_is_unwritable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("telemetry.db");
    let store = TelemetryStore::open(&path).unwrap();
    let service = TelemetryCollector::new(store, DailyCap::new(10));
    assert_eq!(service.health(Request::new(TelemetryHealthRequest {})).await.unwrap().into_inner().status, "SERVING");
    // Replace the database with a directory: opening it for writing now fails.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    std::fs::create_dir(&path).unwrap();
    let response = service.health(Request::new(TelemetryHealthRequest {})).await.unwrap().into_inner();
    assert_eq!((response.service.as_str(), response.status.as_str()), ("telemetry-service", "NOT_SERVING"));
}

#[test]
fn storage_keeps_only_epsilon_stratified_aggregate_counts() {
    let (directory, store) = temp_store();
    store.record(&valid_packet()).unwrap();
    store
        .record(&packet(|p| {
            p.action = "BLOCK".into();
            p.privacy_epsilon = 0.5;
        }))
        .unwrap();
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let tables: std::collections::BTreeSet<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let rows: i64 = connection.query_row("SELECT COUNT(*) FROM telemetry_counts", [], |row| row.get(0)).unwrap();
    let strata: Vec<(i64, i64)> = connection
        .prepare("SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(tables, ["telemetry_counts", "telemetry_strata"].map(String::from).into());
    assert_eq!(rows, 10, "five marginals per epsilon stratum");
    assert_eq!(strata, [(500_000, 1), (1_000_000, 1)]);
    drop(directory);
}

fn contribution(observed: i64, sample: i64, epsilon: f64, domain: f64) -> f64 {
    let exp_epsilon = (epsilon / 5.0).exp();
    let q = 1.0 / (exp_epsilon + domain - 1.0);
    let p = exp_epsilon / (exp_epsilon + domain - 1.0);
    (observed as f64 - sample as f64 * q) / (p - q)
}

#[test]
fn summary_debiases_each_epsilon_stratum_separately() {
    let (_directory, store) = temp_store();
    store.record(&packet(|p| p.action = "ALLOW".into())).unwrap();
    store
        .record(&packet(|p| {
            p.action = "BLOCK".into();
            p.privacy_epsilon = 0.5;
        }))
        .unwrap();
    let summary = store.summary().unwrap();
    assert_eq!(summary.sample_count, 2);
    let action = summary.dimensions.iter().find(|item| item.dimension == "action").unwrap();
    let allow = action.values.iter().find(|item| item.value == "ALLOW").unwrap();
    let expected = (contribution(1, 1, 1.0, 3.0) + contribution(0, 1, 0.5, 3.0)).clamp(0.0, 2.0);
    assert!((allow.estimated_count - expected).abs() < 1e-9, "{} vs {expected}", allow.estimated_count);
    assert_eq!(allow.observed_noisy_count, 1);
}

#[test]
fn summary_inverts_rr_and_clips_impossible_count() {
    let (_directory, store) = temp_store();
    store.record(&packet(|p| p.action = "ALLOW".into())).unwrap();
    let summary = store.summary().unwrap();
    assert_eq!(summary.sample_count, 1);
    let action = summary.dimensions.iter().find(|item| item.dimension == "action").unwrap();
    let allow = action.values.iter().find(|item| item.value == "ALLOW").unwrap();
    assert!((allow.estimated_count - contribution(1, 1, 1.0, 3.0).clamp(0.0, 1.0)).abs() < 1e-9);
    assert_eq!(allow.observed_noisy_count, 1);
    assert!(action.values.iter().all(|row| (0.0..=1.0).contains(&row.estimated_count)));
}

#[tokio::test]
async fn record_and_summary_flow_through_the_handlers() {
    let (_directory, store) = temp_store();
    let service = TelemetryCollector::new(store, DailyCap::new(10));
    let accepted = service.record_telemetry(Request::new(valid_packet())).await.unwrap().into_inner();
    assert!(accepted.accepted);
    let summary = service.get_telemetry_summary(Request::new(GetTelemetrySummaryRequest {})).await.unwrap().into_inner();
    assert_eq!(summary.sample_count, 1);
    let names: std::collections::BTreeSet<&str> = summary.dimensions.iter().map(|row| row.dimension.as_str()).collect();
    assert_eq!(names, ["action", "risk_bucket", "primary_category", "model_version", "time_bucket"].into());
}

#[test]
fn accepts_protected_packet() {
    validate_telemetry_packet(&valid_packet()).unwrap();
}

#[test]
fn rejects_missing_or_untrusted_mechanism() {
    for mechanism in ["", "none", "central_dp"] {
        rejects(&packet(|p| p.privacy_mechanism = mechanism.into()), "mechanism");
    }
}

#[test]
fn rejects_invalid_epsilon_boundaries_and_non_finite_values() {
    for epsilon in [0.0, 0.4999, 2.0001, f64::INFINITY, f64::NAN, f64::NEG_INFINITY, -1.0] {
        rejects(&packet(|p| p.privacy_epsilon = epsilon), "privacy_epsilon");
    }
    validate_telemetry_packet(&packet(|p| p.privacy_epsilon = 0.5)).unwrap();
    validate_telemetry_packet(&packet(|p| p.privacy_epsilon = 2.0)).unwrap();
    // Seven decimal places are refused, six are not (corpus labels epsilon-seven-decimals and 1.333333).
    rejects(&packet(|p| p.privacy_epsilon = 1.000_000_1), "six decimal places");
    validate_telemetry_packet(&packet(|p| p.privacy_epsilon = 1.333_333)).unwrap();
}

#[test]
fn rejects_values_outside_fixed_domains() {
    for field in ["time_bucket", "action", "primary_category", "risk_bucket", "model_version"] {
        let broken = packet(|p| match field {
            "time_bucket" => p.time_bucket = "unbounded-input".into(),
            "action" => p.action = "unbounded-input".into(),
            "primary_category" => p.primary_category = "unbounded-input".into(),
            "risk_bucket" => p.risk_bucket = "unbounded-input".into(),
            _ => p.model_version = "unbounded-input".into(),
        });
        rejects(&broken, &format!("{field} has an unsupported value."));
        assert!(!allowed_values(field).is_empty());
    }
    // Case and whitespace variants are not in the domain either.
    for value in ["allow", "Allow", " ALLOW", "ALLOW ", "ALLOW\n", ""] {
        rejects(&packet(|p| p.action = value.into()), "action has an unsupported value.");
    }
}

#[test]
fn legacy_wire_packet_fails_closed() {
    // A pre-LDP packet has fields 1-16. The new protocol reserves those tags and requires the GRR marker at tag 25,
    // which legacy senders cannot set.
    let legacy = TelemetryPacket::decode(&b"\x3a\x04WARN"[..]).unwrap();
    rejects(&legacy, "mechanism");
}

#[test]
fn explicit_legacy_database_path_fails_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("CREATE TABLE telemetry_events (event_id TEXT, source_id TEXT, risk_score REAL)", []).unwrap();
    connection.execute("INSERT INTO telemetry_events VALUES ('old', 'client', 0.7)", []).unwrap();
    drop(connection);
    let error = TelemetryStore::open(&path).unwrap_err();
    assert!(matches!(error, StoreError::Legacy), "{error}");
    assert!(error.to_string().contains("legacy unprotected"));
    let connection = rusqlite::Connection::open(&path).unwrap();
    let rows: Vec<(String, String, f64)> = connection
        .prepare("SELECT * FROM telemetry_events")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, [("old".to_string(), "client".to_string(), 0.7)]);
    let tables: i64 =
        connection.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'telemetry_%'", [], |row| row.get(0)).unwrap();
    assert_eq!(tables, 1, "the legacy database gained no aggregate table");
}

#[test]
fn an_incompatible_aggregate_schema_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("other.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE telemetry_strata (epsilon_micros INTEGER PRIMARY KEY, sample_count INTEGER, source_id TEXT)", [])
        .unwrap();
    drop(connection);
    assert!(matches!(TelemetryStore::open(&path).unwrap_err(), StoreError::Incompatible));
}

/// Malformed protobuf bytes never become a stored report. Python's generated parser raises on truncation and on
/// invalid UTF-8 in a string field; prost does the same, and the transport turns it into an error status before the
/// handler runs.
#[test]
fn malformed_wire_bytes_do_not_decode_into_reports() {
    let good = valid_packet().encode_to_vec();
    // Every proper prefix of a packet that cuts a field in half is a decode error.
    let mut truncated_errors = 0;
    for length in 1..good.len() {
        if TelemetryPacket::decode(&good[..length]).is_err() {
            truncated_errors += 1;
        }
    }
    assert!(truncated_errors > good.len() / 2, "{truncated_errors} of {} prefixes failed", good.len());
    // Invalid UTF-8 in `action` (tag 21, wire type 2).
    assert!(TelemetryPacket::decode(&b"\xaa\x01\x02\xff\xfe"[..]).is_err());
    // A string field sent with a varint wire type, a group start and a length that overruns the buffer.
    assert!(TelemetryPacket::decode(&b"\xa8\x01\x05"[..]).is_err());
    assert!(TelemetryPacket::decode(&b"\xa3\x01"[..]).is_err());
    assert!(TelemetryPacket::decode(&b"\xaa\x01\x7f"[..]).is_err());
    // Reserved legacy tags decode as unknown fields and are dropped; the marker is then missing.
    let legacy = TelemetryPacket::decode(&b"\x0a\x03abc\x10\x07"[..]).unwrap();
    rejects(&legacy, "mechanism");
    // Duplicate fields: the last value wins (proto3), and it is validated like any other.
    let mut doubled = packet(|p| p.action = "ALLOW".into()).encode_to_vec();
    doubled.extend_from_slice(&packet(|p| p.action = "DENY".into()).encode_to_vec());
    rejects(&TelemetryPacket::decode(doubled.as_slice()).unwrap(), "action has an unsupported value.");
}

#[tokio::test]
async fn rejected_packets_are_not_stored_or_counted() {
    let (_directory, store) = temp_store();
    let service = TelemetryCollector::new(store.clone(), DailyCap::new(1));
    for bad in
        [packet(|p| p.privacy_mechanism = "none".into()), packet(|p| p.privacy_epsilon = f64::NAN), packet(|p| p.action = "DENY".into())]
    {
        assert_eq!(code(service.record_telemetry(Request::new(bad)).await), Code::InvalidArgument);
    }
    assert_eq!(store.summary().unwrap().sample_count, 0);
    // Invalid packets did not use the single daily slot of this (unspecified) source.
    assert_eq!(code(service.record_telemetry(Request::new(valid_packet())).await), Code::Ok);
    assert_eq!(code(service.record_telemetry(Request::new(valid_packet())).await), Code::ResourceExhausted);
    assert_eq!(store.summary().unwrap().sample_count, 1);
}
