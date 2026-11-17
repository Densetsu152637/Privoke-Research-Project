//! The Rust reporter against the Python oracle, on the recorded fixture `tests/fixtures/golden.json`
//! (`evaluation/generate_telemetry_client_golden.py`). Every expected value was produced by the unmodified Python
//! `privacy.py` and `event_emitter.py`; the random source of both is the recorded byte stream, so the same bytes must
//! give the same draws, the same consumption and the same decisions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use privoke_contracts::proto::v1::TelemetryPacket;
use privoke_telemetry_client::{
    AnalysisInput, AnalysisResult, Classification, DailyPrivacyBudget, DeliveryFailure, DeliveryObserver, DeliveryOutcome, PacketTransport,
    PrivacyError, RandomError, RandomSource, ReplayRandom, ReporterParts, ReporterSettings, StructuredEventEmitter, TelemetryReporter,
    domain, generalized_randomized_response, grr_kernel, randomize_report, validate_privacy_config,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

fn golden() -> Value {
    serde_json::from_str(include_str!("fixtures/golden.json")).unwrap()
}

fn float(value: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(value["bits"].as_str().unwrap(), 16).unwrap())
}

fn bits_hex(value: f64) -> String {
    format!("{:016x}", value.to_bits())
}

fn bytes(text: &Value) -> Vec<u8> {
    let text = text.as_str().unwrap();
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(|item| item.as_str().unwrap().to_string()).collect()
}

fn string_map(value: &Value) -> BTreeMap<String, String> {
    value.as_object().unwrap().iter().map(|(key, item)| (key.clone(), item.as_str().unwrap().to_string())).collect()
}

fn moment(spec: &Value) -> OffsetDateTime {
    let parts: Vec<i64> = spec.as_array().unwrap().iter().map(|item| item.as_i64().unwrap()).collect();
    let date = Date::from_calendar_date(parts[0] as i32, Month::try_from(parts[1] as u8).unwrap(), parts[2] as u8).unwrap();
    let time = Time::from_hms(parts[3] as u8, parts[4] as u8, 0).unwrap();
    PrimitiveDateTime::new(date, time).assume_offset(UtcOffset::from_whole_seconds(parts[5] as i32 * 60).unwrap())
}

fn at_hour(hour: u8) -> OffsetDateTime {
    let date = Date::from_calendar_date(2026, Month::March, 5).unwrap();
    PrimitiveDateTime::new(date, Time::from_hms(hour, 17, 41).unwrap()).assume_utc()
}

#[test]
fn the_golden_fixture_is_the_documented_shape() {
    let golden = golden();
    assert_eq!(golden["schema"], 1);
    assert_eq!(golden["constants"]["mechanism"], "grr_rr_v1");
    let domains = golden["constants"]["domains"].as_object().unwrap();
    for (name, values) in domains {
        let expected: Vec<&str> = values.as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect();
        assert_eq!(domain(name).unwrap(), expected.as_slice(), "domain {name}");
    }
    assert_eq!(strings(&golden["constants"]["dimensions"]), privoke_telemetry_client::DIMENSIONS.map(String::from));
}

#[test]
fn kernel_thresholds_match_python_bit_for_bit() {
    let golden = golden();
    for cell in golden["kernel"]["grid"].as_array().unwrap() {
        let epsilon = float(&cell["epsilon"]);
        let kernel = grr_kernel(cell["size"].as_u64().unwrap() as usize, epsilon).unwrap();
        assert_eq!(
            bits_hex(kernel.truthful),
            bits_hex(float(&cell["truthful"])),
            "truthful at {} size {}",
            cell["epsilon"]["repr"],
            cell["size"]
        );
        assert_eq!(bits_hex(kernel.other), bits_hex(float(&cell["other"])), "other at {} size {}", cell["epsilon"]["repr"], cell["size"]);
    }
    for cell in golden["kernel"]["per_dimension"].as_array().unwrap() {
        let event = float(&cell["event_epsilon"]);
        let epsilon = event / privoke_telemetry_client::DIMENSIONS.len() as f64;
        assert_eq!(bits_hex(epsilon), bits_hex(float(&cell["epsilon"])));
        let size = domain(cell["dimension"].as_str().unwrap()).unwrap().len();
        let kernel = grr_kernel(size, epsilon).unwrap();
        assert_eq!(
            bits_hex(kernel.truthful),
            bits_hex(float(&cell["truthful"])),
            "{} at {}",
            cell["dimension"],
            cell["event_epsilon"]["repr"]
        );
        assert_eq!(bits_hex(kernel.other), bits_hex(float(&cell["other"])));
    }
}

#[test]
fn single_draws_and_boundary_draws_match_python_with_the_same_bytes() {
    let golden = golden();
    let mut boundary = 0;
    let mut truthful = 0;
    let mut alternative = 0;
    for case in golden["grr"]["cases"].as_array().unwrap() {
        let domain_names = strings(&case["domain"]);
        let domain: Vec<&str> = domain_names.iter().map(String::as_str).collect();
        let mut random = ReplayRandom::new(bytes(&case["bytes"]));
        let value = case["value"].as_str().unwrap();
        let output = generalized_randomized_response(value, &domain, float(&case["epsilon"]), &mut random).unwrap();
        assert_eq!(output, case["output"].as_str().unwrap(), "case {case}");
        assert_eq!(random.remaining(), 0, "the draw must consume exactly the bytes Python consumed: {case}");
        boundary += usize::from(case.get("boundary").is_some());
        if output == value {
            truthful += 1;
        } else {
            alternative += 1;
        }
    }
    assert!(boundary >= 100 && truthful >= 100 && alternative >= 100, "{boundary} {truthful} {alternative}");
}

#[test]
fn rejected_inputs_carry_python_messages() {
    let golden = golden();
    for case in golden["grr"]["errors"].as_array().unwrap() {
        let domain_names = strings(&case["domain"]);
        let domain: Vec<&str> = domain_names.iter().map(String::as_str).collect();
        let mut random = ReplayRandom::new(Vec::<u8>::new());
        let error =
            generalized_randomized_response(case["value"].as_str().unwrap(), &domain, float(&case["epsilon"]), &mut random).unwrap_err();
        assert_eq!(error.python_class(), case["error"]["class"].as_str().unwrap());
        assert_eq!(error.to_string(), case["error"]["message"].as_str().unwrap(), "case {case}");
    }
    for case in golden["reports"]["invalid"].as_array().unwrap() {
        let mut random = ReplayRandom::new(Vec::<u8>::new());
        let error = randomize_report(&string_map(&case["values"]), float(&case["epsilon"]), &mut random).unwrap_err();
        assert_eq!(error.python_class(), "ValueError");
        assert_eq!(error.to_string(), case["error"]["message"].as_str().unwrap(), "case {}", case["label"]);
    }
}

#[test]
fn randomised_reports_match_python_with_the_same_bytes() {
    let golden = golden();
    for case in golden["reports"]["cases"].as_array().unwrap() {
        let mut random = ReplayRandom::new(bytes(&case["bytes"]));
        let protected = randomize_report(&string_map(&case["values"]), float(&case["epsilon"]), &mut random).unwrap();
        assert_eq!(protected, string_map(&case["output"]), "case {case}");
        assert_eq!(random.remaining(), 0, "case {case}");
    }
}

#[test]
fn privacy_configuration_validation_matches_python() {
    let golden = golden();
    for case in golden["config"].as_array().unwrap() {
        let result = validate_privacy_config(float(&case["event"]), float(&case["daily"]));
        if case["ok"].as_bool().unwrap() {
            assert!(result.is_ok(), "{case}");
        } else {
            assert_eq!(result.unwrap_err().to_string(), case["message"].as_str().unwrap(), "{case}");
        }
    }
}

fn describe(result: Result<bool, PrivacyError>) -> Value {
    match result {
        Ok(accepted) => json!({ "result": accepted }),
        Err(error) => json!({ "error": { "class": error.python_class(), "message": error.to_string() } }),
    }
}

fn ledger_rows(path: &Path) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let connection = Connection::open(path).unwrap();
    let mut statement = connection.prepare("SELECT utc_day, epsilon_spent FROM daily_budget ORDER BY singleton").unwrap();
    let rows: Vec<Value> = statement
        .query_map([], |row| Ok(json!([row.get::<_, String>(0)?, bits_hex(row.get::<_, f64>(1)?)])))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    Some(Value::Array(rows))
}

fn ledger_schema(path: &Path) -> Value {
    let connection = Connection::open(path).unwrap();
    let schema: String = connection.query_row("SELECT sql FROM sqlite_master WHERE name = 'daily_budget'", [], |row| row.get(0)).unwrap();
    Value::String(schema)
}

#[test]
fn ledger_scenarios_match_python_operation_by_operation() {
    let golden = golden();
    for scenario in golden["ledger"]["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let path = state.join("ledger.sqlite3");
        let daily = float(&scenario["daily"]);
        let mut budget = DailyPrivacyBudget::new(&path, daily).unwrap();
        for (index, (operation, expected)) in
            scenario["ops"].as_array().unwrap().iter().zip(scenario["results"].as_array().unwrap()).enumerate()
        {
            let observed = match operation["op"].as_str().unwrap() {
                "reserve" => describe(budget.reserve(float(&operation["epsilon"]), Some(moment(&operation["now"])))),
                "new" => {
                    budget = DailyPrivacyBudget::new(&path, daily).unwrap();
                    json!({ "ok": true })
                }
                "exists" => json!({ "exists": path.exists() }),
                "write_bytes" => {
                    fs::create_dir_all(&state).unwrap();
                    fs::write(&path, bytes(&operation["hex"])).unwrap();
                    json!({ "ok": true })
                }
                "remove_file" => {
                    fs::remove_file(&path).unwrap();
                    json!({ "ok": true })
                }
                "sql" => {
                    fs::create_dir_all(&state).unwrap();
                    let connection = Connection::open(&path).unwrap();
                    for statement in operation["statements"].as_array().unwrap() {
                        connection.execute_batch(statement.as_str().unwrap()).unwrap();
                    }
                    json!({ "ok": true })
                }
                "block_parent" => {
                    fs::rename(&state, directory.path().join("state-moved")).unwrap();
                    fs::write(&state, "x").unwrap();
                    json!({ "ok": true })
                }
                "unblock_parent" => {
                    fs::remove_file(&state).unwrap();
                    fs::rename(directory.path().join("state-moved"), &state).unwrap();
                    json!({ "ok": true })
                }
                other => panic!("unknown operation {other}"),
            };
            assert_eq!(&observed, expected, "scenario {name}, operation {index}: {operation}");
        }
        match ledger_rows(&path) {
            Some(rows) => {
                assert_eq!(rows, scenario["rows"], "scenario {name}: final rows");
                assert_eq!(ledger_schema(&path), scenario["schema"], "scenario {name}: schema text");
            }
            None => assert!(scenario["rows"].is_null(), "scenario {name}: no ledger file but rows expected"),
        }
    }
}

#[test]
fn concurrent_reservations_never_overspend() {
    let golden = golden();
    let expected = &golden["ledger"]["concurrent"];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.sqlite3");
    let now = at_hour(12);
    let threads = expected["threads"].as_u64().unwrap();
    let accepted: Vec<bool> = (0..threads)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || DailyPrivacyBudget::new(path, 8.0).unwrap().reserve(1.0, Some(now)).unwrap())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(accepted.iter().filter(|accepted| **accepted).count() as u64, expected["accepted"].as_u64().unwrap());
    assert!(!DailyPrivacyBudget::new(&path, 8.0).unwrap().reserve(1.0, Some(now)).unwrap());
}

#[test]
fn a_ledger_written_by_python_continues_in_rust_and_has_the_same_schema() {
    let golden = golden();
    let written = &golden["ledger"]["python_written"];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.sqlite3");
    fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python_written_ledger.sqlite3"), &path).unwrap();
    let budget = DailyPrivacyBudget::new(&path, float(&written["daily"])).unwrap();
    let day = moment(&json!([2026, 1, 1, 10, 0, 0]));
    // Python spent 3.0 of 8.0 on 2026-01-01; Rust finds it and spends the remaining five.
    assert_eq!(ledger_rows(&path).unwrap(), json!([["2026-01-01", bits_hex(float(&written["spent"]))]]));
    for _ in 0..5 {
        assert!(budget.reserve(1.0, Some(day)).unwrap());
    }
    assert!(!budget.reserve(1.0, Some(day)).unwrap());
    assert!(budget.reserve(1.0, Some(moment(&json!([2026, 1, 2, 0, 5, 0])))).unwrap());
    assert_eq!(ledger_rows(&path).unwrap(), json!([["2026-01-02", bits_hex(1.0)]]));
    // The same table text as the oracle's own file.
    let python_schema = &golden["ledger"]["scenarios"][0]["schema"];
    assert_eq!(&ledger_schema(&path), python_schema);
}

fn analysis(case: &Value) -> AnalysisInput {
    let result = &case["result"];
    AnalysisInput {
        action: case["action"].as_str().unwrap().to_string(),
        result: if result.is_null() {
            None
        } else {
            let classification = &result["classification"];
            Some(AnalysisResult {
                classification: if classification.is_null() {
                    None
                } else {
                    Some(Classification {
                        sensitivity: classification["sensitivity"].as_str().unwrap().to_string(),
                        categories: strings(&classification["categories"]),
                    })
                },
                model_version: result["model_version"].as_str().map(str::to_string),
            })
        },
    }
}

fn assert_packet(packet: &TelemetryPacket, expected: &Value, context: &str) {
    assert_eq!(packet.time_bucket, expected["time_bucket"].as_str().unwrap(), "{context}");
    assert_eq!(packet.action, expected["action"].as_str().unwrap(), "{context}");
    assert_eq!(packet.primary_category, expected["primary_category"].as_str().unwrap(), "{context}");
    assert_eq!(packet.risk_bucket, expected["risk_bucket"].as_str().unwrap(), "{context}");
    assert_eq!(packet.model_version, expected["model_version"].as_str().unwrap(), "{context}");
    assert_eq!(packet.privacy_mechanism, expected["privacy_mechanism"].as_str().unwrap(), "{context}");
    assert_eq!(bits_hex(packet.privacy_epsilon), bits_hex(float(&expected["privacy_epsilon"])), "{context}");
}

#[test]
fn true_values_and_packets_match_python() {
    let golden = golden();
    let cases = golden["events"]["true_values"].as_array().unwrap();
    assert!(cases.len() >= 200);
    for case in cases {
        let input = analysis(case);
        let hour = case["hour"].as_u64().unwrap() as u8;
        let values = StructuredEventEmitter::true_values(&input, at_hour(hour));
        assert_eq!(values, string_map(&case["true_values"]), "case {case}");
        let epsilon = float(&case["epsilon"]);
        assert_packet(&StructuredEventEmitter::assemble_packet(&values, epsilon), &case["packet"], &case.to_string());
    }
}

#[test]
fn randomised_packets_match_python_with_the_same_bytes() {
    let golden = golden();
    for case in golden["events"]["packets"].as_array().unwrap() {
        let mut random = ReplayRandom::new(bytes(&case["bytes"]));
        let hour = case["hour"].as_u64().unwrap() as u8;
        let packet = StructuredEventEmitter::build_packet(&analysis(case), float(&case["epsilon"]), at_hour(hour), &mut random).unwrap();
        assert_packet(&packet, &case["packet"], &case.to_string());
        assert_eq!(random.remaining(), 0, "case {case}");
    }
}

/// A transport that records packets and plays back a script of outcomes, optionally parked on the first packet.
struct ScriptedTransport {
    script: Vec<String>,
    sent: Arc<Mutex<Vec<TelemetryPacket>>>,
    gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl PacketTransport for ScriptedTransport {
    fn send(&mut self, packet: &TelemetryPacket, _timeout: Duration) -> Result<bool, DeliveryFailure> {
        self.sent.lock().unwrap().push(packet.clone());
        if let Some((entered, release)) = self.gate.take() {
            let _ = entered.send(());
            let _ = release.recv_timeout(Duration::from_secs(10));
        }
        let outcome = if self.script.is_empty() { "ok".to_string() } else { self.script.remove(0) };
        match outcome.as_str() {
            "ok" => Ok(true),
            "rejected" => Ok(false),
            "rpc" => Err(DeliveryFailure::Rpc { code: "StatusCode.UNAVAILABLE".to_string() }),
            "rpc_deadline" => Err(DeliveryFailure::Rpc { code: "StatusCode.DEADLINE_EXCEEDED".to_string() }),
            _ => Err(DeliveryFailure::Other { class: "RuntimeError".to_string() }),
        }
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill(&mut self, _buffer: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError("entropy unavailable".to_string()))
    }
}

fn ledger_spent(path: &Path) -> Option<String> {
    ledger_rows(path).and_then(|rows| rows[0][1].as_str().map(str::to_string))
}

#[test]
fn reporter_scenarios_match_python() {
    let golden = golden();
    for scenario in golden["reporter"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let ledger = state.join("ledger.sqlite3");
        if scenario["blocked_ledger"].as_bool().unwrap() {
            fs::write(&state, "x").unwrap();
        }
        let block_first = scenario["block_first"].as_bool().unwrap();
        let replay = ReplayRandom::new(bytes(&scenario["stream"]));
        let failing = scenario["failing_entropy"].as_bool().unwrap();
        let random: Box<dyn RandomSource + Send> = if failing { Box::new(FailingRandom) } else { Box::new(replay.clone()) };
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (entered_sender, entered) = mpsc::channel();
        let (release_sender, release) = mpsc::channel();
        let transport = ScriptedTransport {
            script: strings(&scenario["script"]),
            sent: Arc::clone(&sent),
            gate: block_first.then_some((entered_sender, release)),
        };
        let (outcome_sender, outcomes) = mpsc::channel();
        let observer: DeliveryObserver = Arc::new(move |outcome: &DeliveryOutcome| {
            let _ = outcome_sender.send(outcome.clone());
        });
        let fixed = at_hour(13);
        let settings = ReporterSettings {
            event_epsilon: float(&scenario["event_epsilon"]),
            daily_epsilon: float(&scenario["daily_epsilon"]),
            ledger_path: Some(ledger.clone()),
            timeout: Duration::from_secs(5),
            queue_size: scenario["queue_size"].as_u64().unwrap() as usize,
        };
        let reporter = TelemetryReporter::with_parts(
            settings,
            ReporterParts { transport: Box::new(transport), random, clock: Box::new(move || fixed), observer: Some(observer) },
        )
        .unwrap();
        let unblock_after = scenario["unblock_after"].as_u64().map(|index| index as usize);
        let mut per_report = Vec::new();
        for (index, action) in strings(&scenario["actions"]).into_iter().enumerate() {
            if unblock_after == Some(index) {
                fs::remove_file(&state).unwrap();
            }
            if block_first && index == 1 {
                entered.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            let input =
                AnalysisInput { action, result: Some(AnalysisResult { classification: None, model_version: Some("v0.3.0".to_string()) }) };
            per_report.push(reporter.report(&input).log_message());
        }
        if block_first {
            release_sender.send(()).unwrap();
        }
        let expected_sent = scenario["sent"].as_array().unwrap();
        let delivered: Vec<DeliveryOutcome> =
            (0..expected_sent.len()).map(|_| outcomes.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
        reporter.close(Duration::from_secs(5));

        let expected_per_report: Vec<Option<String>> =
            scenario["per_report_log"].as_array().unwrap().iter().map(|item| item.as_str().map(str::to_string)).collect();
        assert_eq!(per_report, expected_per_report, "scenario {name}: per-report log");
        let delivery_log: Vec<String> = delivered.iter().filter_map(DeliveryOutcome::log_message).collect();
        assert_eq!(delivery_log, strings(&scenario["delivery_log"]), "scenario {name}: delivery log");
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), expected_sent.len(), "scenario {name}: packets sent");
        for (index, (packet, expected)) in sent.iter().zip(expected_sent).enumerate() {
            assert_packet(packet, expected, &format!("scenario {name}, packet {index} (FIFO order)"));
        }
        if !failing {
            assert_eq!(replay.remaining(), 0, "scenario {name}: random bytes consumed");
        }
        assert_eq!(ledger_spent(&ledger), scenario["spent_after"].as_str().map(str::to_string), "scenario {name}: spend is never refunded");
    }
}
