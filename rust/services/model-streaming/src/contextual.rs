//! Tiny transformer ("contextual training") artifact validation: strategies, objectives, optimizers, the FULL Adam,
//! ORIGINAL-retention and window policies, task-query readouts and the full-encoder shape inventory.
//!
//! Port of `contextual_training.go`. The canonical configuration strings are compared lexically, so they carry
//! Python's float spelling (`1e-08`); see [`privoke_contracts::pyfloat`].

use std::collections::{BTreeMap, BTreeSet};

use privoke_contracts::json::Value;

use crate::artifact::{ModelArtifact, TASK_QUERY_ARCHITECTURE, Tensor};
use crate::error::Result;
use crate::fail;
use crate::jsonx::{self, Object};

/// Metadata key naming the training strategy.
pub const STRATEGY_KEY: &str = "contextual_training_strategy";
/// Last transformer block and heads.
pub const LAST_BLOCK_STRATEGY: &str = "contextual_last_block_sgd_v1";
/// Every encoder tensor.
pub const FULL_ENCODER_STRATEGY: &str = "contextual_full_encoder_sgd_v1";
/// Metadata key naming the optimizer.
pub const OPTIMIZER_KEY: &str = "contextual_training_optimizer";
/// One local SGD step.
pub const LOCAL_SGD_1: &str = "local_sgd_1_v1";
/// Four local SGD steps.
pub const LOCAL_SGD_4: &str = "local_sgd_4_v1";
/// Metadata key naming the objective.
pub const OBJECTIVE_KEY: &str = "contextual_training_objective";
/// Class-balanced objective.
pub const CLASS_BALANCED_OBJECTIVE: &str = "class_balanced_contextual_v1";
/// Class-balanced, mean over categories.
pub const CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE: &str = "class_balanced_contextual_mean_category_v1";
/// Class-balanced with a decision margin.
pub const CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE: &str = "class_balanced_contextual_decision_margin_v1";
/// Class-balanced, summed categories, decision margin.
pub const CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE: &str = "class_balanced_contextual_sum_category_decision_margin_v1";
/// FULL projected Adam optimizer.
pub const FULL_ADAM: &str = "full_projected_adam64_v1";
/// Metadata key naming candidate eligibility.
pub const CANDIDATE_ELIGIBILITY_KEY: &str = "contextual_candidate_eligibility";
/// FULL Adam eligibility.
pub const CANDIDATE_ELIGIBILITY: &str = "candidate_train_exact_eligibility_v1";
/// Metadata key holding the FULL Adam configuration.
pub const FULL_ADAM_CONFIG_KEY: &str = "full_projected_adam_config_v1";
/// ORIGINAL retention, gate optimizer.
pub const RETENTION_GATE: &str = "full_projected_adam64_original_train_gate_v1";
/// ORIGINAL retention, hinge optimizer.
pub const RETENTION_HINGE: &str = "full_projected_adam64_original_train_hinge_v1";
/// ORIGINAL retention gate objective.
pub const RETENTION_GATE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_gate_v1";
/// ORIGINAL retention hinge objective.
pub const RETENTION_HINGE_OBJECTIVE: &str = "class_balanced_contextual_sum_margin_original_hinge_v1";
/// ORIGINAL retention eligibility.
pub const RETENTION_ELIGIBILITY: &str = "candidate_train_exact_original_target_capped_v1";
/// ORIGINAL retention manifest pin key.
pub const RETENTION_MANIFEST_KEY: &str = "original_train_retention_manifest_sha256";
/// Window checkpoint optimizer.
pub const WINDOW_ADAM: &str = "full_projected_adam64_window_checkpoint_v1";
/// Window eligibility.
pub const WINDOW_ELIGIBILITY: &str = "candidate_window_exact_component_retention_v1";
/// Window configuration key.
pub const WINDOW_CONFIG_KEY: &str = "train_window_config_v1";
/// Window manifest pin key.
pub const WINDOW_MANIFEST_KEY: &str = "train_window_manifest_sha256";
/// Component manifest pin key.
pub const COMPONENT_MANIFEST_KEY: &str = "original_train_component_manifest_sha256";

/// The frozen window configuration, spelled exactly as the Python `canonical()` writes it.
pub const WINDOW_CONFIG: &str = r#"{"adam":{"beta1":0.9,"beta2":0.999,"cpu_threads":1,"delta_cap":0.05,"device":"cpu","epsilon":1e-08,"eta":0.003,"gradient_denominator":1,"margin_coefficient":1,"microbatch_size":32,"moment_dtype":"float64","steps":64},"auxiliary_coefficient":1,"block_rows":64,"blocks":8,"candidate_seeds":64,"checkpoints":[8,16,24,32,40,48,56,64],"component_order":["sensitivity","severity","category","visibility","action"],"epochs":8,"epsilon":1e-06,"main_normalization":"eight_times_block_over_frozen_window_weight_v1","margin_cap":1.0,"normalization":"category_bits_then_components_then_rows_v1","selector":"transported_train_component_rank_v1"}"#;

/// Exact Python `canonical(CONFIG)`: lexical equality binds the supported version, including numeric representation,
/// key inventory and the process-thread contract.
pub const FULL_ADAM_CONFIG: &str = r#"{"beta1":0.9,"beta2":0.999,"cpu_threads":1,"delta_cap":0.05,"device":"cpu","epsilon":1e-08,"eta":0.003,"gradient_denominator":1,"margin_coefficient":1,"microbatch_size":32,"moment_dtype":"float64","steps":64}"#;

/// Tensor names inside one transformer block, without the layer prefix.
pub const BLOCK_NAMES: [&str; 9] = [
    "attention.query.weight",
    "attention.key.weight",
    "attention.value.weight",
    "attention.output.weight",
    "attention.output.bias",
    "ffn.input.weight",
    "ffn.input.bias",
    "ffn.output.weight",
    "ffn.output.bias",
];

const TASK_QUERY_READOUT: &str = "residual_task_query_v1";
const TASKS: [&str; 3] = ["sensitivity", "visibility", "category"];

fn layer_prefix(layers: i64, layer: i64) -> String {
    if layers > 1 { format!("layers.{layer}.") } else { String::new() }
}

/// `contextualQueryReadout`: whether the config selects the residual task-query readout.
pub fn contextual_query_readout(config: &str) -> Result<bool> {
    let fields = jsonx::object_of(config)?;
    let Some(raw) = fields.get("readout") else { return Ok(false) };
    let Ok(value) = jsonx::required_string(raw) else { fail!("invalid Tiny readout") };
    match value.as_str() {
        TASK_QUERY_READOUT => Ok(true),
        "legacy_pool_v1" => Ok(false),
        _ => fail!("unsupported Tiny readout"),
    }
}

/// `contextualTrainableNames`: the tensors a strategy marks trainable, and the encoder layer count.
pub fn contextual_trainable_names(config: &str, strategy: &str) -> Result<(BTreeSet<String>, i64)> {
    let mut expected = BTreeSet::new();
    for head in TASKS {
        for part in ["weight", "bias"] {
            expected.insert(format!("head.{head}.{part}"));
        }
    }
    if contextual_query_readout(config)? {
        for task in TASKS {
            expected.insert(format!("readout.{task}.query"));
        }
    }
    if !strategy.is_empty() && strategy != LAST_BLOCK_STRATEGY && strategy != FULL_ENCODER_STRATEGY {
        fail!("unsupported contextual training strategy");
    }
    let fields = jsonx::object_of(config).map_err(|_| crate::error::Error("invalid contextual configuration".into()))?;
    let mut layers = 1i64;
    if let Some(raw) = fields.get("num_layers") {
        layers = jsonx::int64(Some(raw)).map_err(|_| crate::error::Error("invalid contextual encoder layer count".into()))?;
    }
    if !(1..=512).contains(&layers) {
        fail!("invalid contextual encoder layer count");
    }
    if strategy.is_empty() {
        return Ok((expected, layers));
    }
    if strategy == FULL_ENCODER_STRATEGY {
        expected.insert("token_embedding".into());
        expected.insert("position_embedding".into());
        for layer in 0..layers {
            let prefix = layer_prefix(layers, layer);
            for name in BLOCK_NAMES {
                expected.insert(format!("{prefix}{name}"));
            }
        }
        return Ok((expected, layers));
    }
    let prefix = layer_prefix(layers, layers - 1);
    for name in BLOCK_NAMES {
        expected.insert(format!("{prefix}{name}"));
    }
    Ok((expected, layers))
}

fn is_float32_infinite(value: f64) -> bool {
    (value as f32).is_infinite()
}

/// `validateContextualTrainingArtifact`.
pub fn validate_contextual_training_artifact(artifact: &ModelArtifact) -> Result<()> {
    let query_readout = contextual_query_readout(&artifact.config)?;
    if query_readout != (artifact.architecture == TASK_QUERY_ARCHITECTURE) {
        fail!("Tiny architecture and readout disagree");
    }
    if query_readout {
        validate_task_query_config(&artifact.config)?;
    }
    if !query_readout {
        for task in TASKS {
            if artifact.parameters.contains_key(&format!("readout.{task}.query")) {
                fail!("legacy Tiny cannot contain query readouts");
            }
        }
    }
    let metadata = artifact.metadata();
    validate_contextual_full_adam_policy(metadata)?;
    if let Some(optimizer) = metadata.get(OPTIMIZER_KEY)
        && !matches!(optimizer.as_str(), LOCAL_SGD_1 | LOCAL_SGD_4 | FULL_ADAM | RETENTION_GATE | RETENTION_HINGE | WINDOW_ADAM)
    {
        fail!("unsupported contextual training optimizer");
    }
    if let Some(objective) = metadata.get(OBJECTIVE_KEY)
        && !matches!(
            objective.as_str(),
            CLASS_BALANCED_OBJECTIVE
                | CLASS_BALANCED_MEAN_CATEGORY_OBJECTIVE
                | CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE
                | CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE
                | RETENTION_GATE_OBJECTIVE
                | RETENTION_HINGE_OBJECTIVE
        )
    {
        fail!("unsupported contextual training objective");
    }
    let objective = metadata.get(OBJECTIVE_KEY).map_or("", String::as_str);
    if matches!(
        objective,
        CLASS_BALANCED_DECISION_MARGIN_OBJECTIVE
            | CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE
            | RETENTION_GATE_OBJECTIVE
            | RETENTION_HINGE_OBJECTIVE
    ) {
        validate_decision_margin_config(&artifact.config)?;
    }
    let declared_strategy = metadata.get(STRATEGY_KEY);
    let declared = declared_strategy.is_some();
    let strategy = declared_strategy.map_or("", String::as_str);
    if declared && strategy.is_empty() {
        fail!("contextual training strategy must be nonempty");
    }
    let (expected, layers) = contextual_trainable_names(&artifact.config, strategy)?;
    if strategy == FULL_ENCODER_STRATEGY || query_readout {
        validate_full_encoder_shapes(artifact, layers)?;
    }
    for name in &expected {
        if !artifact.parameters.contains_key(name) {
            fail!("contextual training tensor manifest incomplete");
        }
    }
    let mut allowed: BTreeSet<String> = BTreeSet::from(["token_embedding".to_string(), "position_embedding".to_string()]);
    allowed.extend(expected.iter().cloned());
    if declared {
        for layer in 0..layers {
            let prefix = layer_prefix(layers, layer);
            for name in BLOCK_NAMES {
                allowed.insert(format!("{prefix}{name}"));
            }
        }
        if artifact.parameters.len() != allowed.len() {
            fail!("contextual adapted tensor manifest is not exact");
        }
    }
    let limit = if strategy == FULL_ENCODER_STRATEGY { 24576 } else { 4096 };
    for (name, tensor) in &artifact.parameters {
        if query_readout && tensor.values.iter().any(|value| is_float32_infinite(*value)) {
            fail!("task-query parameter is not finite in float32 transport");
        }
        if tensor.trainable != expected.contains(name) {
            fail!("contextual trainable flags do not match strategy");
        }
        if declared && !allowed.contains(name) {
            fail!("unsupported contextual tensor");
        }
        if declared && expected.contains(name) && tensor.values.len() > limit {
            fail!("contextual tensor exceeds update bound");
        }
    }
    Ok(())
}

fn validate_decision_margin_config(config: &str) -> Result<()> {
    let fields = jsonx::object_of(config).map_err(|_| crate::error::Error("invalid decision-margin configuration".into()))?;
    let labels = match fields.get("sensitivity_labels") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => fail!("invalid decision-margin configuration"),
    };
    let (mut s0, mut alternatives) = (0, 0);
    for label in &labels {
        let Ok(text) = jsonx::required_string(label) else { fail!("decision-margin sensitivity labels must be strings") };
        if text == "S0" {
            s0 += 1;
        } else {
            alternatives += 1;
        }
    }
    if s0 != 1 || alternatives == 0 {
        fail!("decision-margin training requires S0 and non-S0 sensitivity labels");
    }
    let mut threshold = 0.5;
    if let Some(raw) = fields.get("category_threshold") {
        let Ok(value) = jsonx::required_float64(raw) else { fail!("invalid decision-margin category threshold") };
        threshold = value;
    }
    if !threshold.is_finite() || threshold <= 0.0 || threshold >= 1.0 {
        fail!("invalid decision-margin category threshold");
    }
    Ok(())
}

/// `validateTaskQueryConfig`.
pub fn validate_task_query_config(config: &str) -> Result<()> {
    let fields = jsonx::object_of(config)?;
    let mut dimensions: BTreeMap<&str, u32> = BTreeMap::new();
    for name in ["vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads"] {
        let mut value = 1u32;
        if let Some(data) = fields.get(name) {
            if matches!(data, Value::Null) {
                fail!("invalid task-query dimension");
            }
            let Ok(decoded) = jsonx::uint32(Some(data)) else { fail!("invalid task-query dimension") };
            value = decoded;
        } else if name != "num_layers" && name != "num_attention_heads" {
            fail!("missing task-query dimension");
        }
        if value == 0 || value > 65536 {
            fail!("task-query dimension exceeds bounds");
        }
        dimensions.insert(name, value);
    }
    if dimensions["vocab_size"] < 2
        || dimensions["max_tokens"] > 512
        || dimensions["num_layers"] > 512
        || !dimensions["hidden_size"].is_multiple_of(dimensions["num_attention_heads"])
    {
        fail!("invalid task-query capacity or attention heads");
    }
    let labels: [(&str, &[&str]); 3] = [
        ("sensitivity_labels", &["S0", "S1", "S2", "S3"]),
        ("visibility_labels", &["P0", "P1", "P2", "P3", "P4", "PU"]),
        (
            "category_labels",
            &["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"],
        ),
    ];
    for (name, required) in labels {
        let Ok(actual) = jsonx::string_list(fields.get(name)) else { fail!("invalid task-query label inventory") };
        if actual.len() != required.len() {
            fail!("invalid task-query label inventory");
        }
        let mut seen = BTreeSet::new();
        for label in &actual {
            if !seen.insert(label.clone()) {
                fail!("duplicate task-query label");
            }
        }
        for label in required {
            if !seen.contains(*label) {
                fail!("unknown task-query label");
            }
        }
    }
    if let Some(data) = fields.get("category_threshold") {
        let valid = jsonx::required_float64(data).is_ok_and(|value| value.is_finite() && value > 0.0 && value < 1.0);
        if !valid {
            fail!("invalid task-query category threshold");
        }
    }
    Ok(())
}

fn is_lower_hex_64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn declared(metadata: &BTreeMap<String, String>, key: &str) -> bool {
    metadata.contains_key(key)
}

fn value<'a>(metadata: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    metadata.get(key).map_or("", String::as_str)
}

/// `validateContextualFullAdamPolicy`.
pub fn validate_contextual_full_adam_policy(metadata: &BTreeMap<String, String>) -> Result<()> {
    let optimizer = value(metadata, OPTIMIZER_KEY);
    let optimizer_declared = declared(metadata, OPTIMIZER_KEY);
    if optimizer == WINDOW_ADAM {
        if value(metadata, STRATEGY_KEY) != FULL_ENCODER_STRATEGY
            || value(metadata, OBJECTIVE_KEY) != CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE
            || value(metadata, CANDIDATE_ELIGIBILITY_KEY) != WINDOW_ELIGIBILITY
            || value(metadata, WINDOW_CONFIG_KEY) != WINDOW_CONFIG
        {
            fail!("window optimizer requires exact FULL objective, eligibility and frozen configuration");
        }
        for key in [WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY] {
            if !is_lower_hex_64(value(metadata, key)) {
                fail!("window optimizer requires immutable source pins");
            }
        }
        for key in [
            "contextual_training_backtracking_policy",
            "contextual_training_backtracking_preparation",
            "contextual_training_diagnostics_policy",
            FULL_ADAM_CONFIG_KEY,
            RETENTION_MANIFEST_KEY,
        ] {
            if declared(metadata, key) {
                fail!("window optimizer rejects mixed policies");
            }
        }
        return Ok(());
    }
    for key in [WINDOW_CONFIG_KEY, WINDOW_MANIFEST_KEY, COMPONENT_MANIFEST_KEY] {
        if declared(metadata, key) {
            fail!("orphan window optimizer configuration");
        }
    }
    if optimizer == RETENTION_GATE || optimizer == RETENTION_HINGE {
        let objective = if optimizer == RETENTION_HINGE { RETENTION_HINGE_OBJECTIVE } else { RETENTION_GATE_OBJECTIVE };
        if !is_lower_hex_64(value(metadata, RETENTION_MANIFEST_KEY))
            || value(metadata, STRATEGY_KEY) != FULL_ENCODER_STRATEGY
            || value(metadata, OBJECTIVE_KEY) != objective
            || value(metadata, CANDIDATE_ELIGIBILITY_KEY) != RETENTION_ELIGIBILITY
            || value(metadata, FULL_ADAM_CONFIG_KEY) != FULL_ADAM_CONFIG
        {
            fail!("ORIGINAL retention requires exact policy, objective, eligibility, configuration and manifest pin");
        }
        for key in [
            "contextual_training_backtracking_policy",
            "contextual_training_backtracking_preparation",
            "contextual_training_diagnostics_policy",
        ] {
            if declared(metadata, key) {
                fail!("ORIGINAL retention rejects mixed diagnostics/backtracking");
            }
        }
        return Ok(());
    }
    if declared(metadata, RETENTION_MANIFEST_KEY) {
        fail!("orphan ORIGINAL retention artifact pin");
    }
    let objective = value(metadata, OBJECTIVE_KEY);
    if objective == RETENTION_GATE_OBJECTIVE || objective == RETENTION_HINGE_OBJECTIVE {
        fail!("ORIGINAL retention objective requires matching optimizer");
    }
    if optimizer != FULL_ADAM {
        if declared(metadata, CANDIDATE_ELIGIBILITY_KEY) {
            fail!("candidate eligibility requires FULL Adam optimizer");
        }
        if declared(metadata, FULL_ADAM_CONFIG_KEY) {
            fail!("FULL Adam configuration requires its optimizer");
        }
        if objective == CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE && optimizer_declared {
            fail!("summed-category decision-margin optimizer mismatch");
        }
        return Ok(());
    }
    if value(metadata, STRATEGY_KEY) != FULL_ENCODER_STRATEGY
        || value(metadata, OBJECTIVE_KEY) != CLASS_BALANCED_SUM_DECISION_MARGIN_OBJECTIVE
        || value(metadata, CANDIDATE_ELIGIBILITY_KEY) != CANDIDATE_ELIGIBILITY
        || value(metadata, FULL_ADAM_CONFIG_KEY) != FULL_ADAM_CONFIG
    {
        fail!("FULL Adam requires exact full encoder, objective, eligibility and canonical configuration");
    }
    for key in [
        "contextual_training_backtracking_policy",
        "contextual_training_backtracking_preparation",
        "contextual_training_diagnostics_policy",
    ] {
        if declared(metadata, key) {
            fail!("FULL Adam rejects mixed diagnostics/backtracking policy");
        }
    }
    Ok(())
}

/// `validateFullEncoderShapes`.
pub fn validate_full_encoder_shapes(artifact: &ModelArtifact, layers: i64) -> Result<()> {
    let fields: Object = jsonx::object_of(&artifact.config)?;
    let vocab = jsonx::uint32(fields.get("vocab_size"))?;
    let hidden = jsonx::uint32(fields.get("hidden_size"))?;
    let intermediate = jsonx::uint32(fields.get("intermediate_size"))?;
    let context = jsonx::uint32(fields.get("max_tokens"))?;
    let sensitivity = jsonx::string_list(fields.get("sensitivity_labels"))?;
    let visibility = jsonx::string_list(fields.get("visibility_labels"))?;
    let category = jsonx::string_list(fields.get("category_labels"))?;
    if vocab < 2 || hidden == 0 || intermediate == 0 || context == 0 || context > 512 {
        fail!("invalid full encoder dimensions");
    }
    let mut expected: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    expected.insert("token_embedding".into(), vec![vocab, hidden]);
    expected.insert("position_embedding".into(), vec![context, hidden]);
    if contextual_query_readout(&artifact.config)? {
        for task in TASKS {
            expected.insert(format!("readout.{task}.query"), vec![hidden]);
        }
    }
    for (task, labels) in [("sensitivity", &sensitivity), ("visibility", &visibility), ("category", &category)] {
        if labels.is_empty() {
            fail!("full encoder label inventory missing");
        }
        expected.insert(format!("head.{task}.weight"), vec![hidden, labels.len() as u32]);
        expected.insert(format!("head.{task}.bias"), vec![labels.len() as u32]);
    }
    for layer in 0..layers {
        let prefix = layer_prefix(layers, layer);
        for name in ["attention.query.weight", "attention.key.weight", "attention.value.weight", "attention.output.weight"] {
            expected.insert(format!("{prefix}{name}"), vec![hidden, hidden]);
        }
        expected.insert(format!("{prefix}attention.output.bias"), vec![hidden]);
        expected.insert(format!("{prefix}ffn.input.weight"), vec![hidden, intermediate]);
        expected.insert(format!("{prefix}ffn.input.bias"), vec![intermediate]);
        expected.insert(format!("{prefix}ffn.output.weight"), vec![intermediate, hidden]);
        expected.insert(format!("{prefix}ffn.output.bias"), vec![hidden]);
    }
    if artifact.parameters.len() != expected.len() {
        fail!("full encoder inventory mismatch");
    }
    for (name, shape) in &expected {
        let actual = artifact.parameters.get(name).map(|tensor: &Tensor| tensor.shape.as_slice());
        if actual != Some(shape.as_slice()) {
            fail!("full encoder shape mismatch: {name}");
        }
    }
    Ok(())
}
