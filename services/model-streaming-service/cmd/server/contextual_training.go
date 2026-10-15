package main

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
)

const contextualStrategyKey = "contextual_training_strategy"
const contextualLastBlockStrategy = "contextual_last_block_sgd_v1"
const contextualFullEncoderStrategy = "contextual_full_encoder_sgd_v1"
const contextualOptimizerKey = "contextual_training_optimizer"
const contextualLocalSGD1 = "local_sgd_1_v1"
const contextualLocalSGD4 = "local_sgd_4_v1"
const contextualObjectiveKey = "contextual_training_objective"
const contextualClassBalancedObjective = "class_balanced_contextual_v1"
const contextualClassBalancedMeanCategoryObjective = "class_balanced_contextual_mean_category_v1"
const contextualClassBalancedDecisionMarginObjective = "class_balanced_contextual_decision_margin_v1"
const contextualClassBalancedSumDecisionMarginObjective = "class_balanced_contextual_sum_category_decision_margin_v1"
const contextualFullAdam = "full_projected_adam64_v1"
const contextualCandidateEligibilityKey = "contextual_candidate_eligibility"
const contextualCandidateEligibility = "candidate_train_exact_eligibility_v1"
const contextualFullAdamConfigKey = "full_projected_adam_config_v1"
const contextualRetentionGate = "full_projected_adam64_original_train_gate_v1"
const contextualRetentionHinge = "full_projected_adam64_original_train_hinge_v1"
const contextualRetentionGateObjective = "class_balanced_contextual_sum_margin_original_gate_v1"
const contextualRetentionHingeObjective = "class_balanced_contextual_sum_margin_original_hinge_v1"
const contextualRetentionEligibility = "candidate_train_exact_original_target_capped_v1"
const contextualRetentionManifestKey = "original_train_retention_manifest_sha256"
const contextualWindowAdam = "full_projected_adam64_window_checkpoint_v1"
const contextualWindowEligibility = "candidate_window_exact_component_retention_v1"
const contextualWindowConfigKey = "train_window_config_v1"
const contextualWindowManifestKey = "train_window_manifest_sha256"
const contextualComponentManifestKey = "original_train_component_manifest_sha256"
const contextualWindowConfig = `{"adam":{"beta1":0.9,"beta2":0.999,"cpu_threads":1,"delta_cap":0.05,"device":"cpu","epsilon":1e-08,"eta":0.003,"gradient_denominator":1,"margin_coefficient":1,"microbatch_size":32,"moment_dtype":"float64","steps":64},"auxiliary_coefficient":1,"block_rows":64,"blocks":8,"candidate_seeds":64,"checkpoints":[8,16,24,32,40,48,56,64],"component_order":["sensitivity","severity","category","visibility","action"],"epochs":8,"epsilon":1e-06,"main_normalization":"eight_times_block_over_frozen_window_weight_v1","margin_cap":1.0,"normalization":"category_bits_then_components_then_rows_v1","selector":"transported_train_component_rank_v1"}`

// Exact Python canonical(CONFIG): lexical equality binds the supported version,
// including numeric representation, key inventory and process-thread contract.
const contextualFullAdamConfig = `{"beta1":0.9,"beta2":0.999,"cpu_threads":1,"delta_cap":0.05,"device":"cpu","epsilon":1e-08,"eta":0.003,"gradient_denominator":1,"margin_coefficient":1,"microbatch_size":32,"moment_dtype":"float64","steps":64}`

var contextualBlockNames = []string{
	"attention.query.weight", "attention.key.weight", "attention.value.weight",
	"attention.output.weight", "attention.output.bias", "ffn.input.weight",
	"ffn.input.bias", "ffn.output.weight", "ffn.output.bias",
}

const taskQueryReadout = "residual_task_query_v1"

func contextualQueryReadout(config json.RawMessage) (bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(config, &fields); err != nil {
		return false, err
	}
	raw, present := fields["readout"]
	if !present {
		return false, nil
	}
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return false, fmt.Errorf("invalid Tiny readout")
	}
	if *value == taskQueryReadout {
		return true, nil
	}
	if *value == "legacy_pool_v1" {
		return false, nil
	}
	return false, fmt.Errorf("unsupported Tiny readout")
}

func contextualTrainableNames(config json.RawMessage, strategy string) (map[string]bool, int, error) {
	expected := map[string]bool{}
	for _, head := range []string{"sensitivity", "visibility", "category"} {
		for _, part := range []string{"weight", "bias"} {
			expected["head."+head+"."+part] = true
		}
	}
	queryReadout, err := contextualQueryReadout(config)
	if err != nil {
		return nil, 0, err
	}
	if queryReadout {
		for _, task := range []string{"sensitivity", "visibility", "category"} {
			expected["readout."+task+".query"] = true
		}
	}
	if strategy != "" && strategy != contextualLastBlockStrategy && strategy != contextualFullEncoderStrategy {
		return nil, 0, fmt.Errorf("unsupported contextual training strategy")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(config, &fields); err != nil {
		return nil, 0, fmt.Errorf("invalid contextual configuration")
	}
	layers := 1
	if raw, ok := fields["num_layers"]; ok {
		layers = 0
		if err := json.Unmarshal(raw, &layers); err != nil {
			return nil, 0, fmt.Errorf("invalid contextual encoder layer count")
		}
	}
	if layers < 1 || layers > 512 {
		return nil, 0, fmt.Errorf("invalid contextual encoder layer count")
	}
	if strategy == "" {
		return expected, layers, nil
	}
	if strategy == contextualFullEncoderStrategy {
		expected["token_embedding"] = true
		expected["position_embedding"] = true
		for layer := 0; layer < layers; layer++ {
			prefix := ""
			if layers > 1 {
				prefix = fmt.Sprintf("layers.%d.", layer)
			}
			for _, name := range contextualBlockNames {
				expected[prefix+name] = true
			}
		}
		return expected, layers, nil
	}
	prefix := ""
	if layers > 1 {
		prefix = fmt.Sprintf("layers.%d.", layers-1)
	}
	for _, name := range contextualBlockNames {
		expected[prefix+name] = true
	}
	return expected, layers, nil
}

func validateContextualTrainingArtifact(artifact *modelArtifact) error {
	queryReadout, err := contextualQueryReadout(artifact.Config)
	if err != nil {
		return err
	}
	if queryReadout != (artifact.Architecture == taskQueryArchitecture) {
		return fmt.Errorf("Tiny architecture and readout disagree")
	}
	if queryReadout {
		if err := validateTaskQueryConfig(artifact.Config); err != nil {
			return err
		}
	}
	if !queryReadout {
		for _, task := range []string{"sensitivity", "visibility", "category"} {
			if _, present := artifact.Parameters["readout."+task+".query"]; present {
				return fmt.Errorf("legacy Tiny cannot contain query readouts")
			}
		}
	}
	if err := validateContextualFullAdamPolicy(artifact.Metadata); err != nil {
		return err
	}
	if optimizer, declared := artifact.Metadata[contextualOptimizerKey]; declared && optimizer != contextualLocalSGD1 && optimizer != contextualLocalSGD4 && optimizer != contextualFullAdam && optimizer != contextualRetentionGate && optimizer != contextualRetentionHinge && optimizer != contextualWindowAdam {
		return fmt.Errorf("unsupported contextual training optimizer")
	}
	if objective, declared := artifact.Metadata[contextualObjectiveKey]; declared && objective != contextualClassBalancedObjective && objective != contextualClassBalancedMeanCategoryObjective && objective != contextualClassBalancedDecisionMarginObjective && objective != contextualClassBalancedSumDecisionMarginObjective && objective != contextualRetentionGateObjective && objective != contextualRetentionHingeObjective {
		return fmt.Errorf("unsupported contextual training objective")
	}
	if objective := artifact.Metadata[contextualObjectiveKey]; objective == contextualClassBalancedDecisionMarginObjective || objective == contextualClassBalancedSumDecisionMarginObjective || objective == contextualRetentionGateObjective || objective == contextualRetentionHingeObjective {
		var config struct {
			SensitivityLabels []json.RawMessage `json:"sensitivity_labels"`
		}
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			return fmt.Errorf("invalid decision-margin configuration")
		}
		s0, alternatives := 0, 0
		for _, rawLabel := range config.SensitivityLabels {
			var label *string
			if err := json.Unmarshal(rawLabel, &label); err != nil || label == nil {
				return fmt.Errorf("decision-margin sensitivity labels must be strings")
			}
			if *label == "S0" {
				s0++
			} else {
				alternatives++
			}
		}
		if s0 != 1 || alternatives == 0 {
			return fmt.Errorf("decision-margin training requires S0 and non-S0 sensitivity labels")
		}
		threshold := 0.5
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(artifact.Config, &fields); err != nil {
			return fmt.Errorf("invalid decision-margin configuration")
		}
		if raw, present := fields["category_threshold"]; present {
			var value *float64
			if err := json.Unmarshal(raw, &value); err != nil || value == nil {
				return fmt.Errorf("invalid decision-margin category threshold")
			}
			threshold = *value
		}
		if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0 || threshold >= 1 {
			return fmt.Errorf("invalid decision-margin category threshold")
		}
	}
	strategy, declared := artifact.Metadata[contextualStrategyKey]
	if declared && strategy == "" {
		return fmt.Errorf("contextual training strategy must be nonempty")
	}
	expected, layers, err := contextualTrainableNames(artifact.Config, strategy)
	if err != nil {
		return err
	}
	if strategy == contextualFullEncoderStrategy || queryReadout {
		if err := validateFullEncoderShapes(artifact, layers); err != nil {
			return err
		}
	}
	for name := range expected {
		if _, ok := artifact.Parameters[name]; !ok {
			return fmt.Errorf("contextual training tensor manifest incomplete")
		}
	}
	allowed := map[string]bool{"token_embedding": true, "position_embedding": true}
	for name := range expected {
		allowed[name] = true
	}
	if declared {
		for layer := 0; layer < layers; layer++ {
			prefix := ""
			if layers > 1 {
				prefix = fmt.Sprintf("layers.%d.", layer)
			}
			for _, name := range contextualBlockNames {
				allowed[prefix+name] = true
			}
		}
		if len(artifact.Parameters) != len(allowed) {
			return fmt.Errorf("contextual adapted tensor manifest is not exact")
		}
	}
	for name, tensor := range artifact.Parameters {
		if queryReadout {
			for _, value := range tensor.Values {
				if math.IsInf(float64(float32(value)), 0) {
					return fmt.Errorf("task-query parameter is not finite in float32 transport")
				}
			}
		}
		if tensor.Trainable != expected[name] {
			return fmt.Errorf("contextual trainable flags do not match strategy")
		}
		if declared && !allowed[name] {
			return fmt.Errorf("unsupported contextual tensor")
		}
		limit := 4096
		if strategy == contextualFullEncoderStrategy {
			limit = 24576
		}
		if declared && expected[name] && len(tensor.Values) > limit {
			return fmt.Errorf("contextual tensor exceeds update bound")
		}
	}
	return nil
}

func validateTaskQueryConfig(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	dimensions := map[string]uint32{}
	for _, name := range []string{"vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads"} {
		value := uint32(1)
		if data, ok := fields[name]; ok {
			var decoded *uint32
			if err := json.Unmarshal(data, &decoded); err != nil || decoded == nil {
				return fmt.Errorf("invalid task-query dimension")
			}
			value = *decoded
		} else if name != "num_layers" && name != "num_attention_heads" {
			return fmt.Errorf("missing task-query dimension")
		}
		if value == 0 || value > 65536 {
			return fmt.Errorf("task-query dimension exceeds bounds")
		}
		dimensions[name] = value
	}
	if dimensions["vocab_size"] < 2 || dimensions["max_tokens"] > 512 || dimensions["num_layers"] > 512 || dimensions["hidden_size"]%dimensions["num_attention_heads"] != 0 {
		return fmt.Errorf("invalid task-query capacity or attention heads")
	}
	labels := map[string][]string{
		"sensitivity_labels": {"S0", "S1", "S2", "S3"},
		"visibility_labels":  {"P0", "P1", "P2", "P3", "P4", "PU"},
		"category_labels":    {"HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"},
	}
	for name, required := range labels {
		var actual []string
		if err := json.Unmarshal(fields[name], &actual); err != nil || len(actual) != len(required) {
			return fmt.Errorf("invalid task-query label inventory")
		}
		seen := map[string]bool{}
		for _, label := range actual {
			if seen[label] {
				return fmt.Errorf("duplicate task-query label")
			}
			seen[label] = true
		}
		for _, label := range required {
			if !seen[label] {
				return fmt.Errorf("unknown task-query label")
			}
		}
	}
	if data, ok := fields["category_threshold"]; ok {
		var threshold *float64
		if err := json.Unmarshal(data, &threshold); err != nil || threshold == nil || math.IsNaN(*threshold) || math.IsInf(*threshold, 0) || *threshold <= 0 || *threshold >= 1 {
			return fmt.Errorf("invalid task-query category threshold")
		}
	}
	return nil
}

func validateContextualFullAdamPolicy(metadata map[string]string) error {
	optimizer, declared := metadata[contextualOptimizerKey]
	if optimizer == contextualWindowAdam {
		if metadata[contextualStrategyKey] != contextualFullEncoderStrategy || metadata[contextualObjectiveKey] != contextualClassBalancedSumDecisionMarginObjective || metadata[contextualCandidateEligibilityKey] != contextualWindowEligibility || metadata[contextualWindowConfigKey] != contextualWindowConfig {
			return fmt.Errorf("window optimizer requires exact FULL objective, eligibility and frozen configuration")
		}
		for _, key := range []string{contextualWindowManifestKey, contextualComponentManifestKey} {
			pin := metadata[key]
			valid := len(pin) == 64
			for _, c := range pin {
				valid = valid && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
			}
			if !valid {
				return fmt.Errorf("window optimizer requires immutable source pins")
			}
		}
		for _, key := range []string{"contextual_training_backtracking_policy", "contextual_training_backtracking_preparation", "contextual_training_diagnostics_policy", contextualFullAdamConfigKey, contextualRetentionManifestKey} {
			if _, present := metadata[key]; present {
				return fmt.Errorf("window optimizer rejects mixed policies")
			}
		}
		return nil
	}
	for _, key := range []string{contextualWindowConfigKey, contextualWindowManifestKey, contextualComponentManifestKey} {
		if _, present := metadata[key]; present {
			return fmt.Errorf("orphan window optimizer configuration")
		}
	}
	if optimizer == contextualRetentionGate || optimizer == contextualRetentionHinge {
		objective := contextualRetentionGateObjective
		if optimizer == contextualRetentionHinge {
			objective = contextualRetentionHingeObjective
		}
		pin := metadata[contextualRetentionManifestKey]
		validPin := len(pin) == 64
		for _, c := range pin {
			validPin = validPin && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		}
		if !validPin || metadata[contextualStrategyKey] != contextualFullEncoderStrategy || metadata[contextualObjectiveKey] != objective || metadata[contextualCandidateEligibilityKey] != contextualRetentionEligibility || metadata[contextualFullAdamConfigKey] != contextualFullAdamConfig {
			return fmt.Errorf("ORIGINAL retention requires exact policy, objective, eligibility, configuration and manifest pin")
		}
		for _, key := range []string{"contextual_training_backtracking_policy", "contextual_training_backtracking_preparation", "contextual_training_diagnostics_policy"} {
			if _, present := metadata[key]; present {
				return fmt.Errorf("ORIGINAL retention rejects mixed diagnostics/backtracking")
			}
		}
		return nil
	}
	if _, present := metadata[contextualRetentionManifestKey]; present {
		return fmt.Errorf("orphan ORIGINAL retention artifact pin")
	}
	if metadata[contextualObjectiveKey] == contextualRetentionGateObjective || metadata[contextualObjectiveKey] == contextualRetentionHingeObjective {
		return fmt.Errorf("ORIGINAL retention objective requires matching optimizer")
	}
	if optimizer != contextualFullAdam {
		if _, present := metadata[contextualCandidateEligibilityKey]; present {
			return fmt.Errorf("candidate eligibility requires FULL Adam optimizer")
		}
		if _, present := metadata[contextualFullAdamConfigKey]; present {
			return fmt.Errorf("FULL Adam configuration requires its optimizer")
		}
		if metadata[contextualObjectiveKey] == contextualClassBalancedSumDecisionMarginObjective && declared {
			return fmt.Errorf("summed-category decision-margin optimizer mismatch")
		}
		return nil
	}
	if metadata[contextualStrategyKey] != contextualFullEncoderStrategy ||
		metadata[contextualObjectiveKey] != contextualClassBalancedSumDecisionMarginObjective ||
		metadata[contextualCandidateEligibilityKey] != contextualCandidateEligibility ||
		metadata[contextualFullAdamConfigKey] != contextualFullAdamConfig {
		return fmt.Errorf("FULL Adam requires exact full encoder, objective, eligibility and canonical configuration")
	}
	for _, key := range []string{"contextual_training_backtracking_policy", "contextual_training_backtracking_preparation", "contextual_training_diagnostics_policy"} {
		if _, present := metadata[key]; present {
			return fmt.Errorf("FULL Adam rejects mixed diagnostics/backtracking policy")
		}
	}
	return nil
}

func validateFullEncoderShapes(artifact *modelArtifact, layers int) error {
	var config struct {
		Vocab        uint32   `json:"vocab_size"`
		Hidden       uint32   `json:"hidden_size"`
		Intermediate uint32   `json:"intermediate_size"`
		Context      uint32   `json:"max_tokens"`
		Sensitivity  []string `json:"sensitivity_labels"`
		Visibility   []string `json:"visibility_labels"`
		Category     []string `json:"category_labels"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		return err
	}
	if config.Vocab < 2 || config.Hidden == 0 || config.Intermediate == 0 || config.Context == 0 || config.Context > 512 {
		return fmt.Errorf("invalid full encoder dimensions")
	}
	expected := map[string][]uint32{"token_embedding": {config.Vocab, config.Hidden}, "position_embedding": {config.Context, config.Hidden}}
	queryReadout, err := contextualQueryReadout(artifact.Config)
	if err != nil {
		return err
	}
	if queryReadout {
		for _, task := range []string{"sensitivity", "visibility", "category"} {
			expected["readout."+task+".query"] = []uint32{config.Hidden}
		}
	}
	for task, labels := range map[string][]string{"sensitivity": config.Sensitivity, "visibility": config.Visibility, "category": config.Category} {
		if len(labels) == 0 {
			return fmt.Errorf("full encoder label inventory missing")
		}
		expected["head."+task+".weight"] = []uint32{config.Hidden, uint32(len(labels))}
		expected["head."+task+".bias"] = []uint32{uint32(len(labels))}
	}
	for layer := 0; layer < layers; layer++ {
		prefix := ""
		if layers > 1 {
			prefix = fmt.Sprintf("layers.%d.", layer)
		}
		for _, name := range []string{"attention.query.weight", "attention.key.weight", "attention.value.weight", "attention.output.weight"} {
			expected[prefix+name] = []uint32{config.Hidden, config.Hidden}
		}
		expected[prefix+"attention.output.bias"] = []uint32{config.Hidden}
		expected[prefix+"ffn.input.weight"] = []uint32{config.Hidden, config.Intermediate}
		expected[prefix+"ffn.input.bias"] = []uint32{config.Intermediate}
		expected[prefix+"ffn.output.weight"] = []uint32{config.Intermediate, config.Hidden}
		expected[prefix+"ffn.output.bias"] = []uint32{config.Hidden}
	}
	if len(artifact.Parameters) != len(expected) {
		return fmt.Errorf("full encoder inventory mismatch")
	}
	for name, shape := range expected {
		if !reflect.DeepEqual(artifact.Parameters[name].Shape, shape) {
			return fmt.Errorf("full encoder shape mismatch: %s", name)
		}
	}
	return nil
}
