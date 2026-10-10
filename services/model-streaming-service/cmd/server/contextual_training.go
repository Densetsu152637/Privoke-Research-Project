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

var contextualBlockNames = []string{
	"attention.query.weight", "attention.key.weight", "attention.value.weight",
	"attention.output.weight", "attention.output.bias", "ffn.input.weight",
	"ffn.input.bias", "ffn.output.weight", "ffn.output.bias",
}

func contextualTrainableNames(config json.RawMessage, strategy string) (map[string]bool, int, error) {
	expected := map[string]bool{}
	for _, head := range []string{"sensitivity", "visibility", "category"} {
		for _, part := range []string{"weight", "bias"} {
			expected["head."+head+"."+part] = true
		}
	}
	if strategy == "" {
		return expected, 1, nil
	}
	if strategy != contextualLastBlockStrategy && strategy != contextualFullEncoderStrategy {
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
	if optimizer, declared := artifact.Metadata[contextualOptimizerKey]; declared && optimizer != contextualLocalSGD1 && optimizer != contextualLocalSGD4 {
		return fmt.Errorf("unsupported contextual training optimizer")
	}
	if objective, declared := artifact.Metadata[contextualObjectiveKey]; declared && objective != contextualClassBalancedObjective && objective != contextualClassBalancedMeanCategoryObjective && objective != contextualClassBalancedDecisionMarginObjective {
		return fmt.Errorf("unsupported contextual training objective")
	}
	if artifact.Metadata[contextualObjectiveKey] == contextualClassBalancedDecisionMarginObjective {
		var config struct {
			SensitivityLabels []string `json:"sensitivity_labels"`
		}
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			return fmt.Errorf("invalid decision-margin configuration")
		}
		s0, alternatives := 0, 0
		for _, label := range config.SensitivityLabels {
			if label == "S0" {
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
	if strategy == contextualFullEncoderStrategy {
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
