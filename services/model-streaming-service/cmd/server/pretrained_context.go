package main

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
)

const pretrainedContextArchitecture = "privoke_pretrained_context_v1"
const pretrainedContextModelID = "privoke-pretrained-context-minilm"
const pretrainedBackboneHash = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452"
const pretrainedTokenizerHash = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"

var pretrainedVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)

type pretrainedContextConfig struct {
	Task              string   `json:"task"`
	BackboneModelID   string   `json:"backbone_model_id"`
	BackboneRevision  string   `json:"backbone_revision"`
	BackboneSHA256    string   `json:"backbone_sha256"`
	TokenizerSHA256   string   `json:"tokenizer_sha256"`
	HiddenSize        int      `json:"hidden_size"`
	MaxTokens         int      `json:"max_tokens"`
	Pooling           string   `json:"pooling"`
	Normalization     string   `json:"normalization"`
	CategorySemantics string   `json:"category_semantics"`
	Arithmetic        string   `json:"arithmetic"`
	SensitivityLabels []string `json:"sensitivity_labels"`
	VisibilityLabels  []string `json:"visibility_labels"`
	CategoryLabels    []string `json:"category_labels"`
	CategoryThreshold float64  `json:"category_threshold"`
}

var pretrainedLabels = map[string][]string{
	"sensitivity": {"S0", "S1", "S2", "S3"},
	"visibility":  {"P0", "P1", "P2", "P3", "P4", "PU"},
	"category":    {"HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"},
}

func validatePretrainedContextArtifact(artifact *modelArtifact) error {
	if artifact.Architecture != pretrainedContextArchitecture || artifact.ModelID != pretrainedContextModelID {
		return fmt.Errorf("pretrained contextual architecture/model ID mismatch")
	}
	if !pretrainedVersion.MatchString(artifact.Version) {
		return fmt.Errorf("pretrained contextual version is invalid")
	}
	if err := exactJSONFields(artifact.Config, "task", "backbone_model_id", "backbone_revision", "backbone_sha256", "tokenizer_sha256", "hidden_size", "max_tokens", "pooling", "normalization", "category_semantics", "arithmetic", "sensitivity_labels", "visibility_labels", "category_labels", "category_threshold"); err != nil {
		return err
	}
	var config pretrainedContextConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		return fmt.Errorf("invalid pretrained contextual config: %w", err)
	}
	if config.Task != "contextual_privacy" || config.BackboneModelID != "sentence-transformers/all-MiniLM-L6-v2" || config.BackboneRevision != "1110a243fdf4706b3f48f1d95db1a4f5529b4d41" || config.BackboneSHA256 != pretrainedBackboneHash || config.TokenizerSHA256 != pretrainedTokenizerHash || config.HiddenSize != 384 || config.MaxTokens != 256 || config.Pooling != "masked_mean_l2_v1" || config.Normalization != "detector_normalize_text_v1" || config.CategorySemantics != "asserted_personal_disclosure_v1" || config.Arithmetic != "float32_onnx_numpy_heads_v1" {
		return fmt.Errorf("pretrained contextual encoder contract mismatch")
	}
	if !reflect.DeepEqual(config.SensitivityLabels, pretrainedLabels["sensitivity"]) || !reflect.DeepEqual(config.VisibilityLabels, pretrainedLabels["visibility"]) || !reflect.DeepEqual(config.CategoryLabels, pretrainedLabels["category"]) {
		return fmt.Errorf("pretrained contextual label order mismatch")
	}
	if math.IsNaN(config.CategoryThreshold) || math.IsInf(config.CategoryThreshold, 0) || config.CategoryThreshold <= 0 || config.CategoryThreshold >= 1 {
		return fmt.Errorf("pretrained contextual category threshold is invalid")
	}
	if len(artifact.Parameters) != 6 {
		return fmt.Errorf("pretrained contextual model requires exactly six head tensors")
	}
	for task, labels := range pretrainedLabels {
		for _, part := range []string{"weight", "bias"} {
			shape := []uint32{uint32(len(labels))}
			if part == "weight" {
				shape = []uint32{384, uint32(len(labels))}
			}
			tensor, ok := artifact.Parameters["head."+task+"."+part]
			if !ok || !reflect.DeepEqual(tensor.Shape, shape) || tensor.Trainable {
				return fmt.Errorf("pretrained contextual head shape/scope mismatch")
			}
			for _, value := range tensor.Values {
				if math.IsInf(float64(float32(value)), 0) || math.IsNaN(value) {
					return fmt.Errorf("pretrained contextual head is outside finite float32 range")
				}
			}
		}
	}
	if artifact.Metadata == nil {
		return fmt.Errorf("pretrained contextual metadata must be an object")
	}
	return nil
}
