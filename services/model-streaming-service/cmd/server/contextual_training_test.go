package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func contextualFixture(t *testing.T) modelArtifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "contextual-last-block.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadModelArtifactBytes(raw, "contextual-training-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return loaded.modelArtifact
}

func TestContextualSharedFixtureTrainabilityAndMetadata(t *testing.T) {
	artifact := contextualFixture(t)
	parameters, names := parameterMessages(artifact.Parameters)
	if len(names) != 15 || len(parameters) != 26 {
		t.Fatal("incorrect adapted manifest")
	}
	metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
	if metadata[contextualStrategyKey] != contextualLastBlockStrategy {
		t.Fatal("training strategy not streamed")
	}
	if artifact.Parameters["token_embedding"].Trainable || artifact.Parameters["layers.0.ffn.input.weight"].Trainable {
		t.Fatal("frozen representation tensors became trainable")
	}
}

func TestFullEncoderProfilesAdmitEmbeddingsAndRejectFrozenOrWrongScope(t *testing.T) {
	for _, profile := range []string{"baseline", "efficient", "balanced", "quality"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "models", "privoke-"+profile+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var artifact modelArtifact
		if err := json.Unmarshal(raw, &artifact); err != nil {
			t.Fatal(err)
		}
		artifact.Metadata[contextualStrategyKey] = contextualFullEncoderStrategy
		for name, tensor := range artifact.Parameters {
			tensor.Trainable = true
			artifact.Parameters[name] = tensor
		}
		if err := validateModelArtifact(&artifact, ""); err != nil {
			t.Fatalf("full profile %s rejected: %v", profile, err)
		}
		parameters, names := parameterMessages(artifact.Parameters)
		if len(parameters) != len(names) {
			t.Fatal("full tensor trainability lost during transport")
		}
		artifact.Metadata[contextualStrategyKey] = contextualLastBlockStrategy
		if err := validateModelArtifact(&artifact, ""); err == nil {
			t.Fatal("legacy strategy accepted full trainability")
		}
		artifact.Metadata[contextualStrategyKey] = contextualFullEncoderStrategy
		tensor := artifact.Parameters["token_embedding"]
		originalShape := tensor.Shape
		tensor.Shape = []uint32{1, uint32(len(tensor.Values))}
		artifact.Parameters["token_embedding"] = tensor
		if err := validateModelArtifact(&artifact, ""); err == nil {
			t.Fatal("full strategy accepted incorrect embedding dimensions")
		}
		tensor.Shape = originalShape
		tensor.Trainable = false
		artifact.Parameters["token_embedding"] = tensor
		if err := validateModelArtifact(&artifact, ""); err == nil {
			t.Fatal("full strategy accepted frozen embedding")
		}
	}
}

func TestContextualStrategyAndManifestRejectInvalid(t *testing.T) {
	mutations := map[string]func(*modelArtifact){
		"unknown strategy": func(a *modelArtifact) { a.Metadata[contextualStrategyKey] = "unknown" },
		"empty strategy":   func(a *modelArtifact) { a.Metadata[contextualStrategyKey] = "" },
		"missing strategy": func(a *modelArtifact) { delete(a.Metadata, contextualStrategyKey) },
		"missing block":    func(a *modelArtifact) { delete(a.Parameters, "layers.1.ffn.input.weight") },
		"trainable embedding": func(a *modelArtifact) {
			p := a.Parameters["token_embedding"]
			p.Trainable = true
			a.Parameters["token_embedding"] = p
		},
		"trainable earlier block": func(a *modelArtifact) {
			p := a.Parameters["layers.0.ffn.input.weight"]
			p.Trainable = true
			a.Parameters["layers.0.ffn.input.weight"] = p
		},
		"frozen unsupported": func(a *modelArtifact) {
			a.Parameters["unsupported"] = artifactTensor{Shape: []uint32{1}, Values: []float64{0}}
		},
		"oversized update": func(a *modelArtifact) {
			a.Parameters["layers.1.ffn.input.weight"] = artifactTensor{Shape: []uint32{4097}, Values: make([]float64, 4097), Trainable: true}
		},
		"null layers": func(a *modelArtifact) { a.Config = json.RawMessage(`{"num_layers":null}`) },
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			artifact := contextualFixture(t)
			mutation(&artifact)
			if err := validateModelArtifact(&artifact, ""); err == nil {
				t.Fatal("invalid contextual contract accepted")
			}
		})
	}
}

func TestContextualRawFlagsRequireBoolean(t *testing.T) {
	for _, value := range []any{nil, "true", 1} {
		artifact := contextualFixture(t)
		raw, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		tensor := payload["parameters"].(map[string]any)["head.category.bias"].(map[string]any)
		tensor["trainable"] = value
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePresenceRawTensorFlags(raw); err == nil {
			t.Fatal("invalid flag accepted")
		}
		delete(tensor, "trainable")
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePresenceRawTensorFlags(raw); err == nil {
			t.Fatal("missing flag accepted")
		}
	}
}

func TestContextualObjectiveIndependentOfTrainingStrategy(t *testing.T) {
	for _, adapted := range []bool{false, true} {
		artifact := contextualFixture(t)
		if !adapted {
			delete(artifact.Metadata, contextualStrategyKey)
			for name, tensor := range artifact.Parameters {
				tensor.Trainable = false
				for _, head := range []string{"sensitivity", "visibility", "category"} {
					if name == "head."+head+".weight" || name == "head."+head+".bias" {
						tensor.Trainable = true
					}
				}
				artifact.Parameters[name] = tensor
			}
		}
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedObjective
		if err := validateModelArtifact(&artifact, ""); err != nil {
			t.Fatal(err)
		}
		_, names := parameterMessages(artifact.Parameters)
		metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
		if metadata[contextualObjectiveKey] != contextualClassBalancedObjective {
			t.Fatal("objective not streamed")
		}
		for _, invalid := range []string{"", "unknown"} {
			artifact.Metadata[contextualObjectiveKey] = invalid
			if err := validateModelArtifact(&artifact, ""); err == nil {
				t.Fatal("unsupported objective accepted")
			}
		}
		delete(artifact.Metadata, contextualObjectiveKey)
		if err := validateModelArtifact(&artifact, ""); err != nil {
			t.Fatal("legacy objective rejected", err)
		}
	}
}

func TestContextualRawObjectiveTypesRejected(t *testing.T) {
	for _, value := range []any{nil, true, 1, []any{}, map[string]any{}} {
		artifact := contextualFixture(t)
		raw, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		payload["metadata"].(map[string]any)[contextualObjectiveKey] = value
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var typed modelArtifact
		if err := json.Unmarshal(raw, &typed); err == nil {
			// JSON null becomes an empty string in a string map, which must fail validation.
			if err := validateModelArtifact(&typed, ""); err == nil {
				t.Fatal("invalid objective type accepted")
			}
		}
	}
}

func TestContextualMeanCategoryObjectivePreservesManifestAndStreams(t *testing.T) {
	for _, adapted := range []bool{false, true} {
		artifact := contextualFixture(t)
		if !adapted {
			delete(artifact.Metadata, contextualStrategyKey)
			for name, tensor := range artifact.Parameters {
				tensor.Trainable = false
				for _, head := range []string{"sensitivity", "visibility", "category"} {
					if name == "head."+head+".weight" || name == "head."+head+".bias" {
						tensor.Trainable = true
					}
				}
				artifact.Parameters[name] = tensor
			}
		}
		_, before := parameterMessages(artifact.Parameters)
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedMeanCategoryObjective
		if err := validateModelArtifact(&artifact, ""); err != nil {
			t.Fatal(err)
		}
		_, names := parameterMessages(artifact.Parameters)
		if len(before) != len(names) {
			t.Fatal("objective changed trainability")
		}
		metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
		if metadata[contextualObjectiveKey] != contextualClassBalancedMeanCategoryObjective {
			t.Fatal("mean-category objective not streamed")
		}
	}
}

func TestContextualOptimizerIndependentAndStreamed(t *testing.T) {
	for _, adapted := range []bool{false, true} {
		for _, objective := range []string{"", contextualClassBalancedObjective, contextualClassBalancedMeanCategoryObjective} {
			for _, optimizer := range []string{contextualLocalSGD1, contextualLocalSGD4} {
				artifact := contextualFixture(t)
				if !adapted {
					delete(artifact.Metadata, contextualStrategyKey)
					for name, tensor := range artifact.Parameters {
						tensor.Trainable = false
						for _, head := range []string{"sensitivity", "visibility", "category"} {
							if name == "head."+head+".weight" || name == "head."+head+".bias" {
								tensor.Trainable = true
							}
						}
						artifact.Parameters[name] = tensor
					}
				}
				if objective != "" {
					artifact.Metadata[contextualObjectiveKey] = objective
				}
				artifact.Metadata[contextualOptimizerKey] = optimizer
				if err := validateModelArtifact(&artifact, ""); err != nil {
					t.Fatal(err)
				}
				_, names := parameterMessages(artifact.Parameters)
				metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
				if metadata[contextualOptimizerKey] != optimizer {
					t.Fatal("optimizer not streamed")
				}
				for _, invalid := range []string{"", "unknown", "local_sgd_2_v1"} {
					artifact.Metadata[contextualOptimizerKey] = invalid
					if err := validateModelArtifact(&artifact, ""); err == nil {
						t.Fatal("unsupported optimizer accepted")
					}
				}
				delete(artifact.Metadata, contextualOptimizerKey)
				if err := validateModelArtifact(&artifact, ""); err != nil {
					t.Fatal("legacy optimizer rejected", err)
				}
			}
		}
	}
}

func TestContextualRawOptimizerTypesRejected(t *testing.T) {
	for _, value := range []any{nil, true, 1, []any{}, map[string]any{}} {
		artifact := contextualFixture(t)
		raw, err := json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		payload["metadata"].(map[string]any)[contextualOptimizerKey] = value
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var typed modelArtifact
		if err := json.Unmarshal(raw, &typed); err == nil {
			// JSON null becomes an empty string; the optimizer validator must reject it.
			if err := validateModelArtifact(&typed, ""); err == nil {
				t.Fatal("invalid optimizer type accepted")
			}
		}
	}
}

func TestContextualDecisionMarginObjectivePreservesManifestAndStreams(t *testing.T) {
	for _, adapted := range []bool{false, true} {
		artifact := contextualFixture(t)
		if !adapted {
			delete(artifact.Metadata, contextualStrategyKey)
			for name, tensor := range artifact.Parameters {
				tensor.Trainable = false
				for _, head := range []string{"sensitivity", "visibility", "category"} {
					if name == "head."+head+".weight" || name == "head."+head+".bias" {
						tensor.Trainable = true
					}
				}
				artifact.Parameters[name] = tensor
			}
		}
		_, before := parameterMessages(artifact.Parameters)
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedDecisionMarginObjective
		for _, optimizer := range []string{"", contextualLocalSGD1, contextualLocalSGD4} {
			if optimizer != "" {
				artifact.Metadata[contextualOptimizerKey] = optimizer
			}
			if err := validateModelArtifact(&artifact, ""); err != nil {
				t.Fatal(err)
			}
			_, names := parameterMessages(artifact.Parameters)
			if len(before) != len(names) {
				t.Fatal("objective changed manifest")
			}
			metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
			if metadata[contextualObjectiveKey] != contextualClassBalancedDecisionMarginObjective {
				t.Fatal("objective not streamed")
			}
		}
	}
}

func TestContextualDecisionMarginConfigurationFailsClosed(t *testing.T) {
	for _, labels := range []any{[]string{"S1", "S2"}, []string{"S0"}, []string{"S0", "S0"}, nil, true} {
		artifact := contextualFixture(t)
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedDecisionMarginObjective
		var config map[string]any
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			t.Fatal(err)
		}
		config["sensitivity_labels"] = labels
		artifact.Config, _ = json.Marshal(config)
		if err := validateContextualTrainingArtifact(&artifact); err == nil {
			t.Fatal("invalid reference labels accepted")
		}
	}
	for _, threshold := range []any{nil, true, 0., 1., "0.38"} {
		artifact := contextualFixture(t)
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedDecisionMarginObjective
		var config map[string]any
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			t.Fatal(err)
		}
		config["category_threshold"] = threshold
		artifact.Config, _ = json.Marshal(config)
		if err := validateContextualTrainingArtifact(&artifact); err == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
	for _, threshold := range []float64{.38, .5, .9} {
		artifact := contextualFixture(t)
		artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedDecisionMarginObjective
		var config map[string]any
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			t.Fatal(err)
		}
		config["category_threshold"] = threshold
		artifact.Config, _ = json.Marshal(config)
		if err := validateContextualTrainingArtifact(&artifact); err != nil {
			t.Fatal(err)
		}
	}
}
