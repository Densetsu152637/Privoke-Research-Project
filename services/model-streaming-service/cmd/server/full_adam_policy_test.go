package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fullAdamArtifact(t *testing.T, profile string) modelArtifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "models", "privoke-"+profile+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact modelArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.Metadata[contextualStrategyKey] = contextualFullEncoderStrategy
	artifact.Metadata[contextualObjectiveKey] = contextualClassBalancedSumDecisionMarginObjective
	artifact.Metadata[contextualOptimizerKey] = contextualFullAdam
	artifact.Metadata[contextualCandidateEligibilityKey] = contextualCandidateEligibility
	artifact.Metadata[contextualFullAdamConfigKey] = contextualFullAdamConfig
	for name, tensor := range artifact.Parameters {
		tensor.Trainable = true
		artifact.Parameters[name] = tensor
	}
	return artifact
}

func TestFullAdamThreeProfilesAndExactMetadata(t *testing.T) {
	for _, profile := range []string{"efficient", "balanced", "quality"} {
		t.Run(profile, func(t *testing.T) {
			artifact := fullAdamArtifact(t, profile)
			if err := validateModelArtifact(&artifact, ""); err != nil {
				t.Fatal(err)
			}
			_, names := parameterMessages(artifact.Parameters)
			metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "test", names)
			for _, key := range []string{contextualStrategyKey, contextualObjectiveKey, contextualOptimizerKey, contextualCandidateEligibilityKey, contextualFullAdamConfigKey} {
				if metadata[key] != artifact.Metadata[key] {
					t.Fatalf("metadata changed: %s", key)
				}
			}
		})
	}
}

func TestFullAdamPolicyRejectsMissingMalformedMixedAndUnsupported(t *testing.T) {
	mutations := map[string]func(*modelArtifact){
		"missing strategy":  func(a *modelArtifact) { delete(a.Metadata, contextualStrategyKey) },
		"head strategy":     func(a *modelArtifact) { a.Metadata[contextualStrategyKey] = contextualLastBlockStrategy },
		"missing objective": func(a *modelArtifact) { delete(a.Metadata, contextualObjectiveKey) },
		"other objective": func(a *modelArtifact) {
			a.Metadata[contextualObjectiveKey] = contextualClassBalancedDecisionMarginObjective
		},
		"missing optimizer":   func(a *modelArtifact) { delete(a.Metadata, contextualOptimizerKey) },
		"unknown optimizer":   func(a *modelArtifact) { a.Metadata[contextualOptimizerKey] = "adam" },
		"local optimizer":     func(a *modelArtifact) { a.Metadata[contextualOptimizerKey] = contextualLocalSGD4 },
		"missing eligibility": func(a *modelArtifact) { delete(a.Metadata, contextualCandidateEligibilityKey) },
		"unknown eligibility": func(a *modelArtifact) { a.Metadata[contextualCandidateEligibilityKey] = "base_train_exact_v1" },
		"missing config":      func(a *modelArtifact) { delete(a.Metadata, contextualFullAdamConfigKey) },
		"noncanonical config": func(a *modelArtifact) { a.Metadata[contextualFullAdamConfigKey] = " " + contextualFullAdamConfig },
		"invalid json config": func(a *modelArtifact) { a.Metadata[contextualFullAdamConfigKey] = "{" },
		"unsupported steps":   func(a *modelArtifact) { a.Metadata[contextualFullAdamConfigKey] = `{"steps":63}` },
		"diagnostics":         func(a *modelArtifact) { a.Metadata["contextual_training_diagnostics_policy"] = "" },
		"backtracking": func(a *modelArtifact) {
			a.Metadata["contextual_training_backtracking_policy"] = "full_train_backtracking_v1"
		},
		"backtracking preparation": func(a *modelArtifact) { a.Metadata["contextual_training_backtracking_preparation"] = "{}" },
		"frozen embedding": func(a *modelArtifact) {
			x := a.Parameters["token_embedding"]
			x.Trainable = false
			a.Parameters["token_embedding"] = x
		},
		"wrong shape": func(a *modelArtifact) {
			x := a.Parameters["token_embedding"]
			x.Shape = []uint32{1, uint32(len(x.Values))}
			a.Parameters["token_embedding"] = x
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			artifact := fullAdamArtifact(t, "balanced")
			mutate(&artifact)
			if err := validateModelArtifact(&artifact, ""); err == nil {
				t.Fatal("invalid FULL Adam accepted")
			}
		})
	}
}

func TestSumDecisionMarginConfigAndOptimizerParity(t *testing.T) {
	for _, key := range []string{"category_threshold", "sensitivity_labels"} {
		values := []any{nil, true, "invalid", 0., 1.}
		if key == "sensitivity_labels" {
			values = []any{nil, true, []string{"S1"}, []string{"S0"}, []string{"S0", "S0"}, []any{"S0", nil}}
		}
		for _, value := range values {
			artifact := fullAdamArtifact(t, "balanced")
			var config map[string]any
			if err := json.Unmarshal(artifact.Config, &config); err != nil {
				t.Fatal(err)
			}
			config[key] = value
			artifact.Config, _ = json.Marshal(config)
			if err := validateContextualTrainingArtifact(&artifact); err == nil {
				t.Fatalf("invalid SUM %s accepted", key)
			}
		}
	}
	// The earlier SUM objective with absent optimizer remains its distinct route.
	artifact := fullAdamArtifact(t, "balanced")
	delete(artifact.Metadata, contextualOptimizerKey)
	delete(artifact.Metadata, contextualCandidateEligibilityKey)
	delete(artifact.Metadata, contextualFullAdamConfigKey)
	if err := validateModelArtifact(&artifact, ""); err != nil {
		t.Fatal(err)
	}
	artifact.Metadata[contextualOptimizerKey] = contextualLocalSGD1
	if err := validateModelArtifact(&artifact, ""); err == nil {
		t.Fatal("SUM allowed local SGD")
	}
}
