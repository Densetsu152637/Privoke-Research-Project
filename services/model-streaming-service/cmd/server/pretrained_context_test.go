package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pretrainedFixturePath() string {
	return filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "pretrained-context-minilm.json")
}

func pretrainedFixture(t *testing.T) *loadedArtifact {
	t.Helper()
	artifact, err := loadModelArtifact(pretrainedFixturePath(), pretrainedContextModelID)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestPretrainedSharedPythonFixtureLoadsAndStreamsSixFrozenHeads(t *testing.T) {
	artifact := pretrainedFixture(t)
	response := parameterResponse(artifact, "test")
	if len(response.Parameters) != 6 || response.Metadata["architecture"] != pretrainedContextArchitecture || response.Metadata["trainable_parameters"] != "" {
		t.Fatal("pretrained stream does not preserve six frozen head contract")
	}
	count := 0
	for _, tensor := range response.Parameters {
		count += len(tensor.Values)
	}
	if count != 7700 {
		t.Fatalf("expected 7700 head values, got %d", count)
	}
}

func TestPretrainedArtifactRejectsConfigHeadAndIdentityDrift(t *testing.T) {
	for name, mutate := range map[string]func(*modelArtifact){
		"invalid version":    func(a *modelArtifact) { a.Version = strings.Repeat("x", 129) },
		"wrong ID":           func(a *modelArtifact) { a.ModelID = "privoke-balanced" },
		"wrong architecture": func(a *modelArtifact) { a.Architecture = expectedArchitecture },
		"missing head":       func(a *modelArtifact) { delete(a.Parameters, "head.category.bias") },
		"extra head": func(a *modelArtifact) {
			a.Parameters["extra"] = artifactTensor{Shape: []uint32{1}, Values: []float64{0}}
		},
		"trainable": func(a *modelArtifact) {
			v := a.Parameters["head.category.bias"]
			v.Trainable = true
			a.Parameters["head.category.bias"] = v
		},
		"wrong shape": func(a *modelArtifact) {
			v := a.Parameters["head.visibility.bias"]
			v.Shape = []uint32{2, 3}
			a.Parameters["head.visibility.bias"] = v
		},
		"float32 overflow": func(a *modelArtifact) {
			v := a.Parameters["head.category.bias"]
			v.Values[0] = 1e100
			a.Parameters["head.category.bias"] = v
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := pretrainedFixture(t).modelArtifact
			mutate(&a)
			if err := validateModelArtifact(&a, ""); err == nil {
				t.Fatal("invalid pretrained artifact accepted")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"semantics":   func(c map[string]any) { c["category_semantics"] = "topic_tags_v1" },
		"unknown":     func(c map[string]any) { c["extra"] = true },
		"tokenizer":   func(c map[string]any) { c["tokenizer_sha256"] = strings.Repeat("f", 64) },
		"backbone":    func(c map[string]any) { c["backbone_revision"] = strings.Repeat("f", 40) },
		"context":     func(c map[string]any) { c["max_tokens"] = 513 },
		"threshold":   func(c map[string]any) { c["category_threshold"] = 0 },
		"label order": func(c map[string]any) { c["sensitivity_labels"] = []string{"S3", "S2", "S1", "S0"} },
	} {
		t.Run(name, func(t *testing.T) {
			a := pretrainedFixture(t).modelArtifact
			rewritePresenceConfig(t, &a, mutate)
			if err := validateModelArtifact(&a, ""); err == nil {
				t.Fatal("invalid pretrained config accepted")
			}
		})
	}
}

func TestPretrainedOnlyAdmittedContextProfilesPreserveStreamConfig(t *testing.T) {
	for _, limit := range []any{256, 512, 0, 255, 257, 511, 513, true, "512", 512.5, nil} {
		artifact := pretrainedFixture(t).modelArtifact
		rewritePresenceConfig(t, &artifact, func(config map[string]any) { config["max_tokens"] = limit })
		err := validateModelArtifact(&artifact, "")
		admitted := limit == 256 || limit == 512
		if (err == nil) != admitted {
			t.Fatalf("context limit %v admission mismatch: %v", limit, err)
		}
		if admitted {
			response := parameterResponse(&loadedArtifact{modelArtifact: artifact}, "test")
			var config pretrainedContextConfig
			if err := json.Unmarshal([]byte(response.Metadata["model_config"]), &config); err != nil || config.MaxTokens != limit {
				t.Fatalf("stream lost admitted context limit %v: %v", limit, err)
			}
		}
	}
}

func TestPretrainedRawDuplicateFlagsAndUnknownFieldsRejected(t *testing.T) {
	raw, err := os.ReadFile(pretrainedFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, invalid := range []string{
		strings.Replace(text, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(text, `"architecture":"privoke_pretrained_context_v1"`, `"architecture":"privoke_pretrained_context_v1","architecture":"privoke_tiny_transformer_v1"`, 1),
		strings.Replace(text, `"category_threshold":0.5`, `"category_threshold":0.5,"category_threshold":0.6`, 1),
		strings.Replace(text, `,"trainable":false`, "", 1),
		strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"extra":1}`,
	} {
		if _, err := loadModelArtifactBytes([]byte(invalid), ""); err == nil {
			t.Fatal("invalid raw pretrained artifact accepted")
		}
	}
}

func TestPretrainedCannotBeLatestAndExplicitCatalogLoadPreservesIdentity(t *testing.T) {
	directory := t.TempDir()
	raw, err := os.ReadFile(pretrainedFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, pretrainedContextModelID+".json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadModelCatalog(directory, pretrainedContextModelID); err == nil {
		t.Fatal("experimental latest admitted")
	}
	catalog := modelCatalog{latestModelID: "privoke-balanced", paths: map[string]string{pretrainedContextModelID: path}}
	loaded, err := catalog.load(pretrainedContextModelID)
	if err != nil || loaded.ModelID != pretrainedContextModelID {
		t.Fatalf("explicit load failed: %v", err)
	}
	catalog.latestModelID = pretrainedContextModelID
	if _, err := catalog.load("latest"); err == nil {
		t.Fatal("hand-built experimental latest admitted")
	}
	t.Setenv("MODEL_LATEST_ID", pretrainedContextModelID)
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("experimental latest configuration admitted")
	}
}

func TestPretrainedClosedASCIIReleaseVersionsMatchPython(t *testing.T) {
	for _, version := range []string{"", "has space", "café", ".leading", strings.Repeat("x", 129)} {
		artifact := pretrainedFixture(t).modelArtifact
		artifact.Version = version
		if err := validateModelArtifact(&artifact, ""); err == nil {
			t.Fatalf("invalid pretrained version accepted: %q", version)
		}
	}
}
