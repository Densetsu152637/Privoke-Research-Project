package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func taskQueryFixture(t *testing.T) modelArtifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "contextual-task-query.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadModelArtifactBytes(raw, "contextual-training-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return loaded.modelArtifact
}

func TestTaskQuerySharedFixtureTransportAndScopes(t *testing.T) {
	artifact := taskQueryFixture(t)
	for _, strategy := range []string{"", contextualLastBlockStrategy, contextualFullEncoderStrategy} {
		if strategy == "" {
			delete(artifact.Metadata, contextualStrategyKey)
		} else {
			artifact.Metadata[contextualStrategyKey] = strategy
		}
		names, _, err := contextualTrainableNames(artifact.Config, strategy)
		if err != nil {
			t.Fatal(err)
		}
		for name, tensor := range artifact.Parameters {
			tensor.Trainable = names[name]
			artifact.Parameters[name] = tensor
		}
		if err := validateModelArtifact(&artifact, ""); err != nil {
			t.Fatal(err)
		}
		_, trainables := parameterMessages(artifact.Parameters)
		if len(trainables) != len(names) {
			t.Fatal("query trainability lost in transport")
		}
		for _, task := range []string{"sensitivity", "visibility", "category"} {
			if !names["readout."+task+".query"] {
				t.Fatal("query is silently frozen")
			}
		}
		metadata := responseMetadata(&loadedArtifact{modelArtifact: artifact}, "synthetic", trainables)
		if metadata["architecture"] != taskQueryArchitecture {
			t.Fatal("query architecture lost in stream")
		}
	}
}

func TestTaskQueryFailClosed(t *testing.T) {
	cases := map[string]func(*modelArtifact){
		"legacy identity": func(a *modelArtifact) { a.Architecture = expectedArchitecture },
		"missing query":   func(a *modelArtifact) { delete(a.Parameters, "readout.category.query") },
		"wrong query shape": func(a *modelArtifact) {
			v := a.Parameters["readout.category.query"]
			v.Shape = []uint32{1, 2}
			a.Parameters["readout.category.query"] = v
		},
		"frozen query": func(a *modelArtifact) {
			v := a.Parameters["readout.category.query"]
			v.Trainable = false
			a.Parameters["readout.category.query"] = v
		},
		"extra tensor": func(a *modelArtifact) {
			a.Parameters["extra"] = artifactTensor{Shape: []uint32{1}, Values: []float64{0}}
		},
		"unsupported readout": func(a *modelArtifact) {
			var c map[string]any
			json.Unmarshal(a.Config, &c)
			c["readout"] = "unknown"
			a.Config, _ = json.Marshal(c)
		},
		"missing readout": func(a *modelArtifact) {
			var c map[string]any
			json.Unmarshal(a.Config, &c)
			delete(c, "readout")
			a.Config, _ = json.Marshal(c)
		},
		"bad attention": func(a *modelArtifact) {
			var c map[string]any
			json.Unmarshal(a.Config, &c)
			c["num_attention_heads"] = 3
			a.Config, _ = json.Marshal(c)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := taskQueryFixture(t)
			mutate(&a)
			if err := validateModelArtifact(&a, ""); err == nil {
				t.Fatal("malformed query artifact accepted")
			}
		})
	}
}
