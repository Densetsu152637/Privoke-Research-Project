package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func presenceFixture(t *testing.T) modelArtifact {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "presence-efficient.json")
	raw, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var artifact modelArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil { t.Fatal(err) }
	return artifact
}

func rewritePresenceConfig(t *testing.T, artifact *modelArtifact, mutate func(map[string]any)) {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(artifact.Config, &config); err != nil { t.Fatal(err) }
	mutate(config)
	raw, err := json.Marshal(config)
	if err != nil { t.Fatal(err) }
	artifact.Config = raw
}

func TestPresenceSharedPythonFixtureLoadsAndStreamsMetadata(t *testing.T) {
	artifact := presenceFixture(t)
	if err := validateModelArtifact(&artifact, "privoke-presence-efficient"); err != nil { t.Fatal(err) }
	path := filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "presence-efficient.json")
	loaded, err := loadModelArtifact(path, artifact.ModelID)
	if err != nil { t.Fatal(err) }
	response := parameterResponse(loaded, "test")
	if response.Metadata["task"] != "annotation_presence" || response.Metadata["profile"] != "efficient" || response.Metadata["arithmetic"] != "float32_parameters_float64_features_fsum_v1" { t.Fatal("presence task identity missing from stream") }
	if parameterChunk(response, response.Parameters[0], 0, 0, 1).Metadata["model_config"] == "" { t.Fatal("first stream chunk missing config") }
	if parameterChunk(response, response.Parameters[0], 0, 1, 2).Metadata != nil { t.Fatal("config should only be transmitted once") }
}

func TestPresenceConfigRejectsInvalidContracts(t *testing.T) {
	cases := map[string]func(map[string]any){
		"unknown field": func(c map[string]any) { c["extra"] = 1 },
		"null threshold": func(c map[string]any) { c["threshold"] = nil },
		"boolean threshold": func(c map[string]any) { c["threshold"] = true },
		"threshold range": func(c map[string]any) { c["threshold"] = 2 },
		"wrong task": func(c map[string]any) { c["task"] = "privacy_severity" },
		"wrong profile": func(c map[string]any) { c["profile"] = "other" },
		"wrong column order": func(c map[string]any) { c["column_order"] = []string{"char", "word"} },
		"wrong block": func(c map[string]any) { c["coefficient_block_size"] = 4095 },
		"wrong vocabulary": func(c map[string]any) { c["branches"].(map[string]any)["word"].(map[string]any)["features"] = []string{"a"} },
		"duplicate vocabulary": func(c map[string]any) { c["branches"].(map[string]any)["word"].(map[string]any)["features"] = []string{"mail", "mail"} },
		"bad char ngram": func(c map[string]any) { c["branches"].(map[string]any)["char"].(map[string]any)["features"] = []string{"xx"} },
		"null lowercase": func(c map[string]any) { c["branches"].(map[string]any)["word"].(map[string]any)["lowercase"] = nil },
		"wrong TF setting": func(c map[string]any) { c["branches"].(map[string]any)["char"].(map[string]any)["sublinear_tf"] = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			artifact := presenceFixture(t)
			rewritePresenceConfig(t, &artifact, mutate)
			if err := validateModelArtifact(&artifact, ""); err == nil { t.Fatal("invalid presence config accepted") }
		})
	}
}

func TestPresenceParametersRejectInvalidManifest(t *testing.T) {
	for _, name := range []string{"frozen flag", "missing tensor", "wrong shape", "zero idf", "float32 overflow", "extra tensor", "wrong model"} {
		t.Run(name, func(t *testing.T) {
			artifact := presenceFixture(t)
			switch name {
			case "frozen flag":
				tensor := artifact.Parameters["features.word.idf"]; tensor.Trainable = true; artifact.Parameters["features.word.idf"] = tensor
			case "missing tensor": delete(artifact.Parameters, "head.presence.bias")
			case "wrong shape":
				tensor := artifact.Parameters["head.presence.bias"]; tensor.Shape = []uint32{1, 1}; artifact.Parameters["head.presence.bias"] = tensor
			case "zero idf": artifact.Parameters["features.word.idf"].Values[0] = 0
			case "float32 overflow": artifact.Parameters["head.presence.bias"].Values[0] = math.MaxFloat64
			case "extra tensor": artifact.Parameters["head.extra"] = artifactTensor{Shape: []uint32{1}, Values: []float64{0}}
			case "wrong model": artifact.ModelID = "privoke-presence-balanced"
			}
			if err := validateModelArtifact(&artifact, ""); err == nil { t.Fatal("invalid presence tensor contract accepted") }
		})
	}
}

func TestPresenceRawTrainableFlagsAndUnicode(t *testing.T) {
	for _, raw := range []string{`{"parameters":{"features.word.idf":{"trainable":null}}}`, `{"parameters":{"features.word.idf":{}}}`, `{"parameters":{"features.word.idf":{"trainable":1}}}`} {
		if err := validatePresenceRawTensorFlags([]byte(raw)); err == nil { t.Fatal("non-boolean/missing trainable accepted") }
	}
	if err := validatePresenceRawTensorFlags([]byte(`{"parameters":{"features.word.idf":{"trainable":false}}}`)); err != nil { t.Fatal(err) }
	for _, raw := range []string{`"\ud800ab"`, `"\udc00ab"`, `"\ud800\u0041"`} {
		if validJSONUnicode([]byte(raw)) { t.Fatalf("invalid surrogate accepted: %s", raw) }
	}
	for _, raw := range []string{`"\ud83e\uddea"`, `"\\ud800"`, `"café"`} {
		if !validJSONUnicode([]byte(raw)) { t.Fatalf("valid Unicode rejected: %s", raw) }
	}
}
