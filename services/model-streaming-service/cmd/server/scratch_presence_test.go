package main

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func scratchFixturePath() string {
	return filepath.Join("..", "..", "..", "..", "shared", "python", "tests", "fixtures", "scratch-presence-efficient.json")
}

func scratchFixture(t *testing.T) *loadedArtifact {
	t.Helper()
	artifact, err := loadModelArtifact(scratchFixturePath(), "privoke-scratch-presence-efficient-head-only")
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestScratchSharedFixtureChecksumAndFirstChunkMetadata(t *testing.T) {
	artifact := scratchFixture(t)
	response := parameterResponse(artifact, "synthetic-test")
	metadata := response.GetMetadata()
	if metadata["task"] != "annotation_presence" || metadata["profile"] != "efficient" || metadata["training_mode"] != "head_only" || metadata["text_normalization"] != "detector_normalize_text_v1" || metadata["tokenizer"] != "legacy_sha256_bucket_tokens_v1" || metadata["pooling"] != "half_first_half_real_mean_v1" || metadata["arithmetic"] != "float32_numpy_encoder_clipped_sigmoid_v1" {
		t.Fatal("scratch derived contract missing")
	}
	// Raw artifact whitespace must not inflate the bounded first-chunk config.
	padded := append([]byte("{ "+strings.Repeat(" ", maxScratchConfigBytes)), artifact.Config[1:]...)
	artifact.Config = padded
	compactMetadata := parameterResponse(artifact, "synthetic-test").Metadata
	if len(compactMetadata["model_config"]) > maxScratchConfigBytes {
		t.Fatal("scratch stream config not compact/bounded")
	}
	if metadata["trainable_parameters"] != "head.presence.bias,head.presence.weight" {
		t.Fatal("scratch trainability not sorted/exact")
	}
	if parameterChunk(response, response.Parameters[0], 0, 0, 2).Metadata == nil || parameterChunk(response, response.Parameters[0], 0, 1, 2).Metadata != nil {
		t.Fatal("metadata is not first-chunk-only")
	}
	weights := artifact.Parameters["head.presence.weight"].Values
	if !math.Signbit(weights[0]) || weights[1] != float64(float32(0.1)) {
		t.Fatal("float32 lexical fixture identity lost")
	}
	for _, parameter := range response.Parameters {
		if parameter.Name == "head.presence.weight" && (!math.Signbit(float64(parameter.Values[0])) || parameter.Values[1] != float32(0.1) || parameter.Values[2] == 0) {
			t.Fatal("protobuf float32 transport vector changed")
		}
	}
}

func TestScratchRejectsWrongShapesModesAndProvenance(t *testing.T) {
	cases := map[string]func(*modelArtifact){
		"mode ID":            func(a *modelArtifact) { a.ModelID = "privoke-scratch-presence-efficient-full-encoder" },
		"wrong architecture": func(a *modelArtifact) { a.Architecture = expectedArchitecture },
		"legacy ID":          func(a *modelArtifact) { a.ModelID = "privoke-balanced" },
		"epoch":              func(a *modelArtifact) { a.Metadata["checkpoint_epoch"] = "2" },
		"Unicode":            func(a *modelArtifact) { a.Metadata["source_revision"] = strings.Repeat("ÃƒÂ©", 40) },
		"unknown metadata":   func(a *modelArtifact) { a.Metadata["extra"] = "x" },
		"noncanonical steps": func(a *modelArtifact) { a.Metadata["training_steps"] = "0490" },
		"overflow": func(a *modelArtifact) {
			tensor := a.Parameters["head.presence.bias"]
			tensor.Values[0] = 1e100
			a.Parameters["head.presence.bias"] = tensor
		},
		"not exact f32": func(a *modelArtifact) {
			tensor := a.Parameters["head.presence.bias"]
			tensor.Values[0] = 0.1
			a.Parameters["head.presence.bias"] = tensor
		},
		"frozen flag": func(a *modelArtifact) {
			tensor := a.Parameters["token_embedding"]
			tensor.Trainable = true
			a.Parameters["token_embedding"] = tensor
		},
		"shape": func(a *modelArtifact) {
			tensor := a.Parameters["head.presence.weight"]
			tensor.Shape = []uint32{24}
			a.Parameters["head.presence.weight"] = tensor
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			artifact := scratchFixture(t)
			mutate(&artifact.modelArtifact)
			if validateModelArtifact(&artifact.modelArtifact, "") == nil {
				t.Fatal("invalid scratch object accepted")
			}
		})
	}
}

func TestScratchRawGuardsRunBeforeTypedDecode(t *testing.T) {
	raw, err := os.ReadFile(scratchFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	cases := map[string]string{
		"duplicate root":                        strings.Replace(text, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"duplicate architecture hiding scratch": strings.Replace(text, `"architecture":"privoke_scratch_presence_transformer_v1"`, `"architecture":"privoke_scratch_presence_transformer_v1","architecture":"privoke_tiny_transformer_v1"`, 1),
		"missing flag":                          strings.Replace(text, `,"trainable":true`, "", 1),
		"null flag":                             strings.Replace(text, `"trainable":true`, `"trainable":null`, 1),
		"unknown root":                          strings.TrimSpace(text[:len(text)-1]) + ` `,
		"surrogate":                             strings.Replace(text, `"source_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, `"source_revision":"\ud800"`, 1),
		"raw byte limit":                        strings.Repeat(" ", maxArtifactBytes) + text,
	}
	cases["unknown root"] = strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"extra":1}`
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scratch.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadModelArtifact(path, ""); err == nil {
				t.Fatal("invalid raw scratch artifact accepted")
			}
		})
	}
}

func TestScratchAllProfilesAndOfflineModes(t *testing.T) {
	for profile, dims := range scratchProfiles {
		for _, mode := range []string{"head_only", "end_to_end"} {
			base := scratchFixture(t).modelArtifact
			config := scratchConfig{Task: "annotation_presence", Profile: profile, TrainingMode: mode, VocabSize: dims[0], HiddenSize: dims[1], IntermediateSize: dims[2], MaxTokens: dims[3], NumLayers: dims[4], NumAttentionHeads: dims[5], Normalization: "detector_normalize_text_v1", Tokenizer: "legacy_sha256_bucket_tokens_v1", Pooling: "half_first_half_real_mean_v1", Arithmetic: "float32_numpy_encoder_clipped_sigmoid_v1", Threshold: 0.5}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			base.Config = raw
			suffix := "head-only"
			if mode == "end_to_end" {
				suffix = "full-encoder"
			}
			base.ModelID = "privoke-scratch-presence-" + profile + "-" + suffix
			base.Parameters = map[string]artifactTensor{}
			for name, shape := range scratchShapes(config) {
				size := 1
				for _, d := range shape {
					size *= int(d)
				}
				base.Parameters[name] = artifactTensor{Shape: shape, Values: make([]float64, size), Trainable: mode == "end_to_end" || strings.HasPrefix(name, "head.presence.")}
			}
			if err := validateModelArtifact(&base, base.ModelID); err != nil {
				t.Fatalf("%s/%s: %v", profile, mode, err)
			}
		}
	}
}

func TestScratchCatalogCannotBecomeLatestOnConstructionOrReload(t *testing.T) {
	artifact := scratchFixture(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(scratchFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scratch.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadModelCatalog(dir, artifact.ModelID); err == nil {
		t.Fatal("scratch selected latest")
	}
	catalog := modelCatalog{latestModelID: artifact.ModelID, paths: map[string]string{artifact.ModelID: path}}
	for _, id := range []string{"latest", "", artifact.ModelID} {
		if _, err := catalog.load(id); err == nil {
			t.Fatal("reload allowed scratch latest")
		}
	}
	if err := catalog.validate(); err == nil {
		t.Fatal("validation allowed scratch latest")
	}
	catalog.latestModelID = "privoke-balanced"
	if _, err := catalog.load(artifact.ModelID); err != nil {
		t.Fatal("explicit offline scratch inference rejected", err)
	}
}

func TestScratchRequestConsumerContract(t *testing.T) {
	server := &streamingServer{}
	cases := []struct {
		name     string
		consumer string
		valid    bool
	}{
		{"empty", "", false},
		{"unicode", "consumer-é", false},
		{"control", "consumer\n", false},
		{"delete", "consumer\x7f", false},
		{"ASCII128", strings.Repeat("a", 128), true},
		{"ASCII129", strings.Repeat("a", 129), false},
	}
	for profile := range scratchProfiles {
		for _, suffix := range []string{"head-only", "full-encoder"} {
			modelID := "privoke-scratch-presence-" + profile + "-" + suffix
			for _, test := range cases {
				t.Run(modelID+"/"+test.name, func(t *testing.T) {
					request := &pb.ModelParametersRequest{ModelId: modelID, ConsumerId: test.consumer}
					err := server.validateRequest(request)
					if test.valid {
						if err != nil {
							t.Fatal("valid scratch consumer rejected", err)
						}
						return
					}
					if status.Code(err) != codes.InvalidArgument {
						t.Fatal("invalid scratch consumer did not reject", err)
					}
					// A nil catalog proves rejection precedes catalog access.
					if _, err := server.GetModelParameters(context.Background(), request); status.Code(err) != codes.InvalidArgument {
						t.Fatal("unary request did not reject before catalog access", err)
					}
				})
			}
		}
	}
	for _, consumer := range []string{"", "consumer-é", strings.Repeat("a", 129)} {
		if err := server.validateRequest(&pb.ModelParametersRequest{ModelId: "privoke-balanced", ConsumerId: consumer}); err != nil {
			t.Fatal("legacy consumer contract changed", err)
		}
	}
}
