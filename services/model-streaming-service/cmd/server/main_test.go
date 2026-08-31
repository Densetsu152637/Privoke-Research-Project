package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetModelParametersLoadsPersistentArtifact(t *testing.T) {
	path := writeTestArtifact(t)
	server := streamingServer{catalog: testCatalog(path)}

	response, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: "privoke-baseline"},
	)
	if err != nil {
		t.Fatalf("GetModelParameters returned an error: %v", err)
	}
	if response.GetModelId() != "privoke-baseline" || response.GetVersion() != "v1" {
		t.Fatalf("returned unexpected model/version %q %q", response.GetModelId(), response.GetVersion())
	}
	if len(response.GetParameters()) != 1 || len(response.GetParameters()[0].GetShape()) != 2 {
		t.Fatalf("artifact tensor shape was not streamed")
	}
}

func TestGetModelParametersResolvesLatestAlias(t *testing.T) {
	server := streamingServer{catalog: testCatalog(writeTestArtifact(t))}

	response, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: latestModelAlias},
	)
	if err != nil {
		t.Fatalf("latest request returned an error: %v", err)
	}
	if response.GetModelId() != "privoke-baseline" {
		t.Fatalf("latest resolved to %q", response.GetModelId())
	}
}

func TestLoadModelCatalogDiscoversArtifacts(t *testing.T) {
	path := writeTestArtifact(t)
	catalog, err := loadModelCatalog(filepath.Dir(path), "privoke-baseline")
	if err != nil {
		t.Fatalf("loadModelCatalog returned an error: %v", err)
	}
	artifact, err := catalog.load(latestModelAlias)
	if err != nil {
		t.Fatalf("latest catalog model could not be loaded: %v", err)
	}
	if artifact.ModelID != "privoke-baseline" {
		t.Fatalf("latest resolved to %q", artifact.ModelID)
	}
}

func TestGetModelParametersRejectsUnknownModel(t *testing.T) {
	server := streamingServer{catalog: testCatalog(writeTestArtifact(t))}

	_, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: "does-not-exist"},
	)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NOT_FOUND, got %v", err)
	}
}

func TestGetModelParametersRejectsControlCharacters(t *testing.T) {
	server := streamingServer{catalog: testCatalog(writeTestArtifact(t))}

	_, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ConsumerId: "attacker\nforged-log"},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %v", err)
	}
}

func TestGetModelParametersRejectsInvalidArtifactChecksum(t *testing.T) {
	path := writeTestArtifact(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["version"] = "tampered"
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	server := streamingServer{catalog: testCatalog(path)}
	_, err = server.GetModelParameters(context.Background(), &pb.ModelParametersRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected UNAVAILABLE, got %v", err)
	}
}

func testCatalog(path string) *modelCatalog {
	return &modelCatalog{
		latestModelID: "privoke-baseline",
		paths: map[string]string{
			"privoke-baseline": path,
		},
	}
}

func TestLoadRepositoryArtifact(t *testing.T) {
	path := filepath.Join("..", "..", "models", "privoke-baseline.json")
	if _, err := os.Stat(path); err != nil {
		path = "/models/privoke-baseline.json"
	}
	artifact, err := loadModelArtifact(path, "privoke-baseline")
	if err != nil {
		t.Fatalf("repository artifact did not validate: %v", err)
	}
	if artifact.Checksum == "" || artifact.fileChecksum == "" {
		t.Fatal("repository artifact checksums were not populated")
	}
}

func TestArtifactChecksumMatchesSharedPythonCanonicalJSON(t *testing.T) {
	raw := []byte(`{"metadata":{"label":"café <safe>\u2028"},"checksum":"ignored"}`)
	checksum, err := calculateArtifactChecksum(raw)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "c35c226b69d388c8090e2021b143a1a693c67a9035d6e61469ce20fac540af87"
	if checksum != expected {
		t.Fatalf("canonical checksum mismatch: got %s want %s", checksum, expected)
	}
}

func writeTestArtifact(t *testing.T) string {
	t.Helper()
	config, err := json.Marshal(map[string]int{"hidden_size": 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(modelArtifact{
		SchemaVersion:   expectedSchema,
		ModelID:         "privoke-baseline",
		Version:         "v1",
		GeneratedAtUnix: 1,
		Architecture:    expectedArchitecture,
		Config:          config,
		Parameters: map[string]artifactTensor{
			"head.weight": {Shape: []uint32{1, 2}, Values: []float64{0.1, 0.2}, Trainable: true},
		},
		Metadata: map[string]string{},
		Checksum: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := calculateArtifactChecksum(payload)
	if err != nil {
		t.Fatal(err)
	}
	var artifact map[string]any
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact["checksum"] = checksum
	payload, err = json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
