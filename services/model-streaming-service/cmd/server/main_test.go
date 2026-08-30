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
	server := streamingServer{modelID: "privoke-baseline", artifactPath: path}

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

func TestGetModelParametersRejectsUnknownModel(t *testing.T) {
	server := streamingServer{modelID: "privoke-baseline", artifactPath: writeTestArtifact(t)}

	_, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: "does-not-exist"},
	)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NOT_FOUND, got %v", err)
	}
}

func TestGetModelParametersRejectsControlCharacters(t *testing.T) {
	server := streamingServer{modelID: "privoke-baseline", artifactPath: writeTestArtifact(t)}

	_, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ConsumerId: "attacker\nforged-log"},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT, got %v", err)
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
		Checksum: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
