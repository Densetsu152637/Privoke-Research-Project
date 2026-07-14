package main

import (
	"context"
	"testing"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetModelParametersReturnsConfiguredModel(t *testing.T) {
	server := streamingServer{modelID: "privoke-baseline", modelVersion: "v1"}

	response, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: "privoke-baseline"},
	)
	if err != nil {
		t.Fatalf("GetModelParameters returned an error: %v", err)
	}
	if response.GetModelId() != "privoke-baseline" {
		t.Fatalf("returned model %q", response.GetModelId())
	}
}

func TestGetModelParametersRejectsUnknownModel(t *testing.T) {
	server := streamingServer{modelID: "privoke-baseline", modelVersion: "v1"}

	_, err := server.GetModelParameters(
		context.Background(),
		&pb.ModelParametersRequest{ModelId: "does-not-exist"},
	)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NOT_FOUND, got %v", err)
	}
}
