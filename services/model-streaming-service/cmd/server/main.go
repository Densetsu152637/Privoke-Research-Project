package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
)

type streamingServer struct {
	pb.UnimplementedModelStreamingServiceServer
	modelID      string
	modelVersion string
}

func (s *streamingServer) GetModelParameters(_ context.Context, req *pb.ModelParametersRequest) (*pb.ModelParametersResponse, error) {
	log.Printf("parameter request consumer=%s model=%s", req.GetConsumerId(), req.GetModelId())

	return &pb.ModelParametersResponse{
		ModelId:         s.modelID,
		Version:         s.modelVersion,
		GeneratedAtUnix: time.Now().Unix(),
		Parameters: []*pb.Parameter{
			{Name: "encoder.layer.0.attention", Values: []float32{0.12, 0.45, 0.87}},
			{Name: "encoder.layer.1.ffn", Values: []float32{0.33, 0.21, 0.55}},
			{Name: "classifier.bias", Values: []float32{0.04}},
		},
		Metadata: map[string]string{
			"served_by":   "model-streaming-service",
			"consumer_id": req.GetConsumerId(),
		},
	}, nil
}

func (s *streamingServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Service: "model-streaming-service",
		Status:  "SERVING",
	}, nil
}

func main() {
	port := envInt("MODEL_STREAMING_PORT", 50051)
	modelID := envString("MODEL_ID", "privoke-baseline")
	modelVersion := envString("MODEL_VERSION", "v0.1.0")

	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	server := grpc.NewServer()
	pb.RegisterModelStreamingServiceServer(server, &streamingServer{
		modelID:      modelID,
		modelVersion: modelVersion,
	})

	log.Printf("model-streaming-service listening on %d", port)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("serve failed: %v", err)
	}
}

func envString(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
