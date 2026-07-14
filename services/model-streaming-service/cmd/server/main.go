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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type streamingServer struct {
	pb.UnimplementedModelStreamingServiceServer
	modelID      string
	modelVersion string
}

func (s *streamingServer) GetModelParameters(_ context.Context, req *pb.ModelParametersRequest) (*pb.ModelParametersResponse, error) {
	if err := validateIdentifier("consumer_id", req.GetConsumerId(), false); err != nil {
		return nil, err
	}
	if err := validateIdentifier("model_id", req.GetModelId(), false); err != nil {
		return nil, err
	}
	log.Printf("parameter request consumer=%q model=%q", req.GetConsumerId(), req.GetModelId())
	if requestedModelID := req.GetModelId(); requestedModelID != "" && requestedModelID != s.modelID {
		return nil, status.Errorf(
			codes.NotFound,
			"model %q is unavailable; this service currently provides %q",
			requestedModelID,
			s.modelID,
		)
	}

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
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := tcpHealthcheck(port); err != nil {
			log.Printf("healthcheck failed: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := validateConfiguredIdentifier("MODEL_ID", modelID); err != nil {
		log.Fatal(err)
	}
	if err := validateConfiguredIdentifier("MODEL_VERSION", modelVersion); err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(64*1024),
		grpc.MaxSendMsgSize(1024*1024),
		grpc.MaxConcurrentStreams(32),
	)
	pb.RegisterModelStreamingServiceServer(server, &streamingServer{
		modelID:      modelID,
		modelVersion: modelVersion,
	})

	log.Printf("model-streaming-service listening on %d", port)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("serve failed: %v", err)
	}
}

func validateIdentifier(field, value string, required bool) error {
	if required && value == "" {
		return status.Errorf(codes.InvalidArgument, "%s is required", field)
	}
	if len(value) > 128 {
		return status.Errorf(codes.InvalidArgument, "%s exceeds 128 bytes", field)
	}
	for _, character := range value {
		if character < 32 || character == 127 {
			return status.Errorf(codes.InvalidArgument, "%s contains control characters", field)
		}
	}
	return nil
}

func validateConfiguredIdentifier(field, value string) error {
	if value == "" {
		return status.Errorf(codes.InvalidArgument, "%s must not be empty", field)
	}
	return validateIdentifier(field, value, true)
}

func tcpHealthcheck(port int) error {
	connection, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		time.Second,
	)
	if err != nil {
		return err
	}
	return connection.Close()
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
