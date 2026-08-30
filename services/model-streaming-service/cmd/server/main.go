package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	expectedSchema       = 1
	expectedArchitecture = "privoke_tiny_transformer_v1"
	maxArtifactBytes     = 8 * 1024 * 1024
	maxParameterValues   = 65536
	parameterChunkValues = 1024
)

type artifactTensor struct {
	Shape     []uint32  `json:"shape"`
	Values    []float64 `json:"values"`
	Trainable bool      `json:"trainable"`
}

type modelArtifact struct {
	SchemaVersion   int                       `json:"schema_version"`
	ModelID         string                    `json:"model_id"`
	Version         string                    `json:"version"`
	GeneratedAtUnix int64                     `json:"generated_at_unix"`
	Architecture    string                    `json:"architecture"`
	Config          json.RawMessage           `json:"config"`
	Parameters      map[string]artifactTensor `json:"parameters"`
	Metadata        map[string]string         `json:"metadata"`
	Checksum        string                    `json:"checksum"`
}

type loadedArtifact struct {
	modelArtifact
	fileChecksum string
}

type streamingServer struct {
	pb.UnimplementedModelStreamingServiceServer
	modelID      string
	artifactPath string
}

func (s *streamingServer) GetModelParameters(_ context.Context, req *pb.ModelParametersRequest) (*pb.ModelParametersResponse, error) {
	if err := validateIdentifier("consumer_id", req.GetConsumerId(), false); err != nil {
		return nil, err
	}
	if err := validateIdentifier("model_id", req.GetModelId(), false); err != nil {
		return nil, err
	}
	if requestedModelID := req.GetModelId(); requestedModelID != "" && requestedModelID != s.modelID {
		return nil, status.Errorf(
			codes.NotFound,
			"model %q is unavailable; this service currently provides %q",
			requestedModelID,
			s.modelID,
		)
	}

	artifact, err := loadModelArtifact(s.artifactPath, s.modelID)
	if err != nil {
		log.Printf("model artifact load failed: %v", err)
		return nil, status.Error(codes.Unavailable, "model artifact is unavailable")
	}
	log.Printf(
		"parameter request consumer=%q model=%q version=%q",
		req.GetConsumerId(),
		artifact.ModelID,
		artifact.Version,
	)

	parameterNames := make([]string, 0, len(artifact.Parameters))
	for name := range artifact.Parameters {
		parameterNames = append(parameterNames, name)
	}
	sort.Strings(parameterNames)
	parameters := make([]*pb.Parameter, 0, len(parameterNames))
	trainableNames := make([]string, 0)
	for _, name := range parameterNames {
		tensor := artifact.Parameters[name]
		values := make([]float32, len(tensor.Values))
		for index, value := range tensor.Values {
			values[index] = float32(value)
		}
		parameters = append(parameters, &pb.Parameter{
			Name:   name,
			Values: values,
			Shape:  tensor.Shape,
		})
		if tensor.Trainable {
			trainableNames = append(trainableNames, name)
		}
	}

	metadata := make(map[string]string, len(artifact.Metadata)+6)
	for key, value := range artifact.Metadata {
		metadata[key] = value
	}
	metadata["served_by"] = "model-streaming-service"
	metadata["consumer_id"] = req.GetConsumerId()
	metadata["architecture"] = artifact.Architecture
	metadata["model_config"] = string(artifact.Config)
	metadata["artifact_checksum"] = artifact.Checksum
	metadata["artifact_file_checksum"] = artifact.fileChecksum
	metadata["trainable_parameters"] = strings.Join(trainableNames, ",")

	return &pb.ModelParametersResponse{
		ModelId:         artifact.ModelID,
		Version:         artifact.Version,
		GeneratedAtUnix: artifact.GeneratedAtUnix,
		Parameters:      parameters,
		Metadata:        metadata,
	}, nil
}

func (s *streamingServer) StreamModelParameters(
	req *pb.ModelParametersRequest,
	stream grpc.ServerStreamingServer[pb.ModelParameterChunk],
) error {
	response, err := s.GetModelParameters(stream.Context(), req)
	if err != nil {
		return err
	}
	totalChunks := 0
	for _, parameter := range response.GetParameters() {
		totalChunks += (len(parameter.GetValues()) + parameterChunkValues - 1) / parameterChunkValues
	}

	chunkIndex := 0
	for _, parameter := range response.GetParameters() {
		for offset := 0; offset < len(parameter.GetValues()); offset += parameterChunkValues {
			end := offset + parameterChunkValues
			if end > len(parameter.GetValues()) {
				end = len(parameter.GetValues())
			}
			metadata := map[string]string(nil)
			if chunkIndex == 0 {
				metadata = response.GetMetadata()
			}
			if err := stream.Send(&pb.ModelParameterChunk{
				ModelId:         response.GetModelId(),
				Version:         response.GetVersion(),
				GeneratedAtUnix: response.GetGeneratedAtUnix(),
				Parameter: &pb.ParameterChunk{
					Name:        parameter.GetName(),
					Shape:       parameter.GetShape(),
					ValueOffset: uint32(offset),
					Values:      parameter.GetValues()[offset:end],
				},
				Metadata:    metadata,
				ChunkIndex:  uint32(chunkIndex),
				TotalChunks: uint32(totalChunks),
			}); err != nil {
				return err
			}
			chunkIndex++
		}
	}
	return nil
}

func (s *streamingServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	serviceStatus := "SERVING"
	if _, err := loadModelArtifact(s.artifactPath, s.modelID); err != nil {
		serviceStatus = "NOT_SERVING"
	}
	return &pb.HealthResponse{
		Service: "model-streaming-service",
		Status:  serviceStatus,
	}, nil
}

func loadModelArtifact(path string, expectedModelID string) (*loadedArtifact, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat artifact: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact must not be a symbolic link")
	}
	if info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return nil, fmt.Errorf("artifact size %d is outside the supported range", info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	var artifact modelArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, fmt.Errorf("decode artifact: %w", err)
	}
	checksum, err := calculateArtifactChecksum(raw)
	if err != nil {
		return nil, fmt.Errorf("calculate artifact checksum: %w", err)
	}
	if artifact.Checksum != checksum {
		return nil, fmt.Errorf("artifact checksum does not match its contents")
	}
	if err := validateModelArtifact(&artifact, expectedModelID); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return &loadedArtifact{
		modelArtifact: artifact,
		fileChecksum:  hex.EncodeToString(digest[:]),
	}, nil
}

func calculateArtifactChecksum(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return "", err
	}
	delete(payload, "checksum")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:]), nil
}

func validateModelArtifact(artifact *modelArtifact, expectedModelID string) error {
	if artifact.SchemaVersion != expectedSchema {
		return fmt.Errorf("unsupported artifact schema %d", artifact.SchemaVersion)
	}
	if artifact.Architecture != expectedArchitecture {
		return fmt.Errorf("unsupported artifact architecture %q", artifact.Architecture)
	}
	if artifact.ModelID != expectedModelID {
		return fmt.Errorf("artifact model %q does not match configured model %q", artifact.ModelID, expectedModelID)
	}
	if err := validateConfiguredIdentifier("artifact model_id", artifact.ModelID); err != nil {
		return err
	}
	if err := validateConfiguredIdentifier("artifact version", artifact.Version); err != nil {
		return err
	}
	if artifact.GeneratedAtUnix <= 0 {
		return fmt.Errorf("artifact generated_at_unix must be positive")
	}
	if len(artifact.Config) == 0 || !json.Valid(artifact.Config) {
		return fmt.Errorf("artifact config must be valid JSON")
	}
	if checksumBytes, err := hex.DecodeString(artifact.Checksum); err != nil || len(checksumBytes) != sha256.Size {
		return fmt.Errorf("artifact checksum must be a SHA-256 value")
	}
	if len(artifact.Parameters) == 0 {
		return fmt.Errorf("artifact has no parameters")
	}

	totalValues := 0
	for name, tensor := range artifact.Parameters {
		if err := validateIdentifier("parameter name", name, true); err != nil {
			return err
		}
		if len(tensor.Shape) == 0 || len(tensor.Values) == 0 {
			return fmt.Errorf("parameter %q has no shape or values", name)
		}
		expectedValues := uint64(1)
		for _, dimension := range tensor.Shape {
			if dimension == 0 {
				return fmt.Errorf("parameter %q has a zero dimension", name)
			}
			expectedValues *= uint64(dimension)
			if expectedValues > maxParameterValues {
				return fmt.Errorf("parameter %q is too large", name)
			}
		}
		if expectedValues != uint64(len(tensor.Values)) {
			return fmt.Errorf("parameter %q shape does not match values", name)
		}
		for _, value := range tensor.Values {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("parameter %q contains a non-finite value", name)
			}
		}
		totalValues += len(tensor.Values)
		if totalValues > maxParameterValues {
			return fmt.Errorf("artifact exceeds %d values", maxParameterValues)
		}
	}
	return nil
}

func main() {
	port := envInt("MODEL_STREAMING_PORT", 50051)
	modelID := envString("MODEL_ID", "privoke-baseline")
	artifactPath := envString("MODEL_ARTIFACT_PATH", "/models/privoke-baseline.json")
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := grpcHealthcheck(port); err != nil {
			log.Printf("healthcheck failed: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := validateConfiguredIdentifier("MODEL_ID", modelID); err != nil {
		log.Fatal(err)
	}
	if _, err := loadModelArtifact(artifactPath, modelID); err != nil {
		log.Fatalf("load model artifact: %v", err)
	}

	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(64*1024),
		grpc.MaxSendMsgSize(8*1024*1024),
		grpc.MaxConcurrentStreams(32),
	)
	pb.RegisterModelStreamingServiceServer(server, &streamingServer{
		modelID:      modelID,
		artifactPath: artifactPath,
	})

	log.Printf("model-streaming-service listening on %d artifact=%q", port, artifactPath)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("serve failed: %v", err)
	}
}

func validateIdentifier(field, value string, required bool) error {
	if required && value == "" {
		return status.Errorf(codes.InvalidArgument, "%s is required", field)
	}
	if len(value) > 256 {
		return status.Errorf(codes.InvalidArgument, "%s exceeds 256 bytes", field)
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

func grpcHealthcheck(port int) error {
	connection, err := grpc.NewClient(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := pb.NewModelStreamingServiceClient(connection).Health(
		ctx,
		&pb.HealthRequest{},
	)
	if err != nil {
		return err
	}
	if response.GetService() != "model-streaming-service" || response.GetStatus() != "SERVING" {
		return fmt.Errorf(
			"unexpected health response service=%q status=%q",
			response.GetService(),
			response.GetStatus(),
		)
	}
	return nil
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
