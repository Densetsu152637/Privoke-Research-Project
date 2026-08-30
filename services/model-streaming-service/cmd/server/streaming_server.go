package main

import (
	"context"
	"log"
	"sort"
	"strings"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const parameterChunkValues = 1024

type streamingServer struct {
	pb.UnimplementedModelStreamingServiceServer
	modelID      string
	artifactPath string
}

func (s *streamingServer) GetModelParameters(
	_ context.Context,
	req *pb.ModelParametersRequest,
) (*pb.ModelParametersResponse, error) {
	if err := s.validateRequest(req); err != nil {
		return nil, err
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
	return parameterResponse(artifact, req.GetConsumerId()), nil
}

func (s *streamingServer) validateRequest(req *pb.ModelParametersRequest) error {
	if err := validateIdentifier("consumer_id", req.GetConsumerId(), false); err != nil {
		return err
	}
	if err := validateIdentifier("model_id", req.GetModelId(), false); err != nil {
		return err
	}
	requestedModelID := req.GetModelId()
	if requestedModelID != "" && requestedModelID != s.modelID {
		return status.Errorf(
			codes.NotFound,
			"model %q is unavailable; this service currently provides %q",
			requestedModelID,
			s.modelID,
		)
	}
	return nil
}

func parameterResponse(
	artifact *loadedArtifact,
	consumerID string,
) *pb.ModelParametersResponse {
	parameters, trainableNames := parameterMessages(artifact.Parameters)
	return &pb.ModelParametersResponse{
		ModelId:         artifact.ModelID,
		Version:         artifact.Version,
		GeneratedAtUnix: artifact.GeneratedAtUnix,
		Parameters:      parameters,
		Metadata:        responseMetadata(artifact, consumerID, trainableNames),
	}
}

func parameterMessages(
	tensors map[string]artifactTensor,
) ([]*pb.Parameter, []string) {
	names := make([]string, 0, len(tensors))
	for name := range tensors {
		names = append(names, name)
	}
	sort.Strings(names)

	parameters := make([]*pb.Parameter, 0, len(names))
	trainableNames := make([]string, 0)
	for _, name := range names {
		tensor := tensors[name]
		values := make([]float32, len(tensor.Values))
		for index, value := range tensor.Values {
			values[index] = float32(value)
		}
		parameters = append(parameters, &pb.Parameter{
			Name: name, Values: values, Shape: tensor.Shape,
		})
		if tensor.Trainable {
			trainableNames = append(trainableNames, name)
		}
	}
	return parameters, trainableNames
}

func responseMetadata(
	artifact *loadedArtifact,
	consumerID string,
	trainableNames []string,
) map[string]string {
	metadata := make(map[string]string, len(artifact.Metadata)+7)
	for key, value := range artifact.Metadata {
		metadata[key] = value
	}
	metadata["served_by"] = serviceName
	metadata["consumer_id"] = consumerID
	metadata["architecture"] = artifact.Architecture
	metadata["model_config"] = string(artifact.Config)
	metadata["artifact_checksum"] = artifact.Checksum
	metadata["artifact_file_checksum"] = artifact.fileChecksum
	metadata["trainable_parameters"] = strings.Join(trainableNames, ",")
	return metadata
}

func (s *streamingServer) StreamModelParameters(
	req *pb.ModelParametersRequest,
	stream grpc.ServerStreamingServer[pb.ModelParameterChunk],
) error {
	response, err := s.GetModelParameters(stream.Context(), req)
	if err != nil {
		return err
	}
	totalChunks := parameterChunkCount(response.GetParameters())
	chunkIndex := 0
	for _, parameter := range response.GetParameters() {
		for offset := 0; offset < len(parameter.GetValues()); offset += parameterChunkValues {
			chunk := parameterChunk(response, parameter, offset, chunkIndex, totalChunks)
			if err := stream.Send(chunk); err != nil {
				return err
			}
			chunkIndex++
		}
	}
	return nil
}

func parameterChunkCount(parameters []*pb.Parameter) int {
	total := 0
	for _, parameter := range parameters {
		total += (len(parameter.GetValues()) + parameterChunkValues - 1) / parameterChunkValues
	}
	return total
}

func parameterChunk(
	response *pb.ModelParametersResponse,
	parameter *pb.Parameter,
	offset int,
	chunkIndex int,
	totalChunks int,
) *pb.ModelParameterChunk {
	end := min(offset+parameterChunkValues, len(parameter.GetValues()))
	var metadata map[string]string
	if chunkIndex == 0 {
		metadata = response.GetMetadata()
	}
	return &pb.ModelParameterChunk{
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
	}
}

func (s *streamingServer) Health(
	context.Context,
	*pb.HealthRequest,
) (*pb.HealthResponse, error) {
	serviceStatus := "SERVING"
	if _, err := loadModelArtifact(s.artifactPath, s.modelID); err != nil {
		serviceStatus = "NOT_SERVING"
	}
	return &pb.HealthResponse{Service: serviceName, Status: serviceStatus}, nil
}
