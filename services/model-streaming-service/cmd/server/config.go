package main

import (
	"fmt"
	"os"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultPort          = 50051
	defaultLatestModelID = "privoke-balanced"
	defaultArtifactDir   = "/models"
)

type serverConfig struct {
	port          int
	latestModelID string
	artifactDir   string
}

func loadServerConfig() (serverConfig, error) {
	port, err := envInt("MODEL_STREAMING_PORT", defaultPort)
	if err != nil {
		return serverConfig{}, err
	}
	config := serverConfig{
		port:          port,
		latestModelID: envString("MODEL_LATEST_ID", defaultLatestModelID),
		artifactDir:   envString("MODEL_ARTIFACT_DIR", defaultArtifactDir),
	}
	if config.port < 1 || config.port > 65535 {
		return serverConfig{}, fmt.Errorf("MODEL_STREAMING_PORT must be between 1 and 65535")
	}
	if err := validateConfiguredIdentifier("MODEL_LATEST_ID", config.latestModelID); err != nil {
		return serverConfig{}, err
	}
	return config, nil
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

func envString(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}
