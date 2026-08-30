package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

const (
	expectedSchema       = 1
	expectedArchitecture = "privoke_tiny_transformer_v1"
	maxArtifactBytes     = 8 * 1024 * 1024
	maxParameterValues   = 65536
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

func loadModelArtifact(path string, expectedModelID string) (*loadedArtifact, error) {
	raw, err := readArtifactFile(path)
	if err != nil {
		return nil, err
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

func readArtifactFile(path string) ([]byte, error) {
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
	return raw, nil
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
		return fmt.Errorf(
			"artifact model %q does not match configured model %q",
			artifact.ModelID,
			expectedModelID,
		)
	}
	if err := validateArtifactMetadata(artifact); err != nil {
		return err
	}
	return validateArtifactParameters(artifact.Parameters)
}

func validateArtifactMetadata(artifact *modelArtifact) error {
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
	checksumBytes, err := hex.DecodeString(artifact.Checksum)
	if err != nil || len(checksumBytes) != sha256.Size {
		return fmt.Errorf("artifact checksum must be a SHA-256 value")
	}
	if len(artifact.Parameters) == 0 {
		return fmt.Errorf("artifact has no parameters")
	}
	return nil
}

func validateArtifactParameters(parameters map[string]artifactTensor) error {
	totalValues := 0
	for name, tensor := range parameters {
		if err := validateIdentifier("parameter name", name, true); err != nil {
			return err
		}
		if err := validateTensor(name, tensor); err != nil {
			return err
		}
		totalValues += len(tensor.Values)
		if totalValues > maxParameterValues {
			return fmt.Errorf("artifact exceeds %d values", maxParameterValues)
		}
	}
	return nil
}

func validateTensor(name string, tensor artifactTensor) error {
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
	return nil
}
