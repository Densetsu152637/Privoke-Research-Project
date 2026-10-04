package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	expectedSchema         = 1
	expectedArchitecture   = "privoke_tiny_transformer_v1"
	maxArtifactBytes       = 8 * 1024 * 1024
	maxParameterValues     = 65536
	presenceArchitecture   = "privoke_sparse_presence_v1"
	maxPresenceConfigBytes = 2 * 1024 * 1024
	presenceBlockSize      = 4096
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

    // Inspect root declarations before typed tensor decoding; preserve duplicate evidence.
    scratchDeclared, err := scratchDeclaredInRaw(raw)
    if err != nil { return nil, fmt.Errorf("decode artifact identity: %w", err) }
    if scratchDeclared {
        if err := validateScratchJSON(raw); err != nil { return nil, err }
    }
    var artifact modelArtifact
    if err := json.Unmarshal(raw, &artifact); err != nil {
        return nil, fmt.Errorf("decode artifact: %w", err)
    }
	if artifact.Architecture == presenceArchitecture {
		if err := validatePresenceRawTensorFlags(raw); err != nil {
			return nil, err
		}
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
    file, err := os.Open(path)
    if err != nil { return nil, fmt.Errorf("open artifact: %w", err) }
    defer file.Close()
    raw, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
    if err != nil { return nil, fmt.Errorf("read artifact: %w", err) }
	if len(raw) == 0 || len(raw) > maxArtifactBytes { return nil, fmt.Errorf("artifact bytes exceed supported range") }
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
	if artifact.Architecture != expectedArchitecture && artifact.Architecture != presenceArchitecture && artifact.Architecture != scratchPresenceArchitecture {
		return fmt.Errorf("unsupported artifact architecture %q", artifact.Architecture)
	}
	if expectedModelID != "" && artifact.ModelID != expectedModelID {
		return fmt.Errorf(
			"artifact model %q does not match configured model %q",
			artifact.ModelID,
			expectedModelID,
		)
	}
	if err := validateArtifactMetadata(artifact); err != nil {
		return err
	}
	if err := validateArtifactParameters(artifact.Parameters); err != nil {
		return err
	}
	if artifact.Architecture == scratchPresenceArchitecture || isScratchModelID(artifact.ModelID) {
		return validateScratchArtifact(artifact)
	}
	if artifact.Architecture == presenceArchitecture {
		return validatePresenceArtifact(artifact)
	}
	return nil
}

type presenceBranch struct {
	Analyzer     string   `json:"analyzer"`
	NgramRange   []int    `json:"ngram_range"`
	MaxFeatures  int      `json:"max_features"`
	Features     []string `json:"features"`
	SublinearTF  bool     `json:"sublinear_tf"`
	UseIDF       bool     `json:"use_idf"`
	SmoothIDF    bool     `json:"smooth_idf"`
	Norm         string   `json:"norm"`
	Lowercase    bool     `json:"lowercase"`
	TokenPattern string   `json:"token_pattern"`
}

type presenceConfig struct {
	Task                 string                    `json:"task"`
	Profile              string                    `json:"profile"`
	Threshold            float64                   `json:"threshold"`
	Normalization        string                    `json:"normalization"`
	ColumnOrder          []string                  `json:"column_order"`
	CoefficientBlockSize int                       `json:"coefficient_block_size"`
	Branches             map[string]presenceBranch `json:"branches"`
}

func exactJSONFields(raw json.RawMessage, expected ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(fields) != len(expected) {
		return fmt.Errorf("presence config has missing or unknown fields")
	}
	for _, name := range expected {
		value, ok := fields[name]
		if !ok || string(bytes.TrimSpace(value)) == "null" {
			return fmt.Errorf("presence config is missing/null %q", name)
		}
	}
	return nil
}

func validatePresenceArtifact(artifact *modelArtifact) error {
	if !validJSONUnicode(artifact.Config) {
		return fmt.Errorf("presence config contains invalid Unicode")
	}
	if err := exactJSONFields(artifact.Config, "task", "profile", "threshold", "normalization", "column_order", "coefficient_block_size", "branches"); err != nil {
		return err
	}
	var config presenceConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		return fmt.Errorf("invalid presence config: %w", err)
	}
	// Canonicalize decoded Unicode/configuration before applying the config bound.
	var compact bytes.Buffer
	encoder := json.NewEncoder(&compact)
	encoder.SetEscapeHTML(false)
	var decoded map[string]any
	if err := json.Unmarshal(artifact.Config, &decoded); err != nil {
		return err
	}
	if err := encoder.Encode(decoded); err != nil {
		return err
	}
	if compact.Len()-1 > maxPresenceConfigBytes {
		return fmt.Errorf("presence config exceeds 2 MiB")
	}
	limits := map[string]int{"efficient": 2000, "balanced": 8000, "quality": 16000}
	limit, ok := limits[config.Profile]
	if !ok || artifact.ModelID != "privoke-presence-"+config.Profile {
		return fmt.Errorf("presence profile/model ID mismatch")
	}
	if config.Task != "annotation_presence" || config.Normalization != "training_text_key_v1" {
		return fmt.Errorf("unsupported presence task or normalization")
	}
	if math.IsNaN(config.Threshold) || math.IsInf(config.Threshold, 0) || config.Threshold < 0 || config.Threshold > 1 {
		return fmt.Errorf("invalid presence threshold")
	}
	if len(config.ColumnOrder) != 2 || config.ColumnOrder[0] != "word" || config.ColumnOrder[1] != "char" || config.CoefficientBlockSize != presenceBlockSize {
		return fmt.Errorf("invalid presence column order/block size")
	}
	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(artifact.Config, &rawConfig); err != nil {
		return err
	}
	if err := exactJSONFields(rawConfig["branches"], "word", "char"); err != nil {
		return err
	}
	var rawBranches map[string]json.RawMessage
	if err := json.Unmarshal(rawConfig["branches"], &rawBranches); err != nil {
		return err
	}
	expectedShapes := map[string]int{}
	total := 0
	for _, name := range []string{"word", "char"} {
		fields := []string{"analyzer", "ngram_range", "max_features", "features", "sublinear_tf", "use_idf", "smooth_idf", "norm", "lowercase"}
		if name == "word" {
			fields = append(fields, "token_pattern")
		}
		if err := exactJSONFields(rawBranches[name], fields...); err != nil {
			return err
		}
		branch := config.Branches[name]
		lower, upper := 1, 2
		if name == "char" {
			lower, upper = 3, 5
		}
		if branch.Analyzer != name || len(branch.NgramRange) != 2 || branch.NgramRange[0] != lower || branch.NgramRange[1] != upper || branch.MaxFeatures != limit {
			return fmt.Errorf("invalid presence %s analyzer/profile", name)
		}
		if name == "word" && branch.TokenPattern != `(?u)\b\w\w+\b` {
			return fmt.Errorf("unsupported presence word token pattern")
		}
		if !branch.SublinearTF || !branch.UseIDF || !branch.SmoothIDF || branch.Norm != "l2" || branch.Lowercase {
			return fmt.Errorf("invalid presence TF-IDF settings")
		}
		if len(branch.Features) == 0 || len(branch.Features) > limit {
			return fmt.Errorf("presence vocabulary exceeds profile bound or is empty")
		}
		seen := map[string]bool{}
		for _, feature := range branch.Features {
			if feature == "" || !utf8.ValidString(feature) || seen[feature] {
				return fmt.Errorf("presence vocabulary must contain unique Unicode strings")
			}
			seen[feature] = true
			if name == "word" && !validPresenceWordFeature(feature) {
				return fmt.Errorf("presence word vocabulary violates token rule")
			}
			if size := utf8.RuneCountInString(feature); name == "char" && (size < 3 || size > 5) {
				return fmt.Errorf("presence character n-gram has invalid length")
			}
		}
		expectedShapes["features."+name+".idf"] = len(branch.Features)
		total += len(branch.Features)
	}
	for offset := 0; offset < total; offset += presenceBlockSize {
		expectedShapes[fmt.Sprintf("head.presence.weight.%03d", offset/presenceBlockSize)] = min(presenceBlockSize, total-offset)
	}
	expectedShapes["head.presence.bias"] = 1
	if len(artifact.Parameters) != len(expectedShapes) {
		return fmt.Errorf("presence tensor manifest has missing or unknown tensors")
	}
	for name, size := range expectedShapes {
		tensor, ok := artifact.Parameters[name]
		if !ok || len(tensor.Shape) != 1 || int(tensor.Shape[0]) != size || len(tensor.Values) != size {
			return fmt.Errorf("presence tensor %q has invalid shape", name)
		}
		if tensor.Trainable != strings.HasPrefix(name, "head.presence.") {
			return fmt.Errorf("only presence head tensors may be trainable")
		}
		for _, value := range tensor.Values {
			converted := float32(value)
			if math.IsInf(float64(converted), 0) || math.IsNaN(float64(converted)) || (strings.HasPrefix(name, "features.") && converted <= 0) {
				return fmt.Errorf("presence tensor %q contains invalid float32 values", name)
			}
		}
	}
	return nil
}

func validatePresenceRawTensorFlags(raw []byte) error {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	var parameters map[string]map[string]json.RawMessage
	if err := json.Unmarshal(payload["parameters"], &parameters); err != nil {
		return err
	}
	for name, tensor := range parameters {
		value, ok := tensor["trainable"]
		if !ok || (string(bytes.TrimSpace(value)) != "true" && string(bytes.TrimSpace(value)) != "false") {
			return fmt.Errorf("presence tensor %q requires an explicit boolean trainable flag", name)
		}
	}
	return nil
}

// encoding/json replaces lone surrogate escapes; reject them before decoding.
func validJSONUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return false
		}
		if raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[index+1:index+5]), 16, 16)
		if err != nil {
			return false
		}
		index += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value < 0xD800 || value > 0xDBFF {
			continue
		}
		if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[index+3:index+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		index += 6
	}
	return true
}

func validPresenceWordFeature(feature string) bool {
	tokens := strings.Split(feature, " ")
	if len(tokens) < 1 || len(tokens) > 2 {
		return false
	}
	for _, token := range tokens {
		if utf8.RuneCountInString(token) < 2 {
			return false
		}
		for _, character := range token {
			if character != '_' && !unicode.IsLetter(character) && !unicode.IsNumber(character) {
				return false
			}
		}
	}
	return true
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
