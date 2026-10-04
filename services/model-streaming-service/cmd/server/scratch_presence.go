package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "math"
    "regexp"
    "strconv"
)

const scratchPresenceArchitecture = "privoke_scratch_presence_transformer_v1"
const maxScratchConfigBytes = 8192

var scratchProfiles = map[string][6]int{
    "efficient": {512, 24, 48, 64, 1, 2},
    "balanced": {512, 32, 64, 96, 2, 4},
    "quality": {768, 32, 64, 128, 3, 4},
}
var scratchHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var scratchRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var scratchVersion = regexp.MustCompile(`^v1\.0\.0\+epoch\.([1-9]|10)$`)
var scratchSteps = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

func isScratchModelID(id string) bool {
    for profile := range scratchProfiles {
        for _, suffix := range []string{"head-only", "full-encoder"} {
            if id == "privoke-scratch-presence-"+profile+"-"+suffix { return true }
        }
    }
    return false
}

type scratchConfig struct {
    Task string `json:"task"`
    Profile string `json:"profile"`
    TrainingMode string `json:"training_mode"`
    VocabSize int `json:"vocab_size"`
    HiddenSize int `json:"hidden_size"`
    IntermediateSize int `json:"intermediate_size"`
    MaxTokens int `json:"max_tokens"`
    NumLayers int `json:"num_layers"`
    NumAttentionHeads int `json:"num_attention_heads"`
    Normalization string `json:"normalization"`
    Tokenizer string `json:"tokenizer"`
    Pooling string `json:"pooling"`
    Arithmetic string `json:"arithmetic"`
    Threshold float64 `json:"threshold"`
}

// Root declarations are inspected as raw values, including duplicate identity fields.
func scratchDeclaredInRaw(raw []byte) (bool, error) {
    decoder := json.NewDecoder(bytes.NewReader(raw))
    token, err := decoder.Token(); if err != nil { return false, err }
    if token != json.Delim('{') { return false, fmt.Errorf("artifact must be an object") }
    declared := false
    for decoder.More() {
        token, err := decoder.Token(); if err != nil { return false, err }
        key, ok := token.(string); if !ok { return false, fmt.Errorf("invalid artifact key") }
        var value json.RawMessage
        if err := decoder.Decode(&value); err != nil { return false, err }
        if key == "architecture" || key == "model_id" {
            var text string
            if json.Unmarshal(value, &text) == nil && ((key == "architecture" && text == scratchPresenceArchitecture) || (key == "model_id" && isScratchModelID(text))) { declared = true }
        }
    }
    return declared, nil
}

// Reject duplicates before any map or typed decoding can discard their evidence.
func validateScratchJSON(raw []byte) error {
    if len(raw) > maxArtifactBytes || !validJSONUnicode(raw) { return fmt.Errorf("invalid scratch JSON bytes") }
    decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.UseNumber()
    var value func() error
    value = func() error {
        token, err := decoder.Token(); if err != nil { return err }
        delimiter, ok := token.(json.Delim); if !ok { return nil }
        switch delimiter {
        case '{':
            seen := map[string]bool{}
            for decoder.More() {
                token, err := decoder.Token(); if err != nil { return err }
                key, ok := token.(string); if !ok || seen[key] { return fmt.Errorf("duplicate scratch JSON field") }
                seen[key] = true
                if err := value(); err != nil { return err }
            }
        case '[':
            for decoder.More() { if err := value(); err != nil { return err } }
        default: return fmt.Errorf("invalid scratch JSON delimiter")
        }
        _, err = decoder.Token(); return err
    }
    if err := value(); err != nil { return err }
    if _, err := decoder.Token(); err != io.EOF { return fmt.Errorf("trailing scratch JSON data") }
    if err := exactJSONFields(raw, "schema_version", "model_id", "version", "generated_at_unix", "architecture", "config", "parameters", "metadata", "checksum"); err != nil { return err }
    var fields map[string]json.RawMessage
    if err := json.Unmarshal(raw, &fields); err != nil { return err }
    var tensors map[string]json.RawMessage
    if err := json.Unmarshal(fields["parameters"], &tensors); err != nil { return err }
    for _, tensor := range tensors {
        if err := exactJSONFields(tensor, "shape", "values", "trainable"); err != nil { return err }
        var fields map[string]json.RawMessage
        if err := json.Unmarshal(tensor, &fields); err != nil { return err }
        flag := string(bytes.TrimSpace(fields["trainable"]))
        if flag != "true" && flag != "false" { return fmt.Errorf("scratch trainable flag must be explicit boolean") }
    }
    return nil
}

func validateScratchArtifact(artifact *modelArtifact) error {
    if artifact.Architecture != scratchPresenceArchitecture || !isScratchModelID(artifact.ModelID) { return fmt.Errorf("scratch architecture/model ID mismatch") }
    if err := exactJSONFields(artifact.Config, "task", "profile", "training_mode", "vocab_size", "hidden_size", "intermediate_size", "max_tokens", "num_layers", "num_attention_heads", "normalization", "tokenizer", "pooling", "arithmetic", "threshold"); err != nil { return err }
    var compact bytes.Buffer
    if err := json.Compact(&compact, artifact.Config); err != nil || compact.Len() > maxScratchConfigBytes { return fmt.Errorf("scratch config exceeds 8 KiB or is invalid") }
    if !validJSONUnicode(artifact.Config) { return fmt.Errorf("invalid scratch config Unicode") }
    var config scratchConfig
    if err := json.Unmarshal(artifact.Config, &config); err != nil { return fmt.Errorf("invalid scratch config") }
    dims, ok := scratchProfiles[config.Profile]
    if !ok || dims != [6]int{config.VocabSize, config.HiddenSize, config.IntermediateSize, config.MaxTokens, config.NumLayers, config.NumAttentionHeads} { return fmt.Errorf("scratch profile dimensions mismatch") }
    suffix := "head-only"
    if config.TrainingMode == "end_to_end" { suffix = "full-encoder" } else if config.TrainingMode != "head_only" { return fmt.Errorf("unsupported scratch training mode") }
    if artifact.ModelID != "privoke-scratch-presence-"+config.Profile+"-"+suffix { return fmt.Errorf("scratch mode/profile identity mismatch") }
    if config.Task != "annotation_presence" || config.Normalization != "detector_normalize_text_v1" || config.Tokenizer != "legacy_sha256_bucket_tokens_v1" || config.Pooling != "half_first_half_real_mean_v1" || config.Arithmetic != "float32_numpy_encoder_clipped_sigmoid_v1" || config.Threshold != 0.5 { return fmt.Errorf("unsupported scratch inference contract") }
    if !scratchHash.MatchString(artifact.Checksum) { return fmt.Errorf("invalid scratch artifact checksum") }
    epoch := scratchVersion.FindStringSubmatch(artifact.Version)
    if epoch == nil { return fmt.Errorf("invalid scratch checkpoint version") }
    if err := validateScratchMetadata(artifact.Metadata, epoch[1]); err != nil { return err }
    expected := scratchShapes(config)
    if len(artifact.Parameters) != len(expected) { return fmt.Errorf("scratch tensor inventory mismatch") }
    for name, shape := range expected {
        tensor, ok := artifact.Parameters[name]
        if !ok || len(tensor.Shape) != len(shape) { return fmt.Errorf("scratch tensor shape mismatch") }
        size := 1
        for index, dimension := range shape { if tensor.Shape[index] != dimension { return fmt.Errorf("scratch tensor shape mismatch") }; size *= int(dimension) }
        if len(tensor.Values) != size { return fmt.Errorf("scratch tensor count mismatch") }
        trainable := config.TrainingMode == "end_to_end" || name == "head.presence.weight" || name == "head.presence.bias"
        if tensor.Trainable != trainable { return fmt.Errorf("scratch offline trainability mismatch") }
        for _, value := range tensor.Values {
            if math.IsNaN(value) || math.IsInf(value, 0) || float64(float32(value)) != value { return fmt.Errorf("scratch tensor requires exact finite float32 values") }
        }
    }
    return nil
}

func scratchShapes(config scratchConfig) map[string][]uint32 {
    h, i := uint32(config.HiddenSize), uint32(config.IntermediateSize)
    expected := map[string][]uint32{
        "token_embedding": {uint32(config.VocabSize), h}, "position_embedding": {uint32(config.MaxTokens), h},
        "head.presence.weight": {h, 1}, "head.presence.bias": {1},
    }
    block := map[string][]uint32{"attention.query.weight": {h,h}, "attention.key.weight": {h,h}, "attention.value.weight": {h,h}, "attention.output.weight": {h,h}, "attention.output.bias": {h}, "ffn.input.weight": {h,i}, "ffn.input.bias": {i}, "ffn.output.weight": {i,h}, "ffn.output.bias": {h}}
    for layer := 0; layer < config.NumLayers; layer++ {
        prefix := ""; if config.NumLayers != 1 { prefix = fmt.Sprintf("layers.%d.", layer) }
        for name, shape := range block { expected[prefix+name] = shape }
    }
    return expected
}

func validateScratchMetadata(metadata map[string]string, epoch string) error {
    keys := []string{"training_route", "source_revision", "study_plan_sha256", "prepared_manifest_sha256", "initialization_sha256", "trainer_contract_sha256", "checkpoint_epoch", "training_steps", "training_seed"}
    if len(metadata) != len(keys) { return fmt.Errorf("scratch metadata inventory mismatch") }
    for _, key := range keys {
        value, ok := metadata[key]; if !ok { return fmt.Errorf("missing scratch metadata") }
        for _, character := range value { if character > 127 { return fmt.Errorf("scratch metadata must be ASCII") } }
    }
    if metadata["training_route"] != "offline_release_fit_v1" || metadata["training_seed"] != "12102026" || !scratchRevision.MatchString(metadata["source_revision"]) || metadata["checkpoint_epoch"] != epoch { return fmt.Errorf("invalid scratch provenance") }
    for _, key := range []string{"study_plan_sha256", "prepared_manifest_sha256", "initialization_sha256", "trainer_contract_sha256"} { if !scratchHash.MatchString(metadata[key]) { return fmt.Errorf("invalid scratch provenance digest") } }
    steps, err := strconv.Atoi(metadata["training_steps"])
    if err != nil || !scratchSteps.MatchString(metadata["training_steps"]) || steps > 2500 { return fmt.Errorf("invalid scratch training steps") }
    return nil
}
