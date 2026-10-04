package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const liveScratchID = "privoke-scratch-presence-efficient-head-only"

func TestScratchCatalogServesFileInstalledAfterConstruction(t *testing.T) {
	server, directory := newLiveScratchServer(t)
	if server.catalog.contains(liveScratchID) {
		t.Fatal("scratch ID was present before its file was installed")
	}
	if got := server.catalog.modelIDs(); len(got) != 1 || got[0] != "privoke-baseline" {
		t.Fatalf("unexpected initial catalog IDs: %v", got)
	}

	raw := scratchLiveArtifactBytes(t, 1)
	installLiveScratch(t, directory, raw)
	response := getLiveScratch(t, server)
	if response.GetModelId() != liveScratchID || response.GetVersion() != "v1.0.0+epoch.1" {
		t.Fatalf("unexpected installed model identity: %q %q", response.GetModelId(), response.GetVersion())
	}
	want := sha256.Sum256(raw)
	if response.GetMetadata()["artifact_file_checksum"] != hex.EncodeToString(want[:]) {
		t.Fatal("served file checksum does not bind installed bytes")
	}
	if !server.catalog.contains(liveScratchID) {
		t.Fatal("installed scratch ID is absent from catalog lookup")
	}

	latest, err := server.GetModelParameters(context.Background(), &pb.ModelParametersRequest{ModelId: "latest"})
	if err != nil {
		t.Fatalf("latest request failed after scratch install: %v", err)
	}
	if latest.GetModelId() != "privoke-baseline" {
		t.Fatalf("scratch install changed latest to %q", latest.GetModelId())
	}
}

func TestAllSixScratchIDsAreServedAfterCatalogConstruction(t *testing.T) {
	for _, profile := range []string{"efficient", "balanced", "quality"} {
		for _, mode := range []string{"head_only", "end_to_end"} {
			suffix := "head-only"
			if mode == "end_to_end" {
				suffix = "full-encoder"
			}
			modelID := "privoke-scratch-presence-" + profile + "-" + suffix
			t.Run(modelID, func(t *testing.T) {
				if !isScratchModelID(modelID) {
					t.Fatalf("test ID is not in the exact scratch allowlist: %q", modelID)
				}
				server, directory := newLiveScratchServer(t)
				config := scratchConfig{Task: "annotation_presence", Profile: profile, TrainingMode: mode, VocabSize: scratchProfiles[profile][0], HiddenSize: scratchProfiles[profile][1], IntermediateSize: scratchProfiles[profile][2], MaxTokens: scratchProfiles[profile][3], NumLayers: scratchProfiles[profile][4], NumAttentionHeads: scratchProfiles[profile][5], Normalization: "detector_normalize_text_v1", Tokenizer: "legacy_sha256_bucket_tokens_v1", Pooling: "half_first_half_real_mean_v1", Arithmetic: "float32_numpy_encoder_clipped_sigmoid_v1", Threshold: 0.5}
				raw := scratchLiveArtifactFor(t, modelID, config, 1)
				if err := os.WriteFile(filepath.Join(directory, modelID+".json"), raw, 0o600); err != nil {
					t.Fatal(err)
				}
				request := liveScratchRequest()
				request.ModelId = modelID
				response, err := server.GetModelParameters(context.Background(), request)
				if err != nil {
					t.Fatalf("explicit scratch request failed: %v", err)
				}
				if response.GetModelId() != modelID || response.GetVersion() != "v1.0.0+epoch.1" {
					t.Fatalf("unexpected scratch identity: %q %q", response.GetModelId(), response.GetVersion())
				}
			})
		}
	}
}

func TestScratchCatalogSeesAtomicReplacementAndRemoval(t *testing.T) {
	server, directory := newLiveScratchServer(t)
	first := scratchLiveArtifactBytes(t, 1)
	installLiveScratch(t, directory, first)
	if got := getLiveScratch(t, server).GetVersion(); got != "v1.0.0+epoch.1" {
		t.Fatalf("initial version = %q", got)
	}

	second := scratchLiveArtifactBytes(t, 2)
	atomicInstallLiveScratch(t, directory, second)
	response := getLiveScratch(t, server)
	if response.GetVersion() != "v1.0.0+epoch.2" {
		t.Fatalf("replacement version = %q", response.GetVersion())
	}
	want := sha256.Sum256(second)
	if response.GetMetadata()["artifact_file_checksum"] != hex.EncodeToString(want[:]) {
		t.Fatal("replacement response retained the previous file identity")
	}

	if err := os.Remove(liveScratchPath(directory)); err != nil {
		t.Fatal(err)
	}
	if server.catalog.contains(liveScratchID) {
		t.Fatal("removed scratch ID remains in catalog lookup")
	}
	_, err := server.GetModelParameters(context.Background(), liveScratchRequest())
	if status.Code(err) != codes.NotFound {
		t.Fatalf("removed scratch request status = %v, want NOT_FOUND", err)
	}
	if got := getLiveLatest(t, server); got != "privoke-baseline" {
		t.Fatalf("removing scratch changed latest to %q", got)
	}
}

func TestScratchOptionalFilesDoNotBreakBaselineHealthButInvalidFilesDo(t *testing.T) {
	server, directory := newLiveScratchServer(t)
	assertLiveScratchHealth(t, server, "SERVING")

	if err := os.WriteFile(liveScratchPath(directory), []byte(`{"not":"an artifact"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := server.GetModelParameters(context.Background(), liveScratchRequest())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("invalid installed scratch status = %v, want UNAVAILABLE", err)
	}
	assertLiveScratchHealth(t, server, "NOT_SERVING")

	if err := os.Remove(liveScratchPath(directory)); err != nil {
		t.Fatal(err)
	}
	assertLiveScratchHealth(t, server, "SERVING")
}

func TestScratchCatalogRejectsSymlinkDirectoryAndWrongIdentity(t *testing.T) {
	t.Run("symlink outside catalog", func(t *testing.T) {
		server, directory := newLiveScratchServer(t)
		target := filepath.Join(t.TempDir(), "outside.json")
		if err := os.WriteFile(target, scratchLiveArtifactBytes(t, 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, liveScratchPath(directory)); err != nil {
			t.Skipf("symlinks are unavailable on this platform: %v", err)
		}
		_, err := server.GetModelParameters(context.Background(), liveScratchRequest())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("symlink request status = %v, want UNAVAILABLE", err)
		}
		assertLiveScratchHealth(t, server, "NOT_SERVING")
	})

	t.Run("directory at canonical filename", func(t *testing.T) {
		server, directory := newLiveScratchServer(t)
		if err := os.Mkdir(liveScratchPath(directory), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := server.GetModelParameters(context.Background(), liveScratchRequest())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("directory request status = %v, want UNAVAILABLE", err)
		}
		assertLiveScratchHealth(t, server, "NOT_SERVING")
	})

	t.Run("wrong model identity", func(t *testing.T) {
		server, directory := newLiveScratchServer(t)
		raw, err := os.ReadFile(scratchFixturePath())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(liveScratchPath(directory), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		// A known filename cannot authorize a different ID inside its payload.
		wrong := "privoke-scratch-presence-efficient-full-encoder"
		if err := os.Rename(liveScratchPath(directory), filepath.Join(directory, wrong+".json")); err != nil {
			t.Fatal(err)
		}
		_, err = server.GetModelParameters(context.Background(), liveScratchRequest())
		if status.Code(err) != codes.NotFound {
			t.Fatalf("missing canonical ID status = %v, want NOT_FOUND", err)
		}
		request := liveScratchRequest()
		request.ModelId = wrong
		_, err = server.GetModelParameters(context.Background(), request)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("wrong identity status = %v, want UNAVAILABLE", err)
		}
	})
}

func TestScratchCatalogRejectsUnknownAndTraversalIDs(t *testing.T) {
	server, directory := newLiveScratchServer(t)
	if err := os.WriteFile(filepath.Join(directory, "privoke-scratch-presence-evil.json"), scratchLiveArtifactBytes(t, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, modelID := range []string{"privoke-scratch-presence-evil", "../privoke-baseline", "privoke-baseline/../../outside"} {
		t.Run(modelID, func(t *testing.T) {
			request := liveScratchRequest()
			request.ModelId = modelID
			if _, err := server.GetModelParameters(context.Background(), request); err == nil {
				t.Fatal("unallowlisted model ID was served")
			}
		})
	}
	if got := getLiveLatest(t, server); got != "privoke-baseline" {
		t.Fatalf("unknown files changed latest to %q", got)
	}
}

func TestScratchCatalogConcurrentReadsInstallAndRemove(t *testing.T) {
	server, directory := newLiveScratchServer(t)
	initial := scratchLiveArtifactBytes(t, 1)
	installLiveScratch(t, directory, initial)

	var readers sync.WaitGroup
	failures := make(chan error, 8)
	for reader := 0; reader < 8; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for attempt := 0; attempt < 30; attempt++ {
				_, err := server.GetModelParameters(context.Background(), liveScratchRequest())
				if err == nil {
					continue
				}
				if code := status.Code(err); code != codes.NotFound && code != codes.Unavailable {
					failures <- err
					return
				}
			}
		}()
	}
	for iteration := 0; iteration < 20; iteration++ {
		if iteration%2 == 0 {
			if err := os.Remove(liveScratchPath(directory)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		atomicInstallLiveScratch(t, directory, scratchLiveArtifactBytes(t, 1+(iteration%2)))
	}
	readers.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("unexpected concurrent request error: %v", err)
	}
	if err := os.Remove(liveScratchPath(directory)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	assertLiveScratchHealth(t, server, "SERVING")
	if server.catalog.contains(liveScratchID) {
		t.Fatal("removed ID remained in the live catalog")
	}
}

func newLiveScratchServer(t *testing.T) (*streamingServer, string) {
	t.Helper()
	directory := t.TempDir()
	baseline, err := os.ReadFile(writeTestArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "privoke-baseline.json"), baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := loadModelCatalog(directory, "privoke-baseline")
	if err != nil {
		t.Fatalf("construct baseline catalog: %v", err)
	}
	return &streamingServer{catalog: catalog}, directory
}

func scratchLiveArtifactBytes(t *testing.T, epoch int) []byte {
	t.Helper()
	config := scratchConfig{Task: "annotation_presence", Profile: "efficient", TrainingMode: "head_only", VocabSize: 512, HiddenSize: 24, IntermediateSize: 48, MaxTokens: 64, NumLayers: 1, NumAttentionHeads: 2, Normalization: "detector_normalize_text_v1", Tokenizer: "legacy_sha256_bucket_tokens_v1", Pooling: "half_first_half_real_mean_v1", Arithmetic: "float32_numpy_encoder_clipped_sigmoid_v1", Threshold: 0.5}
	return scratchLiveArtifactFor(t, liveScratchID, config, epoch)
}

func scratchLiveArtifactFor(t *testing.T, modelID string, config scratchConfig, epoch int) []byte {
	t.Helper()
	raw, err := os.ReadFile(scratchFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	var artifact modelArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.ModelID = modelID
	artifact.Version = "v1.0.0+epoch." + strconv.Itoa(epoch)
	artifact.Metadata["checkpoint_epoch"] = strconv.Itoa(epoch)
	artifact.Config, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Parameters = make(map[string]artifactTensor)
	for name, shape := range scratchShapes(config) {
		count := 1
		for _, dimension := range shape {
			count *= int(dimension)
		}
		trainable := config.TrainingMode == "end_to_end" || name == "head.presence.weight" || name == "head.presence.bias"
		artifact.Parameters[name] = artifactTensor{Shape: shape, Values: make([]float64, count), Trainable: trainable}
	}
	artifact.Checksum = ""
	payload, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Checksum, err = calculateArtifactChecksum(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func installLiveScratch(t *testing.T, directory string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(liveScratchPath(directory), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func atomicInstallLiveScratch(t *testing.T, directory string, raw []byte) {
	t.Helper()
	temporary := filepath.Join(directory, "scratch-install.tmp")
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, liveScratchPath(directory)); err != nil {
		t.Fatal(err)
	}
}

func liveScratchPath(directory string) string {
	return filepath.Join(directory, liveScratchID+".json")
}

func liveScratchRequest() *pb.ModelParametersRequest {
	return &pb.ModelParametersRequest{ModelId: liveScratchID, ConsumerId: "catalog-live-test"}
}

func getLiveScratch(t *testing.T, server *streamingServer) *pb.ModelParametersResponse {
	t.Helper()
	response, err := server.GetModelParameters(context.Background(), liveScratchRequest())
	if err != nil {
		t.Fatalf("scratch request failed: %v", err)
	}
	return response
}

func getLiveLatest(t *testing.T, server *streamingServer) string {
	t.Helper()
	response, err := server.GetModelParameters(context.Background(), &pb.ModelParametersRequest{ModelId: "latest"})
	if err != nil {
		t.Fatalf("latest request failed: %v", err)
	}
	return response.GetModelId()
}

func assertLiveScratchHealth(t *testing.T, server *streamingServer, expected string) {
	t.Helper()
	response, err := server.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	if response.GetStatus() != expected {
		t.Fatalf("health status = %q, want %q", response.GetStatus(), expected)
	}
}