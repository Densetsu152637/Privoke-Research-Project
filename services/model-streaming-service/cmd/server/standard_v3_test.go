package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestStandardV3DefaultAndMissingStoreFailClosed(t *testing.T) {
	t.Setenv("MODEL_LATEST_ID", "")
	config, err := loadServerConfig()
	if err != nil || config.latestModelID != "privoke-v3-balanced" {
		t.Fatalf("wrong standard default: %+v %v", config, err)
	}
	if _, err := openStandardReleases(t.TempDir()); err == nil {
		t.Fatal("missing packages must fail admission")
	}
	server := streamingServer{catalog: &modelCatalog{latestModelID: config.latestModelID}}
	if _, err := server.GetModelParameters(context.Background(), &pb.ModelParametersRequest{ModelId: "latest"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("V3 must not enter legacy float RPC: %v", err)
	}
}

func TestStandardV3RejectsLinksTraversalAndUnpinnedManifests(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openStandardReleases(link); err == nil {
		t.Fatal("release root symlink admitted")
	}
	child := filepath.Join(target, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := openStandardReleases(filepath.Join(link, "child")); err == nil {
		t.Fatal("release ancestor symlink admitted")
	}
	model := filepath.Join(target, "privoke-v3-efficient")
	if err := os.Mkdir(model, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(model, "manifest.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	releases := standardReleases{root: root}
	if _, err := releases.manifest("privoke-v3-efficient"); err == nil {
		t.Fatal("unpinned manifest admitted")
	}
	for _, name := range []string{"../manifest.json", "unknown"} {
		if _, _, err := releases.openAsset("privoke-v3-efficient", name); err == nil {
			t.Fatal("unsafe asset admitted")
		}
	}
	if err := os.Symlink(filepath.Join(model, "manifest.json"), filepath.Join(model, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := releases.openAsset("privoke-v3-efficient", "config.json"); err == nil {
		t.Fatal("asset symlink admitted")
	}
}

func TestStandardV3ActualPinnedAssetsAndLegacyIsolation(t *testing.T) {
	directory := os.Getenv("V3_TEST_RELEASE_DIR")
	if directory == "" {
		t.Skip("set V3_TEST_RELEASE_DIR to the locally prepared immutable AU3 releases")
	}
	releases, err := openStandardReleases(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer releases.root.Close()
	path := writeTestArtifact(t)
	catalog, err := loadModelCatalog(filepath.Dir(path), "privoke-v3-balanced")
	if err != nil {
		t.Fatal(err)
	}
	catalog.releases = releases
	// A mutable legacy publication cannot alter a configuration-owned V3 alias.
	if _, err := catalog.load("privoke-baseline"); err != nil {
		t.Fatal(err)
	}
	if catalog.latestModelID != "privoke-v3-balanced" {
		t.Fatal("legacy load changed latest alias")
	}
	listener := bufconn.Listen(2 * 1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterModelStreamingServiceServer(server, &streamingServer{catalog: catalog})
	go server.Serve(listener)
	defer server.Stop()
	defer listener.Close()
	connection, err := grpc.NewClient("passthrough:///standard-v3", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := pb.NewModelStreamingServiceClient(connection)
	latest, err := client.GetModelPackage(context.Background(), &pb.ModelParametersRequest{ConsumerId: "unit", ModelId: "latest"})
	if err != nil || latest.GetModelId() != "privoke-v3-balanced" {
		t.Fatalf("latest package: %v %v", latest, err)
	}
	for id, pin := range standardV3Pins {
		pkg, err := client.GetModelPackage(context.Background(), &pb.ModelParametersRequest{ConsumerId: "unit", ModelId: id})
		if err != nil {
			t.Fatal(err)
		}
		if pkg.ManifestSha256 != pin || pkg.Architecture != v3Architecture || len(pkg.Assets) != 4 {
			t.Fatal("wrong package identity")
		}
		for _, asset := range pkg.Assets {
			stream, err := client.StreamModelAsset(context.Background(), &pb.ModelAssetRequest{ConsumerId: "unit", ModelId: id, ManifestSha256: pin, AssetName: asset.Name})
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.New()
			offset := uint64(0)
			for {
				chunk, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if chunk.ModelId != id || chunk.ManifestSha256 != pin || chunk.AssetName != asset.Name || chunk.Sha256 != asset.Sha256 || chunk.Offset != offset || chunk.TotalBytes != asset.SizeBytes || len(chunk.Data) == 0 || len(chunk.Data) > modelAssetChunkBytes {
					t.Fatal("invalid wire chunk")
				}
				hash.Write(chunk.Data)
				offset += uint64(len(chunk.Data))
			}
			if offset != asset.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != asset.Sha256 {
				t.Fatal("asset wire hash/size mismatch")
			}
		}
	}
	for _, name := range []string{"../manifest.json", "manifest.json", "unknown"} {
		stream, err := client.StreamModelAsset(context.Background(), &pb.ModelAssetRequest{ModelId: latest.ModelId, ManifestSha256: latest.ManifestSha256, AssetName: name})
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("unsafe asset %q admitted: %v", name, err)
		}
	}
	legacy, err := client.GetModelParameters(context.Background(), &pb.ModelParametersRequest{ModelId: "privoke-baseline"})
	if err != nil || legacy.GetModelId() != "privoke-baseline" {
		t.Fatalf("legacy control failed: %v", err)
	}
	again, err := client.GetModelPackage(context.Background(), &pb.ModelParametersRequest{ModelId: "latest"})
	if err != nil || again.ManifestSha256 != latest.ManifestSha256 {
		t.Fatal("legacy request changed V3 standard alias")
	}
	if err := catalog.validate(); err != nil {
		t.Fatal(err)
	}
}
