package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	pb "github.com/privoke/research-project/services/model-streaming-service/gen/privoke/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const v3Architecture = "privoke_pretrained_bert_v3"
const maxModelAssetBytes = 80 * 1024 * 1024
const modelAssetChunkBytes = 1024 * 1024

var standardV3Pins = map[string]string{
	"privoke-v3-efficient": "1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd",
	"privoke-v3-balanced":  "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589",
	"privoke-v3-quality":   "bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39",
}
var v3AssetKeys = map[string]string{"model.safetensors": "blob", "config.json": "config", "vocab.txt": "vocab", "evidence.json": "evidence"}

type standardReleases struct {
	root       *os.Root
	identities map[string]os.FileInfo
}

func isStandardV3(id string) bool { _, ok := standardV3Pins[id]; return ok }

func openStandardReleases(directory string) (*standardReleases, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("standard release path must not traverse symlinks")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("standard V3 release directory is missing or unsafe; run models/prepare_standard_releases.py")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	result := &standardReleases{root: root, identities: map[string]os.FileInfo{}}
	for id := range standardV3Pins {
		pkg, err := result.manifest(id)
		if err != nil {
			root.Close()
			return nil, err
		}
		for _, asset := range pkg.Assets {
			file, before, err := result.openAsset(id, asset.Name)
			if err != nil {
				root.Close()
				return nil, err
			}
			hash, err := boundedFileHash(file)
			file.Close()
			if err != nil || hash != asset.Sha256 {
				root.Close()
				return nil, fmt.Errorf("standard V3 asset hash mismatch: %s/%s", id, asset.Name)
			}
			result.identities[id+"/"+asset.Name] = before
		}
	}
	return result, nil
}

func (r *standardReleases) openAsset(id, name string) (*os.File, os.FileInfo, error) {
	if !isStandardV3(id) {
		return nil, nil, fmt.Errorf("unknown standard model")
	}
	if name != "manifest.json" {
		if _, ok := v3AssetKeys[name]; !ok {
			return nil, nil, fmt.Errorf("unknown model asset")
		}
	}
	directory, err := r.root.Lstat(id)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("unsafe model directory")
	}
	path := id + "/" + name
	info, err := r.root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxModelAssetBytes {
		return nil, nil, fmt.Errorf("unsafe or oversized model asset")
	}
	file, err := r.root.Open(path)
	if err != nil {
		return nil, nil, err
	}
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		file.Close()
		return nil, nil, fmt.Errorf("model asset changed while opening")
	}
	return file, actual, nil
}

func boundedFileHash(file *os.File) (string, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxModelAssetBytes+1))
	if err != nil || n <= 0 || n > maxModelAssetBytes {
		return "", fmt.Errorf("invalid model asset bytes")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *standardReleases) manifest(id string) (*pb.ModelPackageResponse, error) {
	file, _, err := r.openAsset(id, "manifest.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil || len(raw) > 256*1024 {
		return nil, fmt.Errorf("invalid model manifest size")
	}
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	if pin != standardV3Pins[id] {
		return nil, fmt.Errorf("standard V3 manifest pin mismatch")
	}
	var manifest map[string]json.RawMessage
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	field := func(key string) string { var value string; _ = json.Unmarshal(manifest[key], &value); return value }
	if field("model_id") != id || field("architecture") != v3Architecture {
		return nil, fmt.Errorf("standard V3 manifest identity mismatch")
	}
	pkg := &pb.ModelPackageResponse{ModelId: id, Architecture: v3Architecture, ManifestSha256: pin, ManifestJson: raw}
	names := make([]string, 0, len(v3AssetKeys))
	for name := range v3AssetKeys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		asset, info, err := r.openAsset(id, name)
		if err != nil {
			return nil, err
		}
		asset.Close()
		expected := field(v3AssetKeys[name])
		if len(expected) != 64 {
			return nil, fmt.Errorf("invalid asset digest")
		}
		pkg.Assets = append(pkg.Assets, &pb.ModelPackageAsset{Name: name, Sha256: expected, SizeBytes: uint64(info.Size())})
	}
	return pkg, nil
}

func (r *standardReleases) validate() error {
	for id := range standardV3Pins {
		pkg, err := r.manifest(id)
		if err != nil {
			return err
		}
		for _, asset := range pkg.Assets {
			file, info, err := r.openAsset(id, asset.Name)
			if err != nil {
				return err
			}
			file.Close()
			before := r.identities[id+"/"+asset.Name]
			if before == nil || !os.SameFile(before, info) || before.Size() != info.Size() || !before.ModTime().Equal(info.ModTime()) {
				return fmt.Errorf("standard asset changed after admission")
			}
		}
	}
	return nil
}

func (s *streamingServer) GetModelPackage(_ context.Context, req *pb.ModelParametersRequest) (*pb.ModelPackageResponse, error) {
	if err := s.validateRequest(req); err != nil {
		return nil, err
	}
	id := req.ModelId
	if id == "" || id == latestModelAlias {
		id = s.catalog.latestModelID
	}
	if !isStandardV3(id) {
		artifact, err := s.catalog.load(id)
		if err != nil {
			return nil, status.Error(codes.NotFound, "model is unavailable")
		}
		return &pb.ModelPackageResponse{ModelId: artifact.ModelID, Architecture: artifact.Architecture}, nil
	}
	if s.catalog.releases == nil {
		return nil, status.Error(codes.FailedPrecondition, "standard V3 packages are unavailable")
	}
	result, err := s.catalog.releases.manifest(id)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "standard V3 manifest is unavailable")
	}
	return result, nil
}

func (s *streamingServer) StreamModelAsset(req *pb.ModelAssetRequest, stream grpc.ServerStreamingServer[pb.ModelAssetChunk]) error {
	if err := s.validateRequest(&pb.ModelParametersRequest{ConsumerId: req.ConsumerId, ModelId: req.ModelId}); err != nil {
		return err
	}
	if !isStandardV3(req.ModelId) || req.ManifestSha256 != standardV3Pins[req.ModelId] || s.catalog.releases == nil {
		return status.Error(codes.InvalidArgument, "explicit standard model and manifest pin required")
	}
	if _, ok := v3AssetKeys[req.AssetName]; !ok {
		return status.Error(codes.InvalidArgument, "asset is not allowlisted")
	}
	pkg, err := s.catalog.releases.manifest(req.ModelId)
	if err != nil {
		return status.Error(codes.Unavailable, "model manifest changed")
	}
	var selected *pb.ModelPackageAsset
	for _, asset := range pkg.Assets {
		if asset.Name == req.AssetName {
			selected = asset
		}
	}
	file, info, err := s.catalog.releases.openAsset(req.ModelId, req.AssetName)
	if err != nil {
		return status.Error(codes.Unavailable, "model asset unavailable")
	}
	defer file.Close()
	digest, err := boundedFileHash(file)
	if err != nil || digest != selected.Sha256 {
		return status.Error(codes.DataLoss, "model asset hash mismatch")
	}
	if _, err = file.Seek(0, 0); err != nil {
		return err
	}
	hash := sha256.New()
	buffer := make([]byte, modelAssetChunkBytes)
	offset := uint64(0)
	for {
		if err := stream.Context().Err(); err != nil {
			return err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			hash.Write(buffer[:n])
			if offset+uint64(n) > selected.SizeBytes {
				return status.Error(codes.DataLoss, "model asset grew while streaming")
			}
			if err = stream.Send(&pb.ModelAssetChunk{ModelId: req.ModelId, ManifestSha256: req.ManifestSha256, AssetName: req.AssetName, Sha256: selected.Sha256, Offset: offset, TotalBytes: selected.SizeBytes, Data: append([]byte(nil), buffer[:n]...)}); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || offset != selected.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != selected.Sha256 {
		return status.Error(codes.DataLoss, "model asset changed while streaming")
	}
	if _, err = s.catalog.releases.manifest(req.ModelId); err != nil {
		return status.Error(codes.DataLoss, "model manifest changed while streaming")
	}
	return nil
}
