package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const latestModelAlias = "latest"

var errScratchArtifactAbsent = errors.New("scratch artifact is absent")

// modelCatalog is an allow-list of validated artifact IDs and their paths.
// Requests never become file paths directly, which prevents path traversal.
type modelCatalog struct {
	latestModelID string
	directory     string
	directoryRoot *os.Root
	directoryInfo os.FileInfo
	paths         map[string]string

	// These per-catalog seams are nil in production and support deterministic
	// filesystem-boundary tests without changing process-wide behavior.
	scratchLstat func(*os.Root, string) (os.FileInfo, error)
	scratchOpen  func(*os.Root, string) (*os.File, error)
}

func loadModelCatalog(directory, latestModelID string) (*modelCatalog, error) {
	if isScratchModelID(latestModelID) {
		return nil, fmt.Errorf("scratch presence cannot be the latest model")
	}
	absoluteDirectory, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve model artifact directory: %w", err)
	}
	catalogDirectory, err := filepath.EvalSymlinks(absoluteDirectory)
	if err != nil {
		return nil, fmt.Errorf("resolve model artifact directory: %w", err)
	}
	directoryRoot, err := os.OpenRoot(catalogDirectory)
	if err != nil {
		return nil, fmt.Errorf("open model artifact directory: %w", err)
	}
	keepDirectoryRoot := false
	defer func() {
		if !keepDirectoryRoot {
			_ = directoryRoot.Close()
		}
	}()
	directoryInfo, err := directoryRoot.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("stat model artifact directory: %w", err)
	}
	if !directoryInfo.IsDir() {
		return nil, fmt.Errorf("model artifact path is not a directory")
	}
	entriesFile, err := directoryRoot.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open model artifact directory for reading: %w", err)
	}
	entries, readErr := entriesFile.ReadDir(-1)
	closeErr := entriesFile.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read model artifact directory: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close model artifact directory reader: %w", closeErr)
	}
	catalog := &modelCatalog{
		latestModelID: latestModelID,
		directory:     catalogDirectory,
		directoryRoot: directoryRoot,
		directoryInfo: directoryInfo,
		paths:         make(map[string]string),
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(catalogDirectory, entry.Name())
		artifact, err := loadModelArtifact(path, "")
		if err != nil {
			return nil, fmt.Errorf("load catalog artifact %q: %w", entry.Name(), err)
		}
		if artifact.ModelID == latestModelAlias {
			return nil, fmt.Errorf("model ID %q is reserved", latestModelAlias)
		}
		if isScratchModelID(artifact.ModelID) && entry.Name() != artifact.ModelID+".json" {
			return nil, fmt.Errorf("scratch model %q must use its canonical filename", artifact.ModelID)
		}
		if _, exists := catalog.paths[artifact.ModelID]; exists {
			return nil, fmt.Errorf("duplicate model ID %q", artifact.ModelID)
		}
		catalog.paths[artifact.ModelID] = path
	}
	if len(catalog.paths) == 0 {
		return nil, fmt.Errorf("model artifact directory contains no models")
	}
	if _, exists := catalog.paths[latestModelID]; !exists {
		return nil, fmt.Errorf("latest model %q is not in the catalog", latestModelID)
	}
	keepDirectoryRoot = true
	return catalog, nil
}

func (c *modelCatalog) load(requestedModelID string) (*loadedArtifact, error) {
	modelID := requestedModelID
	if modelID == "" || modelID == latestModelAlias {
		modelID = c.latestModelID
	}
	if isScratchModelID(modelID) {
		if modelID == c.latestModelID {
			return nil, fmt.Errorf("scratch presence cannot be the latest model")
		}
		if c.directoryRoot == nil {
			// Preserve hand-built catalogs used by embedded callers and tests.
			if path, exists := c.paths[modelID]; exists {
				return loadModelArtifact(path, modelID)
			}
			return nil, fmt.Errorf("model %q is unavailable", requestedModelID)
		}
		return c.loadScratch(modelID)
	}
	path, exists := c.paths[modelID]
	if !exists {
		return nil, fmt.Errorf("model %q is unavailable", requestedModelID)
	}
	artifact, err := loadModelArtifact(path, modelID)
	if err == nil && modelID == c.latestModelID && artifact.Architecture == scratchPresenceArchitecture {
		return nil, fmt.Errorf("scratch presence cannot be the latest model")
	}
	return artifact, err
}

func (c *modelCatalog) loadScratch(modelID string) (*loadedArtifact, error) {
	if !isScratchModelID(modelID) || modelID == c.latestModelID {
		return nil, fmt.Errorf("scratch model %q is unavailable", modelID)
	}
	entryInfo, err := c.scratchEntryInfo(modelID)
	if err != nil {
		return nil, err
	}
	if !entryInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("scratch artifact must be a regular file")
	}
	name := modelID + ".json"
	file, err := c.openScratch(name)
	if err != nil {
		return nil, fmt.Errorf("open scratch artifact: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened scratch artifact: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(entryInfo, openedInfo) {
		return nil, fmt.Errorf("opened scratch artifact does not match the inspected regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read scratch artifact: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxArtifactBytes {
		return nil, fmt.Errorf("scratch artifact bytes exceed supported range")
	}
	afterInfo, err := c.scratchEntryInfo(modelID)
	if err != nil {
		return nil, err
	}
	if !afterInfo.Mode().IsRegular() || !os.SameFile(entryInfo, afterInfo) {
		return nil, fmt.Errorf("scratch artifact path changed while reading")
	}
	if err := c.verifyDirectoryIdentity(); err != nil {
		return nil, err
	}
	return loadModelArtifactBytes(raw, modelID)
}

func (c *modelCatalog) scratchEntryInfo(modelID string) (os.FileInfo, error) {
	if !isScratchModelID(modelID) {
		return nil, fmt.Errorf("scratch model %q is unavailable", modelID)
	}
	if err := c.verifyDirectoryIdentity(); err != nil {
		return nil, err
	}
	name := modelID + ".json"
	info, err := c.lstatScratch(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %w", errScratchArtifactAbsent, err)
		}
		return nil, fmt.Errorf("inspect scratch artifact: %w", err)
	}
	return info, nil
}

func (c *modelCatalog) verifyDirectoryIdentity() error {
	if c.directoryRoot == nil || c.directoryInfo == nil {
		return fmt.Errorf("scratch catalog directory identity is unavailable")
	}
	rootInfo, err := c.directoryRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("stat pinned scratch catalog directory: %w", err)
	}
	if !rootInfo.IsDir() || !os.SameFile(c.directoryInfo, rootInfo) {
		return fmt.Errorf("pinned scratch catalog directory identity changed")
	}
	pathInfo, err := os.Stat(c.directory)
	if err != nil {
		return fmt.Errorf("stat scratch catalog directory path: %w", err)
	}
	if !pathInfo.IsDir() || !os.SameFile(c.directoryInfo, pathInfo) {
		return fmt.Errorf("scratch catalog directory path changed")
	}
	return nil
}

func (c *modelCatalog) lstatScratch(name string) (os.FileInfo, error) {
	if c.scratchLstat != nil {
		return c.scratchLstat(c.directoryRoot, name)
	}
	return c.directoryRoot.Lstat(name)
}

func (c *modelCatalog) openScratch(name string) (*os.File, error) {
	if c.scratchOpen != nil {
		return c.scratchOpen(c.directoryRoot, name)
	}
	return c.directoryRoot.Open(name)
}

func (c *modelCatalog) contains(requestedModelID string) bool {
	if requestedModelID == "" || requestedModelID == latestModelAlias {
		return true
	}
	if isScratchModelID(requestedModelID) {
		if c.directoryRoot == nil {
			_, exists := c.paths[requestedModelID]
			return exists
		}
		_, err := c.scratchEntryInfo(requestedModelID)
		return err == nil || !errors.Is(err, errScratchArtifactAbsent)
	}
	_, exists := c.paths[requestedModelID]
	return exists
}

func (c *modelCatalog) modelIDs() []string {
	modelIDs := make([]string, 0, len(c.paths)+len(scratchProfiles)*2)
	for modelID := range c.paths {
		if !isScratchModelID(modelID) || c.directoryRoot == nil {
			modelIDs = append(modelIDs, modelID)
		}
	}
	if c.directoryRoot != nil {
		for modelID := range scratchModelIDs() {
			if c.contains(modelID) {
				modelIDs = append(modelIDs, modelID)
			}
		}
	}
	sort.Strings(modelIDs)
	return modelIDs
}

func scratchModelIDs() map[string]struct{} {
	ids := make(map[string]struct{}, len(scratchProfiles)*2)
	for profile := range scratchProfiles {
		for _, suffix := range []string{"head-only", "full-encoder"} {
			ids["privoke-scratch-presence-"+profile+"-"+suffix] = struct{}{}
		}
	}
	return ids
}

func (c *modelCatalog) validate() error {
	if isScratchModelID(c.latestModelID) {
		return fmt.Errorf("scratch presence cannot be the latest model")
	}
	for modelID, path := range c.paths {
		if isScratchModelID(modelID) {
			if c.directoryRoot == nil {
				if _, err := loadModelArtifact(path, modelID); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := c.load(modelID); err != nil {
			return err
		}
	}
	if c.directoryRoot == nil {
		return nil
	}
	for modelID := range scratchModelIDs() {
		_, err := c.scratchEntryInfo(modelID)
		if errors.Is(err, errScratchArtifactAbsent) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect optional scratch model %q: %w", modelID, err)
		}
		if _, err := c.loadScratch(modelID); err != nil {
			return fmt.Errorf("validate optional scratch model %q: %w", modelID, err)
		}
	}
	return nil
}
