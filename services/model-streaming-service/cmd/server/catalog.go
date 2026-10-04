package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const latestModelAlias = "latest"

// modelCatalog is an allow-list of validated artifact IDs and their paths.
// Requests never become file paths directly, which prevents path traversal.
type modelCatalog struct {
	latestModelID string
	directory     string
	paths         map[string]string
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
	entries, err := os.ReadDir(catalogDirectory)
	if err != nil {
		return nil, fmt.Errorf("read model artifact directory: %w", err)
	}
	catalog := &modelCatalog{
		latestModelID: latestModelID,
		directory:     catalogDirectory,
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
		if c.directory == "" {
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
	path := filepath.Join(c.directory, modelID+".json")
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat scratch artifact: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("scratch artifact must be a regular file")
	}
	artifact, err := loadModelArtifact(path, modelID)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("restat scratch artifact: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("scratch artifact changed while loading")
	}
	return artifact, nil
}

func (c *modelCatalog) scratchFileExists(modelID string) bool {
	if !isScratchModelID(modelID) {
		return false
	}
	_, err := os.Lstat(filepath.Join(c.directory, modelID+".json"))
	return err == nil
}

func (c *modelCatalog) contains(requestedModelID string) bool {
	if requestedModelID == "" || requestedModelID == latestModelAlias {
		return true
	}
	if isScratchModelID(requestedModelID) {
		if c.directory == "" {
			_, exists := c.paths[requestedModelID]
			return exists
		}
		return c.scratchFileExists(requestedModelID)
	}
	_, exists := c.paths[requestedModelID]
	return exists
}

func (c *modelCatalog) modelIDs() []string {
	modelIDs := make([]string, 0, len(c.paths)+len(scratchProfiles)*2)
	for modelID := range c.paths {
		if !isScratchModelID(modelID) || c.directory == "" {
			modelIDs = append(modelIDs, modelID)
		}
	}
	if c.directory != "" {
		for modelID := range scratchModelIDs() {
			if c.scratchFileExists(modelID) {
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
			if c.directory == "" {
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
	if c.directory == "" {
		return nil
	}
	for modelID := range scratchModelIDs() {
		if !c.scratchFileExists(modelID) {
			continue
		}
		if _, err := c.loadScratch(modelID); err != nil {
			return fmt.Errorf("validate optional scratch model %q: %w", modelID, err)
		}
	}
	return nil
}