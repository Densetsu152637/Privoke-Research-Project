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
	paths         map[string]string
}

func loadModelCatalog(directory, latestModelID string) (*modelCatalog, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read model artifact directory: %w", err)
	}
	catalog := &modelCatalog{
		latestModelID: latestModelID,
		paths:         make(map[string]string),
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		artifact, err := loadModelArtifact(path, "")
		if err != nil {
			return nil, fmt.Errorf("load catalog artifact %q: %w", entry.Name(), err)
		}
		if artifact.ModelID == latestModelAlias {
			return nil, fmt.Errorf("model ID %q is reserved", latestModelAlias)
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
	path, exists := c.paths[modelID]
	if !exists {
		return nil, fmt.Errorf("model %q is unavailable", requestedModelID)
	}
	return loadModelArtifact(path, modelID)
}

func (c *modelCatalog) contains(requestedModelID string) bool {
	if requestedModelID == "" || requestedModelID == latestModelAlias {
		return true
	}
	_, exists := c.paths[requestedModelID]
	return exists
}

func (c *modelCatalog) modelIDs() []string {
	modelIDs := make([]string, 0, len(c.paths))
	for modelID := range c.paths {
		modelIDs = append(modelIDs, modelID)
	}
	sort.Strings(modelIDs)
	return modelIDs
}

func (c *modelCatalog) validate() error {
	for modelID, path := range c.paths {
		if _, err := loadModelArtifact(path, modelID); err != nil {
			return err
		}
	}
	return nil
}
