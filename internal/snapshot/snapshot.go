package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"netdiff/pkg/model"
)

var (
	ErrInvalidSchema = errors.New("unsupported snapshot schema version")
	ErrEmptyFile     = errors.New("snapshot file is empty")
)

// Save writes a Snapshot to a .ndiff JSON file.
func Save(path string, snap *model.Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write snapshot file %s: %w", path, err)
	}

	return nil
}

// Load reads and parses a Snapshot from a .ndiff JSON file.
func Load(path string) (*model.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot file %s: %w", path, err)
	}

	if len(data) == 0 {
		return nil, ErrEmptyFile
	}

	var snap model.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot JSON: %w", err)
	}

	if snap.SchemaVersion == "" {
		return nil, fmt.Errorf("%w: missing schema_version", ErrInvalidSchema)
	}

	return &snap, nil
}
