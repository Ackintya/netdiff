package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents persistent NetDiff user configuration stored at ~/.netdiff/config.json.
type Config struct {
	GeminiAPIKey string `json:"gemini_api_key,omitempty"`
	GeminiModel  string `json:"gemini_model,omitempty"`
}

// Dir returns the NetDiff configuration directory (~/.netdiff).
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".netdiff"), nil
}

// Path returns the path to the configuration file (~/.netdiff/config.json).
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads and parses the persistent configuration file.
// If the file does not exist, an empty configuration is returned without error.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return &Config{}, err
	}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return &Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &Config{}, err
	}
	return &cfg, nil
}

// Save writes the configuration to ~/.netdiff/config.json with restrictive permissions (0600).
func Save(cfg *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(p, data, 0600)
}

// GetAPIKey resolves the active Gemini API key.
// Priority:
// 1. GEMINI_API_KEY environment variable
// 2. ~/.netdiff/config.json (gemini_api_key)
func GetAPIKey() string {
	if key := strings.TrimSpace(os.Getenv("GEMINI_API_KEY")); key != "" {
		return key
	}
	cfg, err := Load()
	if err == nil && cfg != nil {
		return strings.TrimSpace(cfg.GeminiAPIKey)
	}
	return ""
}

// SetAPIKey saves the Gemini API key into ~/.netdiff/config.json.
func SetAPIKey(key string) error {
	cfg, err := Load()
	if err != nil {
		cfg = &Config{}
	}
	cfg.GeminiAPIKey = strings.TrimSpace(key)
	return Save(cfg)
}

// ClearAPIKey removes the stored Gemini API key from ~/.netdiff/config.json.
func ClearAPIKey() error {
	cfg, err := Load()
	if err != nil {
		return nil
	}
	cfg.GeminiAPIKey = ""
	return Save(cfg)
}

// MaskKey returns a safe, redacted representation of the API key for display (e.g. AIzaSy...4f1d).
func MaskKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "(not configured)"
	}
	if len(key) <= 10 {
		return "********"
	}
	return key[:6] + "..." + key[len(key)-4:]
}
