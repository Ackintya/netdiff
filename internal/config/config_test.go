package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaskKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "(not configured)"},
		{"   ", "(not configured)"},
		{"short", "********"},
		{"1234567890", "********"},
		{"AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz", "AIzaSy...WxYz"},
	}

	for _, tt := range tests {
		got := MaskKey(tt.input)
		if got != tt.expected {
			t.Errorf("MaskKey(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("USERPROFILE", tmpDir)
	t.Setenv("HOME", tmpDir)
	t.Setenv("GEMINI_API_KEY", "")

	// 1. Initial load should return empty config
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error on initial load: %v", err)
	}
	if cfg.GeminiAPIKey != "" {
		t.Errorf("expected empty key, got: %s", cfg.GeminiAPIKey)
	}

	// 2. Set API key
	testKey := "AIzaSyTestKey123456789"
	if err := SetAPIKey(testKey); err != nil {
		t.Fatalf("unexpected error setting key: %v", err)
	}

	// 3. Verify GetAPIKey returns saved key
	if got := GetAPIKey(); got != testKey {
		t.Errorf("GetAPIKey() = %q, want %q", got, testKey)
	}

	// 4. Verify file was created in tmpDir/.netdiff/config.json
	cfgPath := filepath.Join(tmpDir, ".netdiff", "config.json")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Errorf("expected config file at %s", cfgPath)
	}

	// 5. Test environment override
	envKey := "AIzaSyEnvironmentOverrideKey"
	t.Setenv("GEMINI_API_KEY", envKey)
	if got := GetAPIKey(); got != envKey {
		t.Errorf("expected env override %q, got %q", envKey, got)
	}

	// 6. Test ClearAPIKey
	t.Setenv("GEMINI_API_KEY", "")
	if err := ClearAPIKey(); err != nil {
		t.Fatalf("unexpected error clearing key: %v", err)
	}
	if got := GetAPIKey(); got != "" {
		t.Errorf("expected cleared key, got: %q", got)
	}
}
