package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"api.corp:443", "api-corp-443"},
		{"10.10.0.2:8080", "10-10-0-2-8080"},
		{"https://example.com:8443/", "https-example-com-8443"},
		{"foo..bar--baz::qux", "foo-bar-baz-qux"},
	}

	for _, tt := range tests {
		got := sanitizeTarget(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeTarget(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultBaselinePath(t *testing.T) {
	path, err := defaultBaselinePath("api.internal.corp:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join(".netdiff", "baselines", "api-internal-corp-443.ndiff")) {
		t.Errorf("unexpected baseline path: %s", path)
	}
}

func TestReorderArgs(t *testing.T) {
	args := []string{"api.corp:443", "-o", "out.ndiff", "-v"}
	reordered := reorderArgs(args)
	// Expected flags first: -o out.ndiff -v api.corp:443
	expected := []string{"-o", "out.ndiff", "-v", "api.corp:443"}
	if len(reordered) != len(expected) {
		t.Fatalf("expected length %d, got %d (%v)", len(expected), len(reordered), reordered)
	}
	for i := range expected {
		if reordered[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, reordered[i], expected[i])
		}
	}

	// Test baseline flag reordering
	diagArgs := []string{"api.corp:443", "--baseline", "custom.ndiff", "--ai"}
	diagReordered := reorderArgs(diagArgs)
	if diagReordered[0] != "--baseline" || diagReordered[1] != "custom.ndiff" {
		t.Errorf("unexpected reorder for --baseline: %v", diagReordered)
	}
}
