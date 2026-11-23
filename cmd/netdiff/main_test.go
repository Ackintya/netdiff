package main

import (
	"path/filepath"
	"strings"
	"testing"

	"netdiff/internal/ai"
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

	// Test ask flag reordering
	askArgs := []string{"host-a.ndiff", "host-b.ndiff", "--json", "Why does it fail?"}
	askReordered := reorderArgs(askArgs)
	if askReordered[0] != "--json" {
		t.Errorf("expected --json first, got: %v", askReordered)
	}

	// Test fix and watch flag reordering
	fixArgs := []string{"host-a.ndiff", "host-b.ndiff", "--apply", "--timeout", "15s", "-y"}
	fixReordered := reorderArgs(fixArgs)
	if fixReordered[0] != "--apply" {
		t.Errorf("expected --apply first in fix reorder, got: %v", fixReordered)
	}

	watchArgs := []string{"api.corp:443", "--interval", "10s", "--count", "5", "--json"}
	watchReordered := reorderArgs(watchArgs)
	if watchReordered[0] != "--interval" || watchReordered[1] != "10s" {
		t.Errorf("expected --interval 10s first in watch reorder, got: %v", watchReordered)
	}
}

func TestShouldEnableAI(t *testing.T) {
	withKey := &ai.Reasoner{APIKey: "AIzaSyTest12345"}
	withoutKey := &ai.Reasoner{APIKey: ""}

	// 1. With key, default should be true
	if !shouldEnableAI(false, false, withKey) {
		t.Errorf("expected AI to be enabled by default when key is configured")
	}

	// 2. With key, but --no-ai passed, should be false
	if shouldEnableAI(false, true, withKey) {
		t.Errorf("expected --no-ai to disable AI even if key is configured")
	}

	// 3. Without key, default should be false
	if shouldEnableAI(false, false, withoutKey) {
		t.Errorf("expected AI to be disabled when key is not configured")
	}

	// 4. Without key, even with --ai passed, should return false (after printing prompt)
	if shouldEnableAI(true, false, withoutKey) {
		t.Errorf("expected shouldEnableAI to return false when key is missing")
	}
}
