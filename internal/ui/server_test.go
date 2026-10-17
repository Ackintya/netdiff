package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

func TestUIEndpoints(t *testing.T) {
	comp := &model.ComparisonReport{
		WorkingHost: "host-good",
		FailingHost: "host-bad",
		Target: model.Target{
			Raw:  "api.corp:443",
			Host: "api.corp",
			Port: 443,
		},
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main",
		WorkingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
		},
		FailingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
		},
	}
	exp := &ai.ExplanationReport{
		Summary: "Policy route divergence.",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := assetsFS.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Payload{Comparison: comp, Explanation: exp})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. Test root HTML endpoint
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("failed GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
	}

	// 2. Test /api/data endpoint
	dataResp, err := http.Get(server.URL + "/api/data")
	if err != nil {
		t.Fatalf("failed GET /api/data: %v", err)
	}
	defer dataResp.Body.Close()
	var payload Payload
	if err := json.NewDecoder(dataResp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode JSON from /api/data: %v", err)
	}
	if payload.Comparison == nil || payload.Comparison.Target.Raw != "api.corp:443" {
		t.Errorf("unexpected payload target: %+v", payload)
	}
	if !strings.Contains(payload.Comparison.EarliestDivergence, "Policy Rule") {
		t.Errorf("expected earliest divergence in payload: %s", payload.Comparison.EarliestDivergence)
	}
}
