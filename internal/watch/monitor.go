package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"netdiff/internal/ai"
	"netdiff/internal/diff"
	"netdiff/internal/printer"
	"netdiff/pkg/model"
)

// CaptureEngine defines the interface for capturing live target network state.
type CaptureEngine interface {
	Capture(ctx context.Context, tgt model.Target) (*model.Snapshot, error)
}

// DriftEvent represents the outcome of an individual baseline drift audit tick.
type DriftEvent struct {
	Timestamp          time.Time          `json:"timestamp"`
	Target             string             `json:"target"`
	Status             string             `json:"status"` // "HEALTHY", "DRIFT_DETECTED", "CAPTURE_ERROR"
	Healthy            bool               `json:"healthy"`
	DivergenceCount    int                `json:"divergence_count"`
	EarliestDivergence string             `json:"earliest_divergence,omitempty"`
	Summary            string             `json:"summary"`
	TCPStatus          string             `json:"tcp_status,omitempty"`
	LatencyMs          int64              `json:"latency_ms,omitempty"`
	RemediationCmd     string             `json:"remediation_cmd,omitempty"`
	Differences        []model.Difference `json:"differences,omitempty"`
}

// WatchConfig holds parameters for the continuous baseline drift monitor.
type WatchConfig struct {
	Target            model.Target
	Baseline          *model.Snapshot
	BaselinePath      string
	Interval          time.Duration
	Count             int // 0 = continuous until cancelled
	AlertOnDivergence bool
	JSONOutput        bool
	Engine            CaptureEngine
	Writer            io.Writer
}

// AuditOnce evaluates current target state against baseline once and returns the DriftEvent.
func AuditOnce(ctx context.Context, cfg WatchConfig) (*DriftEvent, error) {
	now := time.Now().UTC()
	event := &DriftEvent{
		Timestamp: now,
		Target:    cfg.Target.Raw,
	}

	if cfg.Baseline == nil {
		event.Status = "CONFIG_ERROR"
		event.Summary = "No baseline snapshot provided for drift comparison."
		return event, fmt.Errorf("baseline snapshot is nil")
	}

	currSnap, err := cfg.Engine.Capture(ctx, cfg.Target)
	if err != nil {
		event.Status = "CAPTURE_ERROR"
		event.Summary = fmt.Sprintf("Failed to capture live target state: %v", err)
		return event, err
	}

	if currSnap.TCP != nil {
		event.TCPStatus = string(currSnap.TCP.Status)
		event.LatencyMs = currSnap.TCP.LatencyMs
	}

	comparison := diff.Compare(cfg.Baseline, currSnap)
	var highOrMedDiffs []model.Difference
	for _, d := range comparison.Differences {
		if d.Relevance == model.RelevanceHigh || d.Relevance == model.RelevanceMedium {
			highOrMedDiffs = append(highOrMedDiffs, d)
		}
	}

	event.Differences = highOrMedDiffs
	event.DivergenceCount = len(highOrMedDiffs)
	event.EarliestDivergence = comparison.EarliestDivergence

	if len(highOrMedDiffs) == 0 {
		event.Healthy = true
		event.Status = "HEALTHY"
		egress := "default"
		if currSnap.Route != nil && currSnap.Route.EgressInterface != "" {
			egress = currSnap.Route.EgressInterface
		}
		event.Summary = fmt.Sprintf("Path aligned with baseline | Egress: %s | TCP: %s (%dms)", egress, event.TCPStatus, event.LatencyMs)
		return event, nil
	}

	// Drift detected
	event.Healthy = false
	event.Status = "DRIFT_DETECTED"
	event.Summary = comparison.Summary

	// Derive actionable remediation hint via deterministic reasoner
	reasoner := ai.NewReasoner()
	exp, expErr := reasoner.Explain(ctx, comparison, false)
	if expErr == nil && exp != nil && exp.Remediation != nil {
		event.RemediationCmd = exp.Remediation.ImmediateBash
	}

	return event, nil
}

// Watch runs periodic drift auditing against the saved baseline until ctx is cancelled or count is reached.
func Watch(ctx context.Context, cfg WatchConfig) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Writer == nil {
		return fmt.Errorf("output writer cannot be nil")
	}

	out := cfg.Writer
	if !cfg.JSONOutput {
		fmt.Fprintf(out, "%sNetDiff Proactive Baseline Drift Monitor%s\n", printer.ColorBold+printer.ColorCyan, printer.ColorReset)
		fmt.Fprintf(out, "  Target:   %s%s%s\n", printer.ColorBold, cfg.Target.Raw, printer.ColorReset)
		if cfg.BaselinePath != "" {
			fmt.Fprintf(out, "  Baseline: %s\n", cfg.BaselinePath)
		}
		fmt.Fprintf(out, "  Interval: %s\n\n", cfg.Interval)
		fmt.Fprintf(out, "Starting continuous audit (press Ctrl+C to stop)...\n\n")
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	iterations := 0

	runIteration := func() error {
		iterations++
		auditCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		event, err := AuditOnce(auditCtx, cfg)
		if err != nil && event.Status == "CAPTURE_ERROR" {
			printEvent(out, event, cfg)
			return nil // continue monitoring despite single transient error
		} else if err != nil {
			return err
		}

		printEvent(out, event, cfg)
		return nil
	}

	// First run immediately
	if err := runIteration(); err != nil {
		return err
	}
	if cfg.Count > 0 && iterations >= cfg.Count {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			if !cfg.JSONOutput {
				fmt.Fprintf(out, "\n%sMonitor stopped by operator.%s\n", printer.ColorMuted, printer.ColorReset)
			}
			return nil
		case <-ticker.C:
			if err := runIteration(); err != nil {
				return err
			}
			if cfg.Count > 0 && iterations >= cfg.Count {
				return nil
			}
		}
	}
}

func printEvent(w io.Writer, event *DriftEvent, cfg WatchConfig) {
	if cfg.JSONOutput {
		data, _ := json.Marshal(event)
		fmt.Fprintln(w, string(data))
		return
	}

	ts := event.Timestamp.Format("2006-01-02 15:04:05")

	if event.Healthy {
		fmt.Fprintf(w, "[%s] %s[OK]%s %s - %s\n",
			ts,
			printer.ColorBold+printer.ColorGreen,
			printer.ColorReset,
			event.Target,
			event.Summary,
		)
		return
	}

	// Drift Alert
	bell := ""
	if cfg.AlertOnDivergence {
		bell = "\a" // Terminal audio bell
	}
	fmt.Fprintf(w, "%s[%s] %s[ALERT - DRIFT DETECTED]%s Target: %s%s\n",
		bell,
		ts,
		printer.ColorBold+printer.ColorRed,
		printer.ColorReset,
		printer.ColorBold,
		event.Target+printer.ColorReset,
	)
	if event.EarliestDivergence != "" {
		fmt.Fprintf(w, "  %sEarliest Divergence:%s %s%s%s\n",
			printer.ColorBold, printer.ColorReset,
			printer.ColorBold+printer.ColorYellow, event.EarliestDivergence, printer.ColorReset)
	}
	if len(event.Differences) > 0 {
		for _, d := range event.Differences {
			fmt.Fprintf(w, "  • %s[%s]%s %s: working=%q failing=%q\n",
				printer.ColorMuted, d.Category, printer.ColorReset,
				d.Field, d.WorkingValue, d.FailingValue)
		}
	}
	if event.RemediationCmd != "" {
		fmt.Fprintf(w, "  %sRecommended Fix:%s    $ %s%s%s\n",
			printer.ColorBold, printer.ColorReset,
			printer.ColorBold+printer.ColorCyan, event.RemediationCmd, printer.ColorReset)
		fmt.Fprintf(w, "  %sGuarded Auto-Fix:%s   $ %snetdiff fix %s --apply%s\n",
			printer.ColorBold, printer.ColorReset,
			printer.ColorBold+printer.ColorGreen, event.Target, printer.ColorReset)
	}
	fmt.Fprintln(w)
}
