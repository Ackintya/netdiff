package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netdiff/internal/ai"
	"netdiff/internal/config"
	"netdiff/internal/diff"
	"netdiff/internal/printer"
	"netdiff/internal/probe"
	"netdiff/internal/remediation"
	"netdiff/internal/report"
	"netdiff/internal/snapshot"
	"netdiff/internal/target"
	"netdiff/internal/ui"
	"netdiff/internal/watch"
	"netdiff/pkg/model"
	"netdiff/pkg/version"
	"os/signal"
	"syscall"
)

var appVersion = version.Version

func printUsage() {
	fmt.Printf(`NetDiff v%s - Explain why a network connection works in one environment and fails in another.

Usage:
  netdiff <command> [arguments]

Commands:
  diagnose <target>       Diagnose target connectivity against saved baseline (single-command workflow)
  check <target>          Fast reachability probe with one-line summary
  capture <target>        Capture relevant network state for a target (e.g. host:port)
  compare <good> <bad>    Compare two .ndiff captures and rank causal path differences
  graph <good> <bad>      Render terminal ASCII/Unicode causal dependency graph
  explain <good> <bad>    Synthesize diagnosis hypotheses and recommend next validation probe
  ask <good> <bad> "<q>"  Ask natural language debugging questions grounded in snapshot evidence
  fix <good> <bad>        Guarded automated remediation with canary probe & rollback protection
  fix <target>            Guarded automated remediation for target using baseline snapshot
  watch <target>          Proactive baseline drift monitor auditing network state continuously
  report <good> <bad>     Generate incident report in markdown or standalone interactive HTML
  ui <good> <bad>         Launch interactive web dashboard visualizing the dual dependency DAGs
  probe <name> [param]    Execute a bounded validation probe from the catalog
  auth [key]              Configure Gemini API key for AI reasoning and diagnosis
  config <subcommand>     Manage NetDiff configuration (show, set-key, clear)
  version                 Display version information

Flags for 'diagnose':
  -b, --baseline <file>   Use custom baseline .ndiff snapshot (default: ~/.netdiff/baselines/<target>.ndiff)
  -u, --update            Update/record baseline snapshot with current network state
  -g, --graph             Render terminal causal dependency graph
  --html <file>           Export standalone interactive HTML report to file
  --ai                    Force Gemini AI reasoning synthesis layer
  --no-ai                 Disable Gemini AI reasoning and use local deterministic engine
  --validate              Immediately execute recommended validation probe against target

Flags for 'check':
  (none - fast reachability test)

Flags for 'capture':
  -o, --output <file>     Path to output .ndiff snapshot file (default: prints summary)

Flags for 'compare':
  -g, --graph             Render terminal causal dependency graph
  -v, --verbose           Show lower-priority path differences
  -j, --json              Output machine-readable JSON comparison

Flags for 'graph':
  --ai                    Force Gemini AI reasoning synthesis layer
  --no-ai                 Disable Gemini AI reasoning

Flags for 'explain':
  --ai                    Force Gemini AI reasoning synthesis layer
  --no-ai                 Disable Gemini AI reasoning and use local deterministic engine
  --validate              Immediately execute recommended validation probe against target

Flags for 'ask':
  -b, --baseline <file>   Use custom baseline .ndiff snapshot (when target is used)
  -j, --json              Output answer as JSON

Flags for 'fix':
  --dry-run               Simulate and display remediation without modifying system (default)
  --apply                 Execute verified remediation command
  -y, --yes               Skip confirmation prompt when running with --apply
  -b, --baseline <file>   Use custom baseline .ndiff snapshot (when target is used)
  --timeout <dur>         Timeout for remediation & canary verification (default: 10s)
  --no-rollback           Disable automated rollback if canary probe fails
  --ai                    Force Gemini AI reasoning synthesis layer
  --no-ai                 Disable Gemini AI reasoning and use local deterministic engine

Flags for 'watch':
  -b, --baseline <file>   Custom baseline snapshot (default: ~/.netdiff/baselines/<target>.ndiff)
  --interval <duration>   Audit polling interval (default: 30s)
  --count <n>             Stop after N audits (default: 0, runs indefinitely until Ctrl+C)
  --alert-on-divergence   Trigger audio bell alert on drift detection
  --json                  Stream events as line-delimited JSON (NDJSON)
  --once                  Audit baseline drift once and exit (exit 0: healthy, 2: drift detected)

Flags for 'report':
  -o, --output <file>     Output report to file instead of stdout
  --html                  Generate standalone interactive HTML report (offline-capable)
  --ai                    Force Gemini AI reasoning synthesis layer
  --no-ai                 Disable Gemini AI reasoning

Flags for 'ui':
  -p, --port <port>       Local HTTP port to serve UI on (default: 8080)
  --no-browser            Do not automatically open default web browser
  --ai                    Enable Gemini AI reasoning synthesis in UI

Flags for 'probe':
  -t, --target <host:port> Target connection to validate

Examples:
  netdiff auth AIzaSy...                         # Configure Gemini API key once
  netdiff auth                                   # Interactive prompt to enter API key
  netdiff config show                            # Display current configuration & AI status
  netdiff diagnose api.internal.corp:443
  netdiff diagnose api.internal.corp:443 --validate
  netdiff check api.internal.corp:443
  netdiff capture api.internal.corp:443 -o host-a.ndiff
  netdiff capture api.internal.corp:443 -o host-b.ndiff
  netdiff compare host-a.ndiff host-b.ndiff
  netdiff graph host-a.ndiff host-b.ndiff
  netdiff explain host-a.ndiff host-b.ndiff
  netdiff explain host-a.ndiff host-b.ndiff --validate
  netdiff ask host-a.ndiff host-b.ndiff "Why is the connection timing out?"
  netdiff ask api.internal.corp:443 "Is this blocked by firewall or routing?"
  netdiff fix host-a.ndiff host-b.ndiff --dry-run
  netdiff fix host-a.ndiff host-b.ndiff --apply -y
  netdiff fix api.internal.corp:443 --apply
  netdiff watch api.internal.corp:443 --interval 15s
  netdiff watch api.internal.corp:443 --once
  netdiff report host-a.ndiff host-b.ndiff -o incident.md
  netdiff ui host-a.ndiff host-b.ndiff -p 8080
  netdiff probe TEST_INTERFACE_STATE eth0
  netdiff probe TEST_TCP_BIND_INTERFACE tun0 -t api.internal.corp:443
`, appVersion)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "help", "-h", "--help":
		printUsage()

	case "version", "-v", "--version":
		fmt.Printf("netdiff version %s\n", appVersion)

	case "auth":
		runAuth(os.Args[2:])

	case "config":
		runConfig(os.Args[2:])

	case "diagnose":
		runDiagnose(os.Args[2:])

	case "check":
		runCheck(os.Args[2:])

	case "capture":
		runCapture(os.Args[2:])

	case "compare":
		runCompare(os.Args[2:])

	case "graph":
		runGraph(os.Args[2:])

	case "explain":
		runExplain(os.Args[2:])

	case "ask":
		runAsk(os.Args[2:])

	case "fix":
		runFix(os.Args[2:])

	case "watch":
		runWatch(os.Args[2:])

	case "report":
		runReport(os.Args[2:])

	case "ui":
		runUI(os.Args[2:])

	case "probe":
		runProbe(os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runDiagnose(args []string) {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	baselineFile := fs.String("b", "", "Custom baseline .ndiff snapshot file")
	fs.StringVar(baselineFile, "baseline", "", "Custom baseline .ndiff snapshot file")
	updateBaseline := fs.Bool("u", false, "Update baseline with current network state")
	fs.BoolVar(updateBaseline, "update", false, "Update baseline with current network state")
	htmlOutput := fs.String("html", "", "Export standalone interactive HTML report to file")
	graphFlag := fs.Bool("g", false, "Render terminal causal dependency graph")
	fs.BoolVar(graphFlag, "graph", false, "Render terminal causal dependency graph")
	aiFlag := fs.Bool("ai", false, "Force Gemini AI reasoning synthesis layer")
	noAIFlag := fs.Bool("no-ai", false, "Disable Gemini AI reasoning and use local deterministic engine")
	validateFlag := fs.Bool("validate", false, "Immediately execute recommended validation probe against target")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: diagnose requires a target in 'host:port' format (e.g., netdiff diagnose api.corp:443)")
		os.Exit(1)
	}

	tgt, err := target.Parse(remaining[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", remaining[0], err)
		os.Exit(1)
	}

	bPath := *baselineFile
	if bPath == "" {
		var err error
		bPath, err = defaultBaselinePath(tgt.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error determining baseline path: %v\n", err)
			os.Exit(1)
		}
	}

	p := printer.New()
	engine := probe.NewEngine()

	// If updating or baseline does not exist yet: capture baseline
	_, statErr := os.Stat(bPath)
	if *updateBaseline || os.IsNotExist(statErr) {
		fmt.Printf("Capturing baseline network state for %s...\n", tgt.Raw)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		snap, err := engine.Capture(ctx, tgt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error capturing baseline: %v\n", err)
			os.Exit(1)
		}

		if err := os.MkdirAll(filepath.Dir(bPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating baseline directory: %v\n", err)
			os.Exit(1)
		}

		if err := snapshot.Save(bPath, snap); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
			os.Exit(1)
		}

		p.PrintCapturePath(snap)
		fmt.Printf("✓ Baseline captured and saved to %s\n", bPath)
		fmt.Printf("To diagnose connection issues in the future, run:\n  netdiff diagnose %s\n\n", tgt.Raw)
		return
	}

	// Baseline exists: load baseline, capture current state, compare and explain
	baseSnap, err := snapshot.Load(bPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline %s: %v\n", bPath, err)
		os.Exit(1)
	}

	fmt.Printf("Capturing current network state for %s...\n", tgt.Raw)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	currSnap, err := engine.Capture(ctx, tgt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error capturing current state: %v\n", err)
		os.Exit(1)
	}

	comparison := diff.Compare(baseSnap, currSnap)
	reasoner := ai.NewReasoner()
	useAI := shouldEnableAI(*aiFlag, *noAIFlag, reasoner)
	explanation, err := reasoner.Explain(ctx, comparison, useAI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating explanation: %v\n", err)
		os.Exit(1)
	}

	if *graphFlag {
		p.PrintGraph(comparison, explanation)
	} else {
		p.PrintDiagnosis(comparison, explanation)
	}

	if *htmlOutput != "" {
		htmlContent := report.GenerateHTML(comparison, explanation)
		if err := os.WriteFile(*htmlOutput, []byte(htmlContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
		} else {
			fmt.Printf("✓ Standalone interactive HTML report saved to %s\n", *htmlOutput)
		}
	}

	// Active validation probe
	if *validateFlag && explanation.NextBestProbe != nil {
		fmt.Printf("%s%s=== Executing Active Validation Probe: %s(%s) ===%s\n",
			printer.ColorBold, printer.ColorMagenta, explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter, printer.ColorReset)
		fmt.Printf("%s[Notice] Validation probe executes in the current local environment. If snapshots were captured inside a network namespace or remote host, run probe in that environment (e.g. 'ip netns exec <ns> netdiff probe ...').%s\n",
			printer.ColorYellow, printer.ColorReset)
		fmt.Printf("Testing against %s...\n", comparison.Target.Raw)

		probeCtx, pCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer pCancel()

		res, err := probe.ExecuteProbe(probeCtx, comparison.Target, explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter)
		if err != nil {
			fmt.Printf("%sValidation probe failed to execute: %v%s\n\n", printer.ColorRed, err, printer.ColorReset)
			return
		}

		statusColor := printer.ColorGreen
		statusSymbol := "✓ VALIDATION SUCCESS"
		if !res.Success {
			statusColor = printer.ColorRed
			statusSymbol = "✗ VALIDATION FAILED"
		}

		fmt.Printf("\n%s%s=== Probe Result: %s ===%s\n", printer.ColorBold, statusColor, statusSymbol, printer.ColorReset)
		fmt.Printf("%s\n", res.Output)
		renderProbeAssessment(explanation.NextBestProbe.ProbeName, res)
	}

	if (currSnap.TCP != nil && currSnap.TCP.Status != model.TCPStatusConnected) || (currSnap.TLS != nil && !currSnap.TLS.HandshakeSuccess) {
		os.Exit(1)
	}
}

func runCheck(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: check requires a target in 'host:port' format (e.g., netdiff check api.corp:443)")
		os.Exit(1)
	}

	tgt, err := target.Parse(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", args[0], err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	engine := probe.NewEngine()
	snap, err := engine.Capture(ctx, tgt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Check failed: %v\n", err)
		os.Exit(1)
	}

	p := printer.New()
	p.PrintCheck(snap)

	if snap.TCP == nil || snap.TCP.Status != model.TCPStatusConnected || (snap.TLS != nil && !snap.TLS.HandshakeSuccess) {
		os.Exit(1)
	}
}

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	outputFile := fs.String("o", "", "Path to output .ndiff snapshot file")
	fs.StringVar(outputFile, "output", "", "Path to output .ndiff snapshot file")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: capture requires a target in 'host:port' format (e.g., netdiff capture api.corp:443)")
		os.Exit(1)
	}

	tgt, err := target.Parse(remaining[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", remaining[0], err)
		os.Exit(1)
	}

	fmt.Printf("Capturing target-specific network state for %s...\n", tgt.Raw)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	engine := probe.NewEngine()
	snap, err := engine.Capture(ctx, tgt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during capture: %v\n", err)
		os.Exit(1)
	}

	p := printer.New()
	p.PrintCapturePath(snap)

	if *outputFile != "" {
		if err := snapshot.Save(*outputFile, snap); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving snapshot: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Saved snapshot to %s\n", *outputFile)
	}
}

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	verbose := fs.Bool("v", false, "Show lower-priority differences")
	fs.BoolVar(verbose, "verbose", false, "Show lower-priority differences")
	asJSON := fs.Bool("j", false, "Output machine-readable JSON")
	fs.BoolVar(asJSON, "json", false, "Output machine-readable JSON")
	graphFlag := fs.Bool("g", false, "Render terminal causal dependency graph")
	fs.BoolVar(graphFlag, "graph", false, "Render terminal causal dependency graph")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: compare requires two snapshot files: netdiff compare <good.ndiff> <bad.ndiff>")
		os.Exit(1)
	}

	snapA, err := snapshot.Load(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[0], err)
		os.Exit(1)
	}

	snapB, err := snapshot.Load(files[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[1], err)
		os.Exit(1)
	}

	comparison := diff.Compare(snapA, snapB)
	p := printer.New()

	if *graphFlag {
		reasoner := ai.NewReasoner()
		explanation, _ := reasoner.Explain(context.Background(), comparison, false)
		p.PrintGraph(comparison, explanation)
		return
	}

	if err := p.PrintComparison(comparison, *asJSON, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering comparison: %v\n", err)
		os.Exit(1)
	}
}

func runGraph(args []string) {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	aiFlag := fs.Bool("ai", false, "Force Gemini AI reasoning synthesis layer")
	noAIFlag := fs.Bool("no-ai", false, "Disable Gemini AI reasoning and use local deterministic engine")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: graph requires two snapshot files: netdiff graph <good.ndiff> <bad.ndiff> [--ai] [--no-ai]")
		os.Exit(1)
	}

	snapA, err := snapshot.Load(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[0], err)
		os.Exit(1)
	}

	snapB, err := snapshot.Load(files[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[1], err)
		os.Exit(1)
	}

	comparison := diff.Compare(snapA, snapB)
	reasoner := ai.NewReasoner()
	useAI := shouldEnableAI(*aiFlag, *noAIFlag, reasoner)
	explanation, _ := reasoner.Explain(context.Background(), comparison, useAI)

	p := printer.New()
	p.PrintGraph(comparison, explanation)
}

func runExplain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	aiFlag := fs.Bool("ai", false, "Force Gemini AI reasoning layer")
	noAIFlag := fs.Bool("no-ai", false, "Disable Gemini AI reasoning and use local deterministic engine")
	validateFlag := fs.Bool("validate", false, "Immediately execute recommended validation probe against target")
	graphFlag := fs.Bool("g", false, "Render terminal causal dependency graph")
	fs.BoolVar(graphFlag, "graph", false, "Render terminal causal dependency graph")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: explain requires two snapshot files: netdiff explain <good.ndiff> <bad.ndiff> [--ai] [--no-ai] [--validate]")
		os.Exit(1)
	}

	snapA, err := snapshot.Load(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[0], err)
		os.Exit(1)
	}

	snapB, err := snapshot.Load(files[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[1], err)
		os.Exit(1)
	}

	comparison := diff.Compare(snapA, snapB)

	reasoner := ai.NewReasoner()
	useAI := shouldEnableAI(*aiFlag, *noAIFlag, reasoner)
	explanation, err := reasoner.Explain(context.Background(), comparison, useAI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating explanation: %v\n", err)
		os.Exit(1)
	}

	p := printer.New()
	if *graphFlag {
		p.PrintGraph(comparison, explanation)
	} else {
		p.PrintDiagnosis(comparison, explanation)
	}

	// Active closed-loop validation
	if *validateFlag && explanation.NextBestProbe != nil {
		fmt.Printf("%s%s=== Executing Active Validation Probe: %s(%s) ===%s\n",
			printer.ColorBold, printer.ColorMagenta, explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter, printer.ColorReset)
		fmt.Printf("%s[Notice] Validation probe executes in the current local environment. If snapshots were captured inside a network namespace or remote host, run probe in that environment (e.g. 'ip netns exec <ns> netdiff probe ...').%s\n",
			printer.ColorYellow, printer.ColorReset)
		fmt.Printf("Testing against %s...\n", comparison.Target.Raw)

		probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		res, err := probe.ExecuteProbe(probeCtx, comparison.Target, explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter)
		if err != nil {
			fmt.Printf("%sValidation probe failed to execute: %v%s\n\n", printer.ColorRed, err, printer.ColorReset)
			return
		}

		statusColor := printer.ColorGreen
		statusSymbol := "✓ VALIDATION SUCCESS"
		if !res.Success {
			statusColor = printer.ColorRed
			statusSymbol = "✗ VALIDATION FAILED"
		}

		fmt.Printf("\n%s%s=== Probe Result: %s ===%s\n", printer.ColorBold, statusColor, statusSymbol, printer.ColorReset)
		fmt.Printf("%s\n", res.Output)
		renderProbeAssessment(explanation.NextBestProbe.ProbeName, res)
	}
}

func renderProbeAssessment(probeName string, res *probe.ProbeResult) {
	switch probeName {
	case "TEST_INTERFACE_STATE":
		if res.Success {
			fmt.Printf("%sAssessment:%s Interface exists and is administratively UP. Route lookup failure is likely due to missing routing table entry or policy rule rather than a disabled interface.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — interface is down or missing in this environment, explaining route lookup failure.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	case "TEST_TCP_BIND_INTERFACE":
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — route/interface bypass establishes connection successfully.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Probe failed; link or upstream hop itself may be down.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	case "TEST_TCP_BIND_SOURCE":
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — binding to source address succeeds.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Probe failed with bound source address.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	case "TEST_DNS_WITH_RESOLVER":
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — target resolves with specified resolver.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Target name failed to resolve with specified resolver.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	case "TEST_PROXY_DISABLED":
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — direct connection succeeds with proxy disabled.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Direct connection without proxy still failed.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	case "TEST_DIRECT_IP":
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — direct IP connection succeeds; name resolution or routing was the blocker.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Direct IP connection also failed; transport/network layer is blocked.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	default:
		if res.Success {
			fmt.Printf("%sAssessment:%s Probe succeeded.\n\n", printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Probe failed.\n\n", printer.ColorBold, printer.ColorReset)
		}
	}
}

func runAsk(args []string) {
	fs := flag.NewFlagSet("ask", flag.ExitOnError)
	baselineFile := fs.String("b", "", "Custom baseline .ndiff snapshot file")
	fs.StringVar(baselineFile, "baseline", "", "Custom baseline .ndiff snapshot file")
	asJSON := fs.Bool("j", false, "Output response as JSON")
	fs.BoolVar(asJSON, "json", false, "Output response as JSON")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 2 {
		fmt.Fprintln(os.Stderr, "Error: 'ask' requires either:")
		fmt.Fprintln(os.Stderr, "  netdiff ask <good.ndiff> <bad.ndiff> \"<question>\"")
		fmt.Fprintln(os.Stderr, "  netdiff ask <target> \"<question>\"")
		os.Exit(1)
	}

	reasoner := ai.NewReasoner()
	if !reasoner.HasAPIKey() && !*asJSON {
		fmt.Printf("%s[NetDiff AI] Running Q&A with built-in causal engine (no Gemini API key detected).%s\n", printer.ColorMuted, printer.ColorReset)
		fmt.Printf("%sTo enable freeform Gemini conversational reasoning:%s\n", printer.ColorMuted, printer.ColorReset)
		fmt.Printf("  Run: %snetdiff auth <your-gemini-key>%s\n\n", printer.ColorBold+printer.ColorGreen, printer.ColorReset)
	}
	p := printer.New()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	if len(remaining) >= 3 {
		// Two snapshot files + question
		goodFile := remaining[0]
		badFile := remaining[1]
		question := remaining[2]

		snapA, err := snapshot.Load(goodFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", goodFile, err)
			os.Exit(1)
		}

		snapB, err := snapshot.Load(badFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", badFile, err)
			os.Exit(1)
		}

		comparison := diff.Compare(snapA, snapB)
		answer, err := reasoner.Ask(ctx, comparison, question)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error answering question: %v\n", err)
			os.Exit(1)
		}

		if *asJSON {
			out := map[string]string{
				"target":   comparison.Target.Raw,
				"question": question,
				"answer":   answer,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(out)
			return
		}

		p.PrintAsk(comparison.Target.Raw, question, answer)
		return
	}

	// 2 arguments: <target> <question>
	targetArg := remaining[0]
	question := remaining[1]

	tgt, err := target.Parse(targetArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", targetArg, err)
		os.Exit(1)
	}

	bPath := *baselineFile
	if bPath == "" {
		bPath, err = defaultBaselinePath(tgt.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error determining baseline path: %v\n", err)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(bPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Baseline snapshot not found at %s.\nRun 'netdiff diagnose %s' first to capture a working baseline, or pass two snapshots:\n  netdiff ask <good.ndiff> <bad.ndiff> %q\n", bPath, tgt.Raw, question)
		os.Exit(1)
	}

	baseSnap, err := snapshot.Load(bPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline %s: %v\n", bPath, err)
		os.Exit(1)
	}

	engine := probe.NewEngine()
	currSnap, err := engine.Capture(ctx, tgt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error capturing current state: %v\n", err)
		os.Exit(1)
	}

	comparison := diff.Compare(baseSnap, currSnap)
	answer, err := reasoner.Ask(ctx, comparison, question)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error answering question: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		out := map[string]string{
			"target":   comparison.Target.Raw,
			"question": question,
			"answer":   answer,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	p.PrintAsk(comparison.Target.Raw, question, answer)
}

func runFix(args []string) {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "Simulate and display remediation without modifying system")
	apply := fs.Bool("apply", false, "Execute verified remediation command")
	yes := fs.Bool("y", false, "Skip confirmation prompt when running with --apply")
	fs.BoolVar(yes, "yes", false, "Skip confirmation prompt when running with --apply")
	baselineFile := fs.String("b", "", "Custom baseline .ndiff snapshot file")
	fs.StringVar(baselineFile, "baseline", "", "Custom baseline .ndiff snapshot file")
	timeout := fs.Duration("timeout", 10*time.Second, "Timeout for remediation & canary verification")
	noRollback := fs.Bool("no-rollback", false, "Disable automated rollback if canary probe fails")
	aiFlag := fs.Bool("ai", false, "Force Gemini AI reasoning synthesis layer")
	noAIFlag := fs.Bool("no-ai", false, "Disable Gemini AI reasoning and use local deterministic engine")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: 'fix' requires either:")
		fmt.Fprintln(os.Stderr, "  netdiff fix <good.ndiff> <bad.ndiff> [--dry-run|--apply]")
		fmt.Fprintln(os.Stderr, "  netdiff fix <target> [--dry-run|--apply]")
		os.Exit(1)
	}

	ctx := context.Background()
	reasoner := ai.NewReasoner()
	useAI := shouldEnableAI(*aiFlag, *noAIFlag, reasoner)
	p := printer.New()

	var comparison *model.ComparisonReport
	var tgt model.Target

	if len(remaining) >= 2 {
		// Two snapshots: good.ndiff and bad.ndiff
		snapA, err := snapshot.Load(remaining[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", remaining[0], err)
			os.Exit(1)
		}
		snapB, err := snapshot.Load(remaining[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", remaining[1], err)
			os.Exit(1)
		}
		comparison = diff.Compare(snapA, snapB)
		tgt = comparison.Target
	} else {
		// Single argument: target (e.g. host:port)
		var err error
		tgt, err = target.Parse(remaining[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", remaining[0], err)
			os.Exit(1)
		}

		bPath := *baselineFile
		if bPath == "" {
			bPath, err = defaultBaselinePath(tgt.Raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error determining baseline path: %v\n", err)
				os.Exit(1)
			}
		}

		if _, err := os.Stat(bPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Baseline snapshot not found at %s.\nRun 'netdiff diagnose %s' first to capture a working baseline, or pass two snapshots:\n  netdiff fix <good.ndiff> <bad.ndiff> --apply\n", bPath, tgt.Raw)
			os.Exit(1)
		}

		baseSnap, err := snapshot.Load(bPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading baseline %s: %v\n", bPath, err)
			os.Exit(1)
		}

		fmt.Printf("Capturing current network state for %s...\n", tgt.Raw)
		capCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		engine := probe.NewEngine()
		currSnap, err := engine.Capture(capCtx, tgt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error capturing current state: %v\n", err)
			os.Exit(1)
		}

		comparison = diff.Compare(baseSnap, currSnap)
	}

	explanation, err := reasoner.Explain(ctx, comparison, useAI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error synthesizing remediation plan: %v\n", err)
		os.Exit(1)
	}

	if explanation.Remediation == nil || strings.TrimSpace(explanation.Remediation.ImmediateBash) == "" {
		fmt.Printf("\n%sNo actionable remediation required — network path to %s matches baseline.%s\n\n", printer.ColorGreen, tgt.Raw, printer.ColorReset)
		return
	}

	isApply := *apply
	// Confirmation prompt if apply is requested without -y / --yes
	if isApply && !*yes {
		fmt.Printf("\n%s%sProposed Remediation Plan for %s:%s\n", printer.ColorBold, printer.ColorCyan, tgt.Raw, printer.ColorReset)
		fmt.Printf("  Command:  $ %s%s%s\n", printer.ColorBold, explanation.Remediation.ImmediateBash, printer.ColorReset)
		if explanation.Remediation.RollbackBash != "" && !strings.HasPrefix(explanation.Remediation.RollbackBash, "#") {
			fmt.Printf("  Rollback: $ %s%s%s\n", printer.ColorYellow, explanation.Remediation.RollbackBash, printer.ColorReset)
		}
		if explanation.Remediation.Explanation != "" {
			fmt.Printf("  Why:      %s\n", explanation.Remediation.Explanation)
		}
		fmt.Print("\nApply this remediation command with automatic rollback protection? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Remediation aborted by operator.")
			return
		}
	}

	executor := remediation.NewExecutor(remediation.FixOptions{
		DryRun:       *dryRun || !isApply,
		Apply:        isApply,
		AutoRollback: !*noRollback,
		Timeout:      *timeout,
	})

	fixRes, fixErr := executor.Execute(ctx, explanation.Remediation, tgt)
	if fixRes != nil {
		p.PrintFixResult(fixRes)
	}

	if fixErr != nil {
		os.Exit(1)
	}
	if fixRes != nil && fixRes.Status == remediation.FixStatusCanaryFailedRolledBack {
		os.Exit(2)
	}
}

func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	baselineFile := fs.String("b", "", "Custom baseline .ndiff snapshot file")
	fs.StringVar(baselineFile, "baseline", "", "Custom baseline .ndiff snapshot file")
	interval := fs.Duration("interval", 30*time.Second, "Audit polling interval")
	count := fs.Int("count", 0, "Stop after N audits (0 = continuous)")
	alertOnDiv := fs.Bool("alert-on-divergence", false, "Trigger audio bell alert on drift detection")
	asJSON := fs.Bool("json", false, "Stream events as line-delimited JSON")
	once := fs.Bool("once", false, "Audit baseline drift once and exit")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: watch requires a target in 'host:port' format (e.g. netdiff watch api.corp:443)")
		os.Exit(1)
	}

	tgt, err := target.Parse(remaining[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", remaining[0], err)
		os.Exit(1)
	}

	bPath := *baselineFile
	if bPath == "" {
		bPath, err = defaultBaselinePath(tgt.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error determining baseline path: %v\n", err)
			os.Exit(1)
		}
	}

	engine := probe.NewEngine()

	// If baseline file does not exist, capture initial baseline now!
	if _, err := os.Stat(bPath); os.IsNotExist(err) {
		if !*asJSON {
			fmt.Printf("Baseline not found at %s.\nCapturing initial baseline snapshot for %s...\n", bPath, tgt.Raw)
		}
		capCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		snap, err := engine.Capture(capCtx, tgt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error capturing baseline: %v\n", err)
			os.Exit(1)
		}

		if err := os.MkdirAll(filepath.Dir(bPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating baseline directory: %v\n", err)
			os.Exit(1)
		}
		if err := snapshot.Save(bPath, snap); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
			os.Exit(1)
		}
		if !*asJSON {
			fmt.Printf("✓ Baseline snapshot saved to %s\n\n", bPath)
		}
	}

	baseSnap, err := snapshot.Load(bPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline %s: %v\n", bPath, err)
		os.Exit(1)
	}

	cfg := watch.WatchConfig{
		Target:            tgt,
		Baseline:          baseSnap,
		BaselinePath:      bPath,
		Interval:          *interval,
		Count:             *count,
		AlertOnDivergence: *alertOnDiv,
		JSONOutput:        *asJSON,
		Engine:            engine,
		Writer:            os.Stdout,
	}

	if *once {
		auditCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		event, err := watch.AuditOnce(auditCtx, cfg)
		if err != nil && event.Status == "CAPTURE_ERROR" {
			if *asJSON {
				data, _ := json.Marshal(event)
				fmt.Println(string(data))
			} else {
				fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
			}
			os.Exit(1)
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if *asJSON {
			data, _ := json.Marshal(event)
			fmt.Println(string(data))
			if !event.Healthy {
				os.Exit(2)
			}
		} else {
			ts := event.Timestamp.Format("2006-01-02 15:04:05")
			if event.Healthy {
				fmt.Printf("[%s] %s[OK]%s %s - %s\n", ts, printer.ColorBold+printer.ColorGreen, printer.ColorReset, event.Target, event.Summary)
			} else {
				fmt.Printf("[%s] %s[ALERT - DRIFT DETECTED]%s %s\n", ts, printer.ColorBold+printer.ColorRed, printer.ColorReset, event.Target)
				if event.EarliestDivergence != "" {
					fmt.Printf("  Earliest Divergence: %s\n", event.EarliestDivergence)
				}
				for _, d := range event.Differences {
					fmt.Printf("  • [%s] %s: working=%q failing=%q\n", d.Category, d.Field, d.WorkingValue, d.FailingValue)
				}
				if event.RemediationCmd != "" {
					fmt.Printf("  Remediation: $ %s\n", event.RemediationCmd)
				}
				os.Exit(2)
			}
		}
		return
	}

	// Continuous watch with graceful signal handling
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := watch.Watch(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Watch error: %v\n", err)
		os.Exit(1)
	}
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outputFile := fs.String("o", "", "Path to output report file")
	fs.StringVar(outputFile, "output", "", "Path to output report file")
	htmlFlag := fs.Bool("html", false, "Generate standalone interactive HTML report")
	aiFlag := fs.Bool("ai", false, "Force Gemini AI reasoning synthesis layer")
	noAIFlag := fs.Bool("no-ai", false, "Disable Gemini AI reasoning and use local deterministic engine")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: report requires two snapshot files: netdiff report <good.ndiff> <bad.ndiff> [-o report.html] [--html] [--ai]")
		os.Exit(1)
	}

	snapA, err := snapshot.Load(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[0], err)
		os.Exit(1)
	}

	snapB, err := snapshot.Load(files[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[1], err)
		os.Exit(1)
	}

	comparison := diff.Compare(snapA, snapB)
	reasoner := ai.NewReasoner()
	useAI := shouldEnableAI(*aiFlag, *noAIFlag, reasoner)
	explanation, _ := reasoner.Explain(context.Background(), comparison, useAI)

	isHTML := *htmlFlag
	if *outputFile != "" {
		lower := strings.ToLower(*outputFile)
		if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
			isHTML = true
		}
	}

	var content string
	if isHTML {
		content = report.GenerateHTML(comparison, explanation)
	} else {
		content = report.GenerateMarkdown(comparison, explanation)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report file: %v\n", err)
			os.Exit(1)
		}
		if isHTML {
			fmt.Printf("✓ Saved interactive HTML report to %s\n", *outputFile)
		} else {
			fmt.Printf("✓ Saved incident report to %s\n", *outputFile)
		}
	} else {
		fmt.Print(content)
	}
}

func runUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	port := fs.Int("p", 8080, "Local HTTP port to serve UI on")
	fs.IntVar(port, "port", 8080, "Local HTTP port to serve UI on")
	noBrowser := fs.Bool("no-browser", false, "Do not automatically launch web browser")
	aiFlag := fs.Bool("ai", false, "Enable Gemini AI reasoning synthesis in UI")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: ui requires two snapshot files: netdiff ui <good.ndiff> <bad.ndiff> [-p 8080] [--no-browser]")
		os.Exit(1)
	}

	snapA, err := snapshot.Load(files[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[0], err)
		os.Exit(1)
	}

	snapB, err := snapshot.Load(files[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", files[1], err)
		os.Exit(1)
	}

	comparison := diff.Compare(snapA, snapB)
	reasoner := ai.NewReasoner()
	explanation, _ := reasoner.Explain(context.Background(), comparison, *aiFlag)

	if err := ui.StartServer(comparison, explanation, *port, !*noBrowser); err != nil {
		fmt.Fprintf(os.Stderr, "UI server error: %v\n", err)
		os.Exit(1)
	}
}

func runProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	targetStr := fs.String("target", "", "Target connection in host:port format")
	fs.StringVar(targetStr, "t", "", "Target connection in host:port format")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: probe requires a probe name (e.g. netdiff probe TEST_TCP_BIND_INTERFACE tun0 -t api.corp:443)")
		os.Exit(1)
	}

	probeName := remaining[0]
	param := ""
	if len(remaining) > 1 {
		param = remaining[1]
	}

	var tgt model.Target
	if *targetStr != "" {
		var err error
		tgt, err = target.Parse(*targetStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", *targetStr, err)
			os.Exit(1)
		}
	} else if probeName == "TEST_INTERFACE_STATE" {
		tgt = model.Target{Raw: "local", Host: "localhost"}
	} else {
		fmt.Fprintln(os.Stderr, "Error: missing --target flag (e.g. -t api.internal:443)")
		os.Exit(1)
	}

	if tgt.Raw == "local" {
		fmt.Printf("Executing validation probe %s(%s)...\n", probeName, param)
	} else {
		fmt.Printf("Executing validation probe %s(%s) on %s...\n", probeName, param, tgt.Raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.ExecuteProbe(ctx, tgt, probeName, param)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Probe execution failed: %v\n", err)
		os.Exit(1)
	}

	statusColor := printer.ColorGreen
	statusSymbol := "✓ SUCCESS"
	if !result.Success {
		statusColor = printer.ColorRed
		statusSymbol = "✗ FAILED"
	}

	fmt.Printf("\n%s%s=== Probe Result: %s ===%s\n", printer.ColorBold, statusColor, statusSymbol, printer.ColorReset)
	fmt.Printf("%s\n\n", result.Output)
}

func defaultBaselinePath(targetRaw string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	name := sanitizeTarget(targetRaw)
	if name == "" {
		name = "target"
	}
	return filepath.Join(home, ".netdiff", "baselines", name+".ndiff"), nil
}

func sanitizeTarget(raw string) string {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ':', '/', '@', '.', ' ':
			return '-'
		default:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '-'
		}
	}, raw)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

// reorderArgs moves flag arguments ahead of positional arguments so standard flag.FlagSet can parse them
func reorderArgs(args []string) []string {
	var flags []string
	var nonFlags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if (arg == "-o" || arg == "--output" || arg == "-t" || arg == "--target" || arg == "-p" || arg == "--port" || arg == "-b" || arg == "--baseline" || arg == "--interval" || arg == "--count" || arg == "--timeout") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			nonFlags = append(nonFlags, arg)
		}
	}
	return append(flags, nonFlags...)
}

// shouldEnableAI decides whether to run Gemini AI reasoning based on flags and key availability.
func shouldEnableAI(forceAI, noAI bool, reasoner *ai.Reasoner) bool {
	if noAI {
		return false
	}
	if reasoner.HasAPIKey() {
		return true
	}
	if forceAI {
		fmt.Printf("%s[NetDiff AI] No Gemini API key detected.%s\n", printer.ColorYellow, printer.ColorReset)
		fmt.Printf("  To activate AI reasoning & deep root cause pinpointing:\n")
		fmt.Printf("    1. Get a free API key at: %shttps://aistudio.google.com/app/apikey%s\n", printer.ColorCyan, printer.ColorReset)
		fmt.Printf("    2. Save it once: %snetdiff auth <your-key>%s\n", printer.ColorBold+printer.ColorGreen, printer.ColorReset)
		fmt.Printf("  (Continuing with local deterministic causal engine...)\n\n")
	}
	return false
}

func runAuth(args []string) {
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		key := strings.TrimSpace(args[0])
		if err := config.SetAPIKey(key); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving API key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n%s✓ Successfully saved Gemini API key to ~/.netdiff/config.json%s\n", printer.ColorGreen, printer.ColorReset)
		fmt.Printf("AI reasoning and deep root cause pinpointing are now %sACTIVE%s by default across all NetDiff commands.\n\n",
			printer.ColorBold+printer.ColorGreen, printer.ColorReset)
		return
	}

	fmt.Printf("\n%sNetDiff AI Authentication Setup%s\n", printer.ColorBold+printer.ColorCyan, printer.ColorReset)
	fmt.Println("To enable Gemini AI reasoning and deep root-cause pinpointing, get a free API key at:")
	fmt.Printf("  %shttps://aistudio.google.com/app/apikey%s\n\n", printer.ColorCyan, printer.ColorReset)
	fmt.Print("Enter your Gemini API Key: ")

	var inputKey string
	if _, err := fmt.Scanln(&inputKey); err != nil || strings.TrimSpace(inputKey) == "" {
		fmt.Fprintln(os.Stderr, "\nNo key entered. Configuration aborted.")
		os.Exit(1)
	}

	inputKey = strings.TrimSpace(inputKey)
	if err := config.SetAPIKey(inputKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving API key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n%s✓ Successfully saved Gemini API key to ~/.netdiff/config.json%s\n", printer.ColorGreen, printer.ColorReset)
	fmt.Printf("AI reasoning and deep root cause pinpointing are now %sACTIVE%s by default across all NetDiff commands.\n\n",
		printer.ColorBold+printer.ColorGreen, printer.ColorReset)
}

func runConfig(args []string) {
	if len(args) == 0 || args[0] == "show" {
		cfg, _ := config.Load()
		activeKey := config.GetAPIKey()
		source := "not configured"
		if os.Getenv("GEMINI_API_KEY") != "" {
			source = "environment (GEMINI_API_KEY)"
		} else if cfg != nil && cfg.GeminiAPIKey != "" {
			source = "~/.netdiff/config.json"
		}

		p, _ := config.Path()
		fmt.Printf("\n%sNetDiff Configuration%s\n", printer.ColorBold+printer.ColorCyan, printer.ColorReset)
		fmt.Printf("  Config File:    %s\n", p)
		fmt.Printf("  Gemini API Key: %s  (%s)\n", config.MaskKey(activeKey), source)
		model := "gemini-2.5-flash"
		if cfg != nil && cfg.GeminiModel != "" {
			model = cfg.GeminiModel
		}
		if envModel := os.Getenv("GEMINI_MODEL"); envModel != "" {
			model = envModel + " (env)"
		}
		fmt.Printf("  Gemini Model:   %s\n", model)
		if activeKey != "" {
			fmt.Printf("  AI Status:      %sACTIVE%s (automatic AI reasoning enabled by default)\n\n", printer.ColorGreen, printer.ColorReset)
		} else {
			fmt.Printf("  AI Status:      %sINACTIVE%s (running local deterministic causal engine)\n", printer.ColorYellow, printer.ColorReset)
			fmt.Printf("                  Run 'netdiff auth <key>' to enable AI reasoning.\n\n")
		}
		return
	}

	sub := args[0]
	switch sub {
	case "set-key":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(os.Stderr, "Error: set-key requires an API key argument: netdiff config set-key <key>")
			os.Exit(1)
		}
		if err := config.SetAPIKey(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Gemini API key saved to ~/.netdiff/config.json\n")
	case "clear", "remove-key":
		if err := config.ClearAPIKey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error clearing key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Saved API key removed from ~/.netdiff/config.json\n")
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand %q. Use 'show', 'set-key', or 'clear'.\n", sub)
		os.Exit(1)
	}
}
