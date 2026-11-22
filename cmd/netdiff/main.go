package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netdiff/internal/ai"
	"netdiff/internal/diff"
	"netdiff/internal/printer"
	"netdiff/internal/probe"
	"netdiff/internal/report"
	"netdiff/internal/snapshot"
	"netdiff/internal/target"
	"netdiff/internal/ui"
	"netdiff/pkg/model"
	"netdiff/pkg/version"
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
  report <good> <bad>     Generate incident report in markdown or standalone interactive HTML
  ui <good> <bad>         Launch interactive web dashboard visualizing the dual dependency DAGs
  probe <name> [param]    Execute a bounded validation probe from the catalog
  version                 Display version information

Flags for 'diagnose':
  -b, --baseline <file>   Use custom baseline .ndiff snapshot (default: ~/.netdiff/baselines/<target>.ndiff)
  -u, --update            Update/record baseline snapshot with current network state
  -g, --graph             Render terminal causal dependency graph
  --html <file>           Export standalone interactive HTML report to file
  --ai                    Enable Gemini AI reasoning synthesis layer
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
  --ai                    Enable Gemini AI reasoning synthesis layer

Flags for 'explain':
  --ai                    Enable Gemini AI reasoning synthesis layer
  --validate              Immediately execute recommended validation probe against target

Flags for 'report':
  -o, --output <file>     Output report to file instead of stdout
  --html                  Generate standalone interactive HTML report (offline-capable)
  --ai                    Enable Gemini AI reasoning synthesis layer

Flags for 'ui':
  -p, --port <port>       Local HTTP port to serve UI on (default: 8080)
  --no-browser            Do not automatically open default web browser
  --ai                    Enable Gemini AI reasoning synthesis in UI

Flags for 'probe':
  -t, --target <host:port> Target connection to validate

Examples:
  netdiff diagnose api.internal.corp:443
  netdiff diagnose api.internal.corp:443 --validate
  netdiff check api.internal.corp:443
  netdiff capture api.internal.corp:443 -o host-a.ndiff
  netdiff capture api.internal.corp:443 -o host-b.ndiff
  netdiff compare host-a.ndiff host-b.ndiff
  netdiff explain host-a.ndiff host-b.ndiff --ai
  netdiff explain host-a.ndiff host-b.ndiff --validate
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
	aiFlag := fs.Bool("ai", false, "Enable Gemini AI reasoning synthesis layer")
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
	explanation, err := reasoner.Explain(ctx, comparison, *aiFlag)
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
	aiFlag := fs.Bool("ai", false, "Enable Gemini AI reasoning synthesis layer")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: graph requires two snapshot files: netdiff graph <good.ndiff> <bad.ndiff> [--ai]")
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

	p := printer.New()
	p.PrintGraph(comparison, explanation)
}

func runExplain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	aiFlag := fs.Bool("ai", false, "Enable Gemini AI reasoning layer")
	validateFlag := fs.Bool("validate", false, "Immediately execute recommended validation probe against target")
	graphFlag := fs.Bool("g", false, "Render terminal causal dependency graph")
	fs.BoolVar(graphFlag, "graph", false, "Render terminal causal dependency graph")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: explain requires two snapshot files: netdiff explain <good.ndiff> <bad.ndiff> [--ai] [--validate]")
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
	explanation, err := reasoner.Explain(context.Background(), comparison, *aiFlag)
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

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outputFile := fs.String("o", "", "Path to output report file")
	fs.StringVar(outputFile, "output", "", "Path to output report file")
	htmlFlag := fs.Bool("html", false, "Generate standalone interactive HTML report")
	aiFlag := fs.Bool("ai", false, "Use Gemini AI reasoning synthesis layer")

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
	explanation, _ := reasoner.Explain(context.Background(), comparison, *aiFlag)

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
			if (arg == "-o" || arg == "--output" || arg == "-t" || arg == "--target" || arg == "-p" || arg == "--port" || arg == "-b" || arg == "--baseline") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			nonFlags = append(nonFlags, arg)
		}
	}
	return append(flags, nonFlags...)
}
