package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"netdiff/internal/ai"
	"netdiff/internal/diff"
	"netdiff/internal/printer"
	"netdiff/internal/probe"
	"netdiff/internal/report"
	"netdiff/internal/snapshot"
	"netdiff/internal/target"
)

const version = "0.2.0"

func printUsage() {
	fmt.Printf(`NetDiff v%s - Explain why a network connection works in one environment and fails in another.

Usage:
  netdiff <command> [arguments]

Commands:
  capture <target>        Capture relevant network state for a target (e.g. host:port)
  compare <good> <bad>    Compare two .ndiff captures and rank causal path differences
  explain <good> <bad>    Synthesize diagnosis hypotheses and recommend next validation probe
  report <good> <bad>     Generate markdown incident post-mortem report (for Slack/Jira/GitHub)
  probe <name> [param]    Execute a bounded validation probe from the catalog
  version                 Display version information

Flags for 'capture':
  -o, --output <file>     Path to output .ndiff snapshot file (default: prints summary)

Flags for 'compare':
  -v, --verbose           Show lower-priority path differences
  -j, --json              Output machine-readable JSON comparison

Flags for 'explain':
  --ai                    Enable Gemini AI reasoning synthesis layer
  --validate              Immediately execute recommended validation probe against target

Flags for 'report':
  -o, --output <file>     Output report to file instead of stdout
  --ai                    Enable Gemini AI reasoning synthesis layer

Flags for 'probe':
  -t, --target <host:port> Target connection to validate

Examples:
  netdiff capture api.internal.corp:443 -o host-a.ndiff
  netdiff capture api.internal.corp:443 -o host-b.ndiff
  netdiff compare host-a.ndiff host-b.ndiff
  netdiff explain host-a.ndiff host-b.ndiff --ai
  netdiff explain host-a.ndiff host-b.ndiff --validate
  netdiff report host-a.ndiff host-b.ndiff -o incident.md
  netdiff probe TEST_TCP_BIND_INTERFACE tun0 -t api.internal.corp:443
`, version)
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
		fmt.Printf("netdiff version %s\n", version)

	case "capture":
		runCapture(os.Args[2:])

	case "compare":
		runCompare(os.Args[2:])

	case "explain":
		runExplain(os.Args[2:])

	case "report":
		runReport(os.Args[2:])

	case "probe":
		runProbe(os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
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

	if *outputFile != "" {
		if err := snapshot.Save(*outputFile, snap); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving snapshot: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Saved snapshot to %s\n", *outputFile)
	} else {
		// Output summary
		fmt.Printf("\n--- Capture Summary ---\n")
		fmt.Printf("Target:     %s\n", snap.Target.Raw)
		if snap.DNS != nil {
			fmt.Printf("DNS:        Success=%v (in %dms)\n", snap.DNS.Success, snap.DNS.ResolutionMs)
		}
		if snap.Route != nil {
			fmt.Printf("Route:      Dev=%s Table=%d Gw=%s Src=%s\n", snap.Route.EgressInterface, snap.Route.Table, snap.Route.Gateway, snap.Route.PreferredSource)
		}
		if snap.TCP != nil {
			fmt.Printf("TCP:        Status=%s Latency=%dms\n", snap.TCP.Status, snap.TCP.LatencyMs)
		}
		if len(snap.CollectionErrors) > 0 {
			fmt.Printf("Warnings:   %v\n", snap.CollectionErrors)
		}
	}
}

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	verbose := fs.Bool("v", false, "Show lower-priority differences")
	fs.BoolVar(verbose, "verbose", false, "Show lower-priority differences")
	asJSON := fs.Bool("j", false, "Output machine-readable JSON")
	fs.BoolVar(asJSON, "json", false, "Output machine-readable JSON")

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
	if err := p.PrintComparison(comparison, *asJSON, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering comparison: %v\n", err)
		os.Exit(1)
	}
}

func runExplain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	aiFlag := fs.Bool("ai", false, "Enable Gemini AI reasoning layer")
	validateFlag := fs.Bool("validate", false, "Immediately execute recommended validation probe against target")

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

	// First print baseline diff
	p := printer.New()
	_ = p.PrintComparison(comparison, false, false)

	reasoner := ai.NewReasoner()
	explanation, err := reasoner.Explain(context.Background(), comparison, *aiFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating explanation: %v\n", err)
		os.Exit(1)
	}

	mode := "Deterministic Diagnostic Engine"
	if explanation.Provider == "gemini" {
		mode = "Gemini AI Diagnostic Synthesis"
	}

	fmt.Printf("\n%s%s=== %s ===%s\n", printer.ColorBold, printer.ColorCyan, mode, printer.ColorReset)
	if explanation.Notice != "" {
		fmt.Printf("%s%s%s\n\n", printer.ColorYellow, explanation.Notice, printer.ColorReset)
	}
	fmt.Printf("%s\n\n", explanation.Summary)

	if len(explanation.Hypotheses) > 0 {
		fmt.Printf("%sDiagnostic Hypotheses:%s\n", printer.ColorBold, printer.ColorReset)
		for i, h := range explanation.Hypotheses {
			fmt.Printf("  %d. %s [%s Support]\n     %s\n", i+1, h.Title, strings.ToUpper(h.SupportLevel), h.Rationale)
		}
		fmt.Println()
	}

	if explanation.NextBestProbe != nil {
		fmt.Printf("%sRecommended Validation Probe:%s\n", printer.ColorBold, printer.ColorReset)
		fmt.Printf("  Action: %s(%s)\n", explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter)
		fmt.Printf("  Why:    %s\n\n", explanation.NextBestProbe.Reason)
	}

	// Active closed-loop validation
	if *validateFlag && explanation.NextBestProbe != nil {
		fmt.Printf("%s%s=== Executing Active Validation Probe: %s(%s) ===%s\n",
			printer.ColorBold, printer.ColorMagenta, explanation.NextBestProbe.ProbeName, explanation.NextBestProbe.Parameter, printer.ColorReset)
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
		if res.Success {
			fmt.Printf("%sAssessment:%s Confirms hypothesis — route/interface bypass establishes connection successfully.\n\n",
				printer.ColorBold, printer.ColorReset)
		} else {
			fmt.Printf("%sAssessment:%s Probe failed; link or upstream hop itself may be down.\n\n",
				printer.ColorBold, printer.ColorReset)
		}
	}
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	outputFile := fs.String("o", "", "Path to output markdown report file")
	fs.StringVar(outputFile, "output", "", "Path to output markdown report file")
	aiFlag := fs.Bool("ai", false, "Use Gemini AI reasoning synthesis layer")

	args = reorderArgs(args)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: report requires two snapshot files: netdiff report <good.ndiff> <bad.ndiff> [-o report.md] [--ai]")
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

	md := report.GenerateMarkdown(comparison, explanation)

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(md), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Saved incident report to %s\n", *outputFile)
	} else {
		fmt.Print(md)
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

	if *targetStr == "" {
		fmt.Fprintln(os.Stderr, "Error: missing --target flag (e.g. -t api.internal:443)")
		os.Exit(1)
	}

	tgt, err := target.Parse(*targetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target %q: %v\n", *targetStr, err)
		os.Exit(1)
	}

	fmt.Printf("Executing validation probe %s(%s) on %s...\n", probeName, param, tgt.Raw)
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

// reorderArgs moves flag arguments ahead of positional arguments so standard flag.FlagSet can parse them
func reorderArgs(args []string) []string {
	var flags []string
	var nonFlags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if (arg == "-o" || arg == "--output" || arg == "-t" || arg == "--target") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			nonFlags = append(nonFlags, arg)
		}
	}
	return append(flags, nonFlags...)
}
