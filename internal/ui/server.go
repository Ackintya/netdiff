package ui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"netdiff/internal/ai"
	"netdiff/internal/printer"
	"netdiff/internal/report"
	"netdiff/pkg/model"
)

//go:embed assets/index.html
var assetsFS embed.FS

// Payload represents the JSON payload served by /api/data.
type Payload struct {
	Comparison  *model.ComparisonReport `json:"comparison"`
	Explanation *ai.ExplanationReport  `json:"explanation"`
}

// StartServer starts the local web server and serves the visual DAG comparison interface.
func StartServer(comp *model.ComparisonReport, exp *ai.ExplanationReport, port int, autoOpen bool) error {
	mux := http.NewServeMux()

	// 1. Root dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := assetsFS.ReadFile("assets/index.html")
		if err != nil {
			http.Error(w, "Asset not found: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	// 2. API Data
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		payload := Payload{
			Comparison:  comp,
			Explanation: exp,
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	// 3. API Report Markdown Download
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		md := report.GenerateMarkdown(comp, exp)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"netdiff-incident-report.md\"")
		_, _ = w.Write([]byte(md))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// Fallback to dynamic port if requested port is occupied
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind local port: %w", err)
		}
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Printf("\n%s%s=== NetDiff Interactive Web Visualizer ===%s\n", printer.ColorBold, printer.ColorCyan, printer.ColorReset)
	fmt.Printf("Dashboard active at: %s%s%s\n", printer.ColorGreen, url, printer.ColorReset)
	fmt.Printf("Press %sCtrl+C%s to stop server\n\n", printer.ColorBold, printer.ColorReset)

	if autoOpen {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}

	// Graceful shutdown handling
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Serve(listener)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-sigChan:
		fmt.Printf("\nShutting down NetDiff UI server...\n")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}

	return nil
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	_ = exec.Command(cmd, args...).Start()
}
