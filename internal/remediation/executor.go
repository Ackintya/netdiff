package remediation

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

// CommandRunner executes system commands.
type CommandRunner interface {
	Run(ctx context.Context, cmd string) (output string, err error)
}

// CanaryChecker checks whether network connectivity to the target is restored.
type CanaryChecker interface {
	Check(ctx context.Context, target model.Target, verificationCmd string) (success bool, output string, err error)
}

// FixStatus reflects the final state of the remediation attempt.
type FixStatus string

const (
	FixStatusDryRun                 FixStatus = "DRY_RUN"
	FixStatusAppliedVerified        FixStatus = "APPLIED_VERIFIED"
	FixStatusApplyFailed            FixStatus = "APPLY_FAILED"
	FixStatusCanaryFailedRolledBack FixStatus = "CANARY_FAILED_ROLLED_BACK"
	FixStatusRollbackFailed         FixStatus = "ROLLBACK_FAILED"
	FixStatusNoPlan                 FixStatus = "NO_PLAN"
)

// FixOptions configures the guarded remediation runner.
type FixOptions struct {
	DryRun        bool
	Apply         bool
	AutoRollback  bool
	Timeout       time.Duration
	CommandRunner CommandRunner
	CanaryChecker CanaryChecker
}

// FixResult records the step-by-step execution outcome of the guarded fix.
type FixResult struct {
	Status          FixStatus           `json:"status"`
	Plan            *ai.RemediationPlan `json:"plan"`
	Target          model.Target        `json:"target"`
	ImmediateOutput string              `json:"immediate_output,omitempty"`
	ImmediateError  error               `json:"immediate_error,omitempty"`
	CanarySuccess   bool                `json:"canary_success"`
	CanaryOutput    string              `json:"canary_output,omitempty"`
	CanaryError     error               `json:"canary_error,omitempty"`
	RolledBack      bool                `json:"rolled_back"`
	RollbackOutput  string              `json:"rollback_output,omitempty"`
	RollbackError   error               `json:"rollback_error,omitempty"`
	Steps           []string            `json:"steps"`
}

// OSCommandRunner executes commands via bash on Unix or cmd.exe on Windows.
type OSCommandRunner struct{}

func (r *OSCommandRunner) Run(ctx context.Context, cmdStr string) (string, error) {
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return "", nil
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", cmdStr)
	} else {
		// When running inside a root container or namespace where sudo is not installed,
		// strip leading "sudo " prefix so commands execute directly as root.
		if strings.HasPrefix(cmdStr, "sudo ") {
			if _, lookErr := exec.LookPath("sudo"); lookErr != nil {
				cmdStr = strings.TrimPrefix(cmdStr, "sudo ")
			}
		}
		cmd = exec.CommandContext(ctx, "bash", "-c", cmdStr)
	}

	out, err := cmd.CombinedOutput()
	return string(out), err
}

// DefaultCanaryChecker validates reachability to target endpoint.
type DefaultCanaryChecker struct {
	Runner CommandRunner
}

func (c *DefaultCanaryChecker) Check(ctx context.Context, target model.Target, verificationCmd string) (bool, string, error) {
	var stepLogs []string

	// 1. If custom verificationCmd is provided, execute it first
	if strings.TrimSpace(verificationCmd) != "" && c.Runner != nil {
		out, err := c.Runner.Run(ctx, verificationCmd)
		if err != nil {
			stepLogs = append(stepLogs, fmt.Sprintf("Verification command returned non-zero (%v): %s", err, strings.TrimSpace(out)))
			return false, strings.Join(stepLogs, "\n"), fmt.Errorf("verification command failed: %w", err)
		}
		stepLogs = append(stepLogs, fmt.Sprintf("Verification command succeeded: %s", strings.TrimSpace(out)))
	}

	// 2. Canary active TCP probe to the target host and port (if port is specified)
	if target.Port > 0 && target.Host != "" {
		addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
		dialer := net.Dialer{Timeout: 3 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			stepLogs = append(stepLogs, fmt.Sprintf("Canary TCP probe to %s failed: %v", addr, err))
			return false, strings.Join(stepLogs, "\n"), err
		}
		_ = conn.Close()

		stepLogs = append(stepLogs, fmt.Sprintf("Canary TCP probe to %s succeeded (connection established)", addr))
	}

	return true, strings.Join(stepLogs, "\n"), nil
}

// Executor coordinates guarded remediation with automated canary verification and rollback.
type Executor struct {
	opts FixOptions
}

// NewExecutor constructs an Executor with sensible defaults.
func NewExecutor(opts FixOptions) *Executor {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.CommandRunner == nil {
		opts.CommandRunner = &OSCommandRunner{}
	}
	if opts.CanaryChecker == nil {
		opts.CanaryChecker = &DefaultCanaryChecker{Runner: opts.CommandRunner}
	}
	return &Executor{opts: opts}
}

// Execute performs the guarded remediation workflow.
func (e *Executor) Execute(ctx context.Context, plan *ai.RemediationPlan, tgt model.Target) (*FixResult, error) {
	res := &FixResult{
		Plan:   plan,
		Target: tgt,
		Steps:  make([]string, 0),
	}

	if plan == nil || strings.TrimSpace(plan.ImmediateBash) == "" {
		res.Status = FixStatusNoPlan
		res.Steps = append(res.Steps, "No actionable remediation commands found for this scenario.")
		return res, nil
	}

	// Mode 1: Dry Run (default when Apply is false)
	if e.opts.DryRun || !e.opts.Apply {
		res.Status = FixStatusDryRun
		res.Steps = append(res.Steps,
			fmt.Sprintf("[DRY-RUN] Would execute remediation: %s", plan.ImmediateBash),
			fmt.Sprintf("[DRY-RUN] Guarded rollback prepared: %s", plan.RollbackBash),
		)
		if plan.VerificationCmd != "" {
			res.Steps = append(res.Steps, fmt.Sprintf("[DRY-RUN] Verification probe: %s", plan.VerificationCmd))
		}
		return res, nil
	}

	// Mode 2: Apply with Canary Validation & Automatic Rollback
	res.Steps = append(res.Steps, fmt.Sprintf("[APPLY] Executing remediation: %s", plan.ImmediateBash))

	execCtx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	// Step 1: Apply remediation
	out, err := e.opts.CommandRunner.Run(execCtx, plan.ImmediateBash)
	res.ImmediateOutput = strings.TrimSpace(out)
	res.ImmediateError = err

	if err != nil {
		res.Status = FixStatusApplyFailed
		res.Steps = append(res.Steps, fmt.Sprintf("[ERROR] Remediation execution failed: %v (output: %s)", err, res.ImmediateOutput))
		return res, fmt.Errorf("remediation command failed: %w", err)
	}
	res.Steps = append(res.Steps, "[SUCCESS] Remediation applied successfully.")

	// Step 2: Canary validation probe
	res.Steps = append(res.Steps, fmt.Sprintf("[CANARY] Executing validation probe against %s...", tgt.Raw))
	canaryCtx, canaryCancel := context.WithTimeout(ctx, 5*time.Second)
	defer canaryCancel()

	canaryPass, canaryOut, canaryErr := e.opts.CanaryChecker.Check(canaryCtx, tgt, plan.VerificationCmd)
	res.CanarySuccess = canaryPass
	res.CanaryOutput = canaryOut
	res.CanaryError = canaryErr

	if canaryPass {
		res.Status = FixStatusAppliedVerified
		res.Steps = append(res.Steps, "[VERIFIED] Target connectivity confirmed healthy. Retaining changes.")
		return res, nil
	}

	// Step 3: Canary failed -> Automatic Rollback if enabled
	res.Steps = append(res.Steps, fmt.Sprintf("[ALERT] Canary check failed: %v", canaryErr))

	if !e.opts.AutoRollback || strings.TrimSpace(plan.RollbackBash) == "" || strings.HasPrefix(plan.RollbackBash, "#") {
		res.Status = FixStatusCanaryFailedRolledBack
		res.Steps = append(res.Steps, "[NOTICE] Auto-rollback skipped (disabled or no rollback command defined).")
		return res, nil
	}

	res.Steps = append(res.Steps, fmt.Sprintf("[ROLLBACK] Triggering automated safety rollback: %s", plan.RollbackBash))
	rbOut, rbErr := e.opts.CommandRunner.Run(execCtx, plan.RollbackBash)
	res.RolledBack = true
	res.RollbackOutput = strings.TrimSpace(rbOut)
	res.RollbackError = rbErr

	if rbErr != nil {
		res.Status = FixStatusRollbackFailed
		res.Steps = append(res.Steps, fmt.Sprintf("[CRITICAL] Rollback execution failed: %v (output: %s)", rbErr, res.RollbackOutput))
		return res, fmt.Errorf("canary probe failed and rollback failed: %w", rbErr)
	}

	res.Status = FixStatusCanaryFailedRolledBack
	res.Steps = append(res.Steps, "[RESTORED] Pre-remediation network state restored safely.")
	return res, nil
}
