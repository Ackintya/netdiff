package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

type mockCommandRunner struct {
	executed []string
	outputs  map[string]string
	errs     map[string]error
}

func (m *mockCommandRunner) Run(ctx context.Context, cmd string) (string, error) {
	m.executed = append(m.executed, cmd)
	if err, ok := m.errs[cmd]; ok && err != nil {
		return m.outputs[cmd], err
	}
	return m.outputs[cmd], nil
}

type mockCanaryChecker struct {
	pass   bool
	output string
	err    error
}

func (m *mockCanaryChecker) Check(ctx context.Context, target model.Target, verificationCmd string) (bool, string, error) {
	return m.pass, m.output, m.err
}

func TestExecute_DryRun(t *testing.T) {
	runner := &mockCommandRunner{outputs: make(map[string]string), errs: make(map[string]error)}
	canary := &mockCanaryChecker{pass: true}

	exec := NewExecutor(FixOptions{
		DryRun:        true,
		Apply:         false,
		CommandRunner: runner,
		CanaryChecker: canary,
	})

	plan := &ai.RemediationPlan{
		ImmediateBash:   "ip rule add to 10.40.8.21/32 lookup 200",
		RollbackBash:    "ip rule del to 10.40.8.21/32 lookup 200",
		VerificationCmd: "ip rule show",
	}
	tgt := model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080}

	res, err := exec.Execute(context.Background(), plan, tgt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != FixStatusDryRun {
		t.Errorf("expected status %s, got %s", FixStatusDryRun, res.Status)
	}
	if len(runner.executed) != 0 {
		t.Errorf("dry run must not execute any commands, executed: %v", runner.executed)
	}
	if res.RolledBack {
		t.Errorf("dry run should not set RolledBack")
	}
}

func TestExecute_ApplySuccess(t *testing.T) {
	fixCmd := "ip rule add to 10.40.8.21/32 lookup 200"
	rbCmd := "ip rule del to 10.40.8.21/32 lookup 200"
	runner := &mockCommandRunner{
		outputs: map[string]string{fixCmd: "rule added"},
		errs:    make(map[string]error),
	}
	canary := &mockCanaryChecker{pass: true, output: "TCP connect ok"}

	exec := NewExecutor(FixOptions{
		DryRun:        false,
		Apply:         true,
		AutoRollback:  true,
		CommandRunner: runner,
		CanaryChecker: canary,
	})

	plan := &ai.RemediationPlan{
		ImmediateBash: fixCmd,
		RollbackBash:  rbCmd,
	}
	tgt := model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080}

	res, err := exec.Execute(context.Background(), plan, tgt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != FixStatusAppliedVerified {
		t.Errorf("expected status %s, got %s", FixStatusAppliedVerified, res.Status)
	}
	if len(runner.executed) != 1 || runner.executed[0] != fixCmd {
		t.Errorf("expected only fix command executed, got: %v", runner.executed)
	}
	if !res.CanarySuccess {
		t.Errorf("expected canary success true")
	}
	if res.RolledBack {
		t.Errorf("expected rolled back false")
	}
}

func TestExecute_ApplyCanaryFails_AutoRollbackSuccess(t *testing.T) {
	fixCmd := "ip rule add to 10.40.8.21/32 lookup 200"
	rbCmd := "ip rule del to 10.40.8.21/32 lookup 200"
	runner := &mockCommandRunner{
		outputs: map[string]string{
			fixCmd: "rule added",
			rbCmd:  "rule deleted",
		},
		errs: make(map[string]error),
	}
	canary := &mockCanaryChecker{
		pass:   false,
		output: "connection timeout",
		err:    errors.New("i/o timeout"),
	}

	exec := NewExecutor(FixOptions{
		DryRun:        false,
		Apply:         true,
		AutoRollback:  true,
		CommandRunner: runner,
		CanaryChecker: canary,
	})

	plan := &ai.RemediationPlan{
		ImmediateBash: fixCmd,
		RollbackBash:  rbCmd,
	}
	tgt := model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080}

	res, err := exec.Execute(context.Background(), plan, tgt)
	if err != nil {
		t.Fatalf("expected nil err on safe rollback recovery, got: %v", err)
	}

	if res.Status != FixStatusCanaryFailedRolledBack {
		t.Errorf("expected status %s, got %s", FixStatusCanaryFailedRolledBack, res.Status)
	}
	if !res.RolledBack {
		t.Errorf("expected rolled back true")
	}
	if len(runner.executed) != 2 {
		t.Fatalf("expected 2 commands executed (fix + rollback), got %d: %v", len(runner.executed), runner.executed)
	}
	if runner.executed[0] != fixCmd || runner.executed[1] != rbCmd {
		t.Errorf("unexpected command order: %v", runner.executed)
	}
}

func TestExecute_ApplyCommandFails(t *testing.T) {
	fixCmd := "ip rule add to 10.40.8.21/32 lookup 200"
	runner := &mockCommandRunner{
		outputs: map[string]string{fixCmd: "RTNETLINK answers: Operation not permitted"},
		errs:    map[string]error{fixCmd: errors.New("exit status 2")},
	}
	canary := &mockCanaryChecker{pass: true}

	exec := NewExecutor(FixOptions{
		DryRun:        false,
		Apply:         true,
		CommandRunner: runner,
		CanaryChecker: canary,
	})

	plan := &ai.RemediationPlan{
		ImmediateBash: fixCmd,
		RollbackBash:  "ip rule del to 10.40.8.21/32 lookup 200",
	}
	tgt := model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080}

	res, err := exec.Execute(context.Background(), plan, tgt)
	if err == nil {
		t.Fatal("expected error on command failure, got nil")
	}

	if res.Status != FixStatusApplyFailed {
		t.Errorf("expected status %s, got %s", FixStatusApplyFailed, res.Status)
	}
	if len(runner.executed) != 1 {
		t.Errorf("expected only 1 command attempt, got: %v", runner.executed)
	}
}

func TestExecute_RollbackFails(t *testing.T) {
	fixCmd := "ip rule add to 10.40.8.21/32 lookup 200"
	rbCmd := "ip rule del to 10.40.8.21/32 lookup 200"
	runner := &mockCommandRunner{
		outputs: map[string]string{
			fixCmd: "applied",
			rbCmd:  "failed to delete rule",
		},
		errs: map[string]error{
			rbCmd: errors.New("cannot delete rule"),
		},
	}
	canary := &mockCanaryChecker{pass: false, err: errors.New("still down")}

	exec := NewExecutor(FixOptions{
		DryRun:        false,
		Apply:         true,
		AutoRollback:  true,
		CommandRunner: runner,
		CanaryChecker: canary,
	})

	plan := &ai.RemediationPlan{
		ImmediateBash: fixCmd,
		RollbackBash:  rbCmd,
	}
	tgt := model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080}

	res, err := exec.Execute(context.Background(), plan, tgt)
	if err == nil {
		t.Fatal("expected error when rollback fails, got nil")
	}

	if res.Status != FixStatusRollbackFailed {
		t.Errorf("expected status %s, got %s", FixStatusRollbackFailed, res.Status)
	}
	if !res.RolledBack {
		t.Errorf("expected RolledBack flag to be true even if rb failed")
	}
}

func TestExecute_EmptyPlan(t *testing.T) {
	exec := NewExecutor(FixOptions{DryRun: true})
	res, err := exec.Execute(context.Background(), nil, model.Target{Raw: "test:80"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != FixStatusNoPlan {
		t.Errorf("expected FixStatusNoPlan, got %s", res.Status)
	}
}

func TestOSCommandRunner_Empty(t *testing.T) {
	r := &OSCommandRunner{}
	out, err := r.Run(context.Background(), "")
	if err != nil || out != "" {
		t.Errorf("expected empty output and nil err, got %q, %v", out, err)
	}
}

func TestDefaultCanaryChecker_Timeout(t *testing.T) {
	c := &DefaultCanaryChecker{
		Runner: &mockCommandRunner{outputs: make(map[string]string), errs: make(map[string]error)},
	}
	// Test against non-routable blackhole IP with brief context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	tgt := model.Target{Raw: "192.0.2.1:65534", Host: "192.0.2.1", Port: 65534}
	pass, out, err := c.Check(ctx, tgt, "")
	if pass {
		t.Errorf("expected canary to fail for unreachable address")
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if !strings.Contains(out, "failed") {
		t.Errorf("expected out to contain 'failed', got: %s", out)
	}
}

func TestDefaultCanaryChecker_VerificationCommandFails(t *testing.T) {
	runner := &mockCommandRunner{
		outputs: map[string]string{"ip rule show": ""},
		errs:    map[string]error{"ip rule show": errors.New("exit status 1")},
	}
	c := &DefaultCanaryChecker{Runner: runner}

	tgt := model.Target{Raw: "127.0.0.1:80", Host: "127.0.0.1", Port: 80}
	pass, out, err := c.Check(context.Background(), tgt, "ip rule show")
	if pass {
		t.Errorf("expected canary check to fail when verification command fails")
	}
	if err == nil {
		t.Errorf("expected non-nil error")
	}
	if !strings.Contains(out, "returned non-zero") {
		t.Errorf("expected step log to record non-zero output, got: %s", out)
	}
}

func TestDefaultCanaryChecker_PortZeroVerification(t *testing.T) {
	runner := &mockCommandRunner{
		outputs: map[string]string{"ip link show dev eth0": "state UP"},
		errs:    make(map[string]error),
	}
	c := &DefaultCanaryChecker{Runner: runner}

	// Port 0 skips TCP dial and verifies via verificationCmd alone
	tgt := model.Target{Raw: "dummy", Host: "dummy", Port: 0}
	pass, out, err := c.Check(context.Background(), tgt, "ip link show dev eth0")
	if !pass || err != nil {
		t.Fatalf("expected canary to pass for port 0 with successful verification command, got: %v (out: %s)", err, out)
	}
	if !strings.Contains(out, "succeeded") {
		t.Errorf("expected output to contain succeeded, got: %s", out)
	}
}
