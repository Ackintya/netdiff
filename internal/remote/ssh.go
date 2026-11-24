package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"netdiff/pkg/model"
)

// SSHClient defines the interface for remote snapshot capture.
type SSHClient interface {
	CaptureSnapshot(ctx context.Context, sshSpec string, target string) (*model.Snapshot, error)
}

// SystemSSHClient executes remote captures using the local OpenSSH client.
type SystemSSHClient struct{}

// NewClient returns a new default SSH client.
func NewClient() SSHClient {
	return &SystemSSHClient{}
}

// ParseSSHSpec parses a remote spec like "user@host:2222", "host:22", or "user@host"
// into hostname, port, and user arguments suitable for ssh.
func ParseSSHSpec(spec string) (host string, port string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", fmt.Errorf("remote SSH specification cannot be empty")
	}

	// Check if port is specified after a colon (e.g. host:2222 or user@host:2222)
	// Be careful with IPv6 if in brackets, but standard host[:port]
	parts := strings.Split(spec, ":")
	if len(parts) == 2 && !strings.Contains(parts[1], "/") {
		return parts[0], parts[1], nil
	}
	return spec, "", nil
}

// CaptureSnapshot connects to the remote host via SSH, executes 'netdiff capture <target>',
// and parses the resulting JSON snapshot directly from stdout.
func (c *SystemSSHClient) CaptureSnapshot(ctx context.Context, sshSpec string, target string) (*model.Snapshot, error) {
	host, port, err := ParseSSHSpec(sshSpec)
	if err != nil {
		return nil, err
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
	}
	if port != "" {
		args = append(args, "-p", port)
	}

	remoteCmd := fmt.Sprintf(`PATH="$PATH:/usr/local/bin:/usr/bin:~/.local/bin:~/go/bin" netdiff capture %s`, target)
	args = append(args, host, remoteCmd)

	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errOutput := strings.TrimSpace(stderr.String())
		if strings.Contains(errOutput, "netdiff: command not found") || strings.Contains(errOutput, "netdiff: not found") {
			return nil, fmt.Errorf("remote host '%s' does not have 'netdiff' installed in PATH.\nInstall on remote host with: ssh %s 'go install github.com/Ackintya/netdiff/cmd/netdiff@latest'", host, host)
		}
		if strings.Contains(errOutput, "Permission denied") {
			return nil, fmt.Errorf("ssh authentication failed for '%s': %s", host, errOutput)
		}
		if strings.Contains(errOutput, "Connection refused") {
			return nil, fmt.Errorf("ssh connection refused to '%s': %s", host, errOutput)
		}
		if errOutput != "" {
			return nil, fmt.Errorf("ssh command failed on '%s': %s", host, errOutput)
		}
		return nil, fmt.Errorf("ssh execution failed: %w", err)
	}

	rawJSON := stdout.Bytes()
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("remote host '%s' returned empty output for target '%s'", host, target)
	}

	// Handle case where stdout might have non-JSON banner lines before the JSON object
	firstBrace := bytes.IndexByte(rawJSON, '{')
	if firstBrace == -1 {
		return nil, fmt.Errorf("invalid response from remote netdiff: no JSON object found in output:\n%s", string(rawJSON))
	}
	rawJSON = rawJSON[firstBrace:]

	var snap model.Snapshot
	if err := json.Unmarshal(rawJSON, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse remote snapshot JSON: %w", err)
	}

	return &snap, nil
}
