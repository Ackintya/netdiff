package remote

import (
	"context"
	"testing"

	"netdiff/pkg/model"
)

func TestParseSSHSpec(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			input:    "staging-box",
			wantHost: "staging-box",
			wantPort: "",
			wantErr:  false,
		},
		{
			input:    "root@10.0.0.5",
			wantHost: "root@10.0.0.5",
			wantPort: "",
			wantErr:  false,
		},
		{
			input:    "deploy@api.corp.internal:2222",
			wantHost: "deploy@api.corp.internal",
			wantPort: "2222",
			wantErr:  false,
		},
		{
			input:    "192.168.1.100:22",
			wantHost: "192.168.1.100",
			wantPort: "22",
			wantErr:  false,
		},
		{
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port, err := ParseSSHSpec(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSSHSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if host != tt.wantHost {
					t.Errorf("host = %q, want %q", host, tt.wantHost)
				}
				if port != tt.wantPort {
					t.Errorf("port = %q, want %q", port, tt.wantPort)
				}
			}
		})
	}
}

type MockSSHClient struct {
	SnapFunc func(ctx context.Context, sshSpec string, target string) (*model.Snapshot, error)
}

func (m *MockSSHClient) CaptureSnapshot(ctx context.Context, sshSpec string, target string) (*model.Snapshot, error) {
	return m.SnapFunc(ctx, sshSpec, target)
}

func TestMockSSHClient(t *testing.T) {
	mock := &MockSSHClient{
		SnapFunc: func(ctx context.Context, sshSpec string, target string) (*model.Snapshot, error) {
			return &model.Snapshot{
				Target: model.Target{
					Raw:  target,
					Host: "example.com",
					Port: 443,
				},
				Metadata: model.SnapshotMetadata{
					Hostname: "remote-staging-node",
				},
			}, nil
		},
	}

	snap, err := mock.CaptureSnapshot(context.Background(), "user@host", "example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.Metadata.Hostname != "remote-staging-node" {
		t.Errorf("expected remote hostname, got %s", snap.Metadata.Hostname)
	}
}
