package target

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantHost   string
		wantPort   int
		wantIsIP   bool
		wantErr    bool
	}{
		{
			name:     "valid hostname with port",
			input:    "api.foo.com:443",
			wantHost: "api.foo.com",
			wantPort: 443,
			wantIsIP: false,
			wantErr:  false,
		},
		{
			name:     "valid ipv4 with port",
			input:    "10.0.8.14:5432",
			wantHost: "10.0.8.14",
			wantPort: 5432,
			wantIsIP: true,
			wantErr:  false,
		},
		{
			name:     "valid ipv6 with port",
			input:    "[2001:db8::1]:8080",
			wantHost: "2001:db8::1",
			wantPort: 8080,
			wantIsIP: true,
			wantErr:  false,
		},
		{
			name:    "missing port",
			input:   "api.foo.com",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "api.foo.com:99999",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.Host != tt.wantHost {
					t.Errorf("got host %q, want %q", got.Host, tt.wantHost)
				}
				if got.Port != tt.wantPort {
					t.Errorf("got port %d, want %d", got.Port, tt.wantPort)
				}
				if got.IsIP != tt.wantIsIP {
					t.Errorf("got isIP %v, want %v", got.IsIP, tt.wantIsIP)
				}
				if got.Protocol != "tcp" {
					t.Errorf("got protocol %q, want tcp", got.Protocol)
				}
			}
		})
	}
}
