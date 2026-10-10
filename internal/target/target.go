package target

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"netdiff/pkg/model"
)

var (
	ErrInvalidFormat = errors.New("target must be in format 'host:port' or '[ipv6]:port'")
	ErrInvalidPort   = errors.New("port must be an integer between 1 and 65535")
	ErrEmptyHost     = errors.New("host cannot be empty")
)

// Parse takes a target string like "api.foo.com:443" or "10.0.8.14:5432" and returns a model.Target.
func Parse(input string) (model.Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return model.Target{}, ErrInvalidFormat
	}

	host, portStr, err := net.SplitHostPort(input)
	if err != nil {
		// If user entered without port, could check if port is missing
		return model.Target{}, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return model.Target{}, ErrEmptyHost
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return model.Target{}, ErrInvalidPort
	}

	// Determine if host is an IP address
	parsedIP := net.ParseIP(host)
	isIP := parsedIP != nil

	return model.Target{
		Raw:      input,
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		IsIP:     isIP,
	}, nil
}
