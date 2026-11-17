package firewall

import (
	"testing"
)

func TestHasActiveIptablesRules_DefaultAccept(t *testing.T) {
	output := `-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
`
	if HasActiveIptablesRules(output) {
		t.Error("expected false for default ACCEPT policies with no rules")
	}
}

func TestHasActiveIptablesRules_AppendDrop(t *testing.T) {
	output := `-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A OUTPUT -p tcp -m tcp --dport 8080 -j DROP
`
	if !HasActiveIptablesRules(output) {
		t.Error("expected true when -A rule is present")
	}
}

func TestHasActiveIptablesRules_PolicyDrop(t *testing.T) {
	output := `-P INPUT DROP
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
`
	if !HasActiveIptablesRules(output) {
		t.Error("expected true when default policy is DROP")
	}
}
