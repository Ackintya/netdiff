//go:build !linux

package rule

import (
	"context"
)

type FallbackRuleCollector struct{}

func New() Collector {
	return &FallbackRuleCollector{}
}

func (c *FallbackRuleCollector) Collect(_ context.Context, _ string) (string, []string, error) {
	return "0: from all lookup main", []string{"0: from all lookup main"}, nil
}
