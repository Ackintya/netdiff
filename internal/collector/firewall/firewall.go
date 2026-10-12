package firewall

import (
	"context"
	"netdiff/pkg/model"
)

type Collector interface {
	Collect(ctx context.Context) (*model.FirewallReport, error)
}
