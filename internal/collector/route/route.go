package route

import (
	"context"
	"netdiff/pkg/model"
)

type Collector interface {
	Collect(ctx context.Context, destIP string) (*model.RouteReport, error)
}
