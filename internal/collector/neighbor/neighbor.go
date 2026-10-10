package neighbor

import (
	"context"
	"netdiff/pkg/model"
)

type Collector interface {
	Collect(ctx context.Context, gatewayIP, ifaceName string) (*model.NeighborReport, error)
}
