package rule

import (
	"context"
)

type Collector interface {
	Collect(ctx context.Context, destIP string) (matchedRule string, allRules []string, err error)
}
