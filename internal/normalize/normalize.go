package normalize

import (
	"sort"
	"strings"

	"netdiff/pkg/model"
)

// Snapshot returns a copy of the snapshot with normalized fields for semantic comparison.
func Snapshot(in *model.Snapshot) *model.Snapshot {
	if in == nil {
		return nil
	}

	clone := *in

	// Normalize DNS sets
	if clone.DNS != nil {
		dnsCopy := *clone.DNS
		dnsCopy.ARecords = sortAndDedup(dnsCopy.ARecords)
		dnsCopy.AAAARecords = sortAndDedup(dnsCopy.AAAARecords)
		clone.DNS = &dnsCopy
	}

	// Normalize Route
	if clone.Route != nil {
		routeCopy := *clone.Route
		if routeCopy.Table == 0 {
			routeCopy.Table = 254
		}
		if routeCopy.TableName == "" && routeCopy.Table == 254 {
			routeCopy.TableName = "main"
		}
		clone.Route = &routeCopy
	}

	// Normalize Interface
	if clone.Interface != nil {
		ifaceCopy := *clone.Interface
		if ifaceCopy.Role == "" {
			ifaceCopy.Role = "physical"
		}
		clone.Interface = &ifaceCopy
	}

	// Normalize Proxy
	if clone.Proxy != nil {
		pCopy := *clone.Proxy
		pCopy.HTTPProxy = strings.TrimRight(strings.TrimSpace(pCopy.HTTPProxy), "/")
		pCopy.HTTPSProxy = strings.TrimRight(strings.TrimSpace(pCopy.HTTPSProxy), "/")
		clone.Proxy = &pCopy
	}

	return &clone
}

func sortAndDedup(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var res []string
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" && !seen[it] {
			seen[it] = true
			res = append(res, it)
		}
	}
	sort.Strings(res)
	return res
}
