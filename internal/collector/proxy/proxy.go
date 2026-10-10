package proxy

import (
	"context"
	"os"
	"strings"

	"netdiff/pkg/model"
)

type Collector struct{}

func New() *Collector {
	return &Collector{}
}

func (c *Collector) Collect(_ context.Context, target model.Target) (*model.ProxyReport, error) {
	httpProxy := getEnvAny("HTTP_PROXY", "http_proxy")
	httpsProxy := getEnvAny("HTTPS_PROXY", "https_proxy")
	noProxy := getEnvAny("NO_PROXY", "no_proxy")

	active := false
	if target.Port == 443 {
		if httpsProxy != "" && !matchesNoProxy(target.Host, noProxy) {
			active = true
		}
	} else {
		if httpProxy != "" && !matchesNoProxy(target.Host, noProxy) {
			active = true
		}
	}

	return &model.ProxyReport{
		HTTPProxy:  httpProxy,
		HTTPSProxy: httpsProxy,
		NoProxy:    noProxy,
		Active:     active,
	}, nil
}

func getEnvAny(keys ...string) string {
	for _, k := range keys {
		if val := os.Getenv(k); val != "" {
			return val
		}
	}
	return ""
}

func matchesNoProxy(host, noProxy string) bool {
	if noProxy == "" {
		return false
	}
	for _, entry := range strings.Split(noProxy, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" || entry == host || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}
