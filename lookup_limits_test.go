package main

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/lookup/asn"
	"github.com/openctemio/sensor/internal/lookup/rdap"
	"testing"
)

func TestLookupsAcceptScopeLimits(t *testing.T) {
	for _, s := range []any{rdap.NewScanner(), asn.NewScanner()} {
		ls, ok := s.(core.ScopeLimitScanner)
		if !ok || !ls.EnforcesScopeLimits() {
			t.Fatalf("%T must accept scope-limited jobs: it never contacts the target", s)
		}
	}
}
