package main

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// The test binary is also the tool child of the ported tools, as the
// sensor binary is. (It is not the sandbox launcher: these tests use fake
// tools that write outside a task directory.)
func TestMain(m *testing.M) {
	adapter.Dispatch(builtinTools()...)
	os.Exit(m.Run())
}
