package toolrun

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// MustManifest loads a tool descriptor embedded in the sensor (tool.yaml,
// strict: an unknown key, a capability outside the taxonomy or a tier below
// a capability's floor is an error). An invalid descriptor compiled into the
// sensor stops it at start: it never runs a tool with a contract it cannot
// enforce.
func MustManifest(yaml []byte) tool.Manifest {
	m, err := tool.LoadManifest(yaml)
	if err != nil {
		panic(fmt.Sprintf("toolrun: embedded tool descriptor: %v", err))
	}
	return m
}

// Contract is the contract a compiled-in tool reports in the sensor
// manifest: its descriptor by digest, with the origin "builtin" (the tool is
// part of the signed sensor binary). The platform derives the trust level
// from the origin.
func Contract(m tool.Manifest) *core.ToolContract {
	c := m.Contract()
	c.Origin = core.ToolOriginBuiltin
	return c
}
