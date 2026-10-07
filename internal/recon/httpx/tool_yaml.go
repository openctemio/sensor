package httpx

import _ "embed"

// ToolYAML is the tool's descriptor (OpenCTEM Tool Contract v1): the one
// place its contract is written. The sensor loads it at start and reports
// it to the platform by digest.
//
//go:embed tool.yaml
var ToolYAML []byte
