package dnsx

import _ "embed"

// EnumToolYAML is the descriptor of the brute-force tool (OpenCTEM Tool
// Contract v1).
//
//go:embed enum_tool.yaml
var EnumToolYAML []byte
