package executor

import "testing"

// SENSOR_ALLOW_PRIVATE_TARGETS is the one switch for private scan targets;
// the removed names never widen it (main refuses to start while one is set).
func TestPrivateTargetsFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, false},
		{"new name", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "1"}, true},
		{"removed name does not widen", map[string]string{"AGENT_ALLOW_PRIVATE_TARGETS": "1"}, false},
		{"SDK name does not widen", map[string]string{"OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS": "1"}, false},
		{"egress switch does not widen", map[string]string{"OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE": "1"}, false},
		{"only 1 enables", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "true"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }
			if got := privateTargetsFromEnv(lookup); got != tc.want {
				t.Fatalf("privateTargetsFromEnv = %v, want %v", got, tc.want)
			}
		})
	}
}
