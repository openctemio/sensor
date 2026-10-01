package executor

import "testing"

// SENSOR_ALLOW_PRIVATE_TARGETS replaced AGENT_ALLOW_PRIVATE_TARGETS; the
// executor reads it at package init, before main applies renamed settings,
// so it must understand both names itself and fail closed on a conflict.
func TestPrivateTargetsFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, false},
		{"new name", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "1"}, true},
		{"old name", map[string]string{"AGENT_ALLOW_PRIVATE_TARGETS": "1"}, true},
		{"both on", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "1", "AGENT_ALLOW_PRIVATE_TARGETS": "1"}, true},
		{"conflict fails closed", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "0", "AGENT_ALLOW_PRIVATE_TARGETS": "1"}, false},
		{"conflict fails closed (reverse)", map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "1", "AGENT_ALLOW_PRIVATE_TARGETS": "0"}, false},
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
