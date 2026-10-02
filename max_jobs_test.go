package main

import "testing"

func TestResolveMaxJobs(t *testing.T) {
	cases := []struct {
		name    string
		flagSet bool
		flagVal int
		env     string
		cfg     int
		want    int
		wantErr bool
	}{
		{name: "default", want: 5},
		{name: "config", cfg: 8, want: 8},
		{name: "env over config", env: "3", cfg: 8, want: 3},
		{name: "flag over env", flagSet: true, flagVal: 12, env: "3", cfg: 8, want: 12},
		{name: "flag default value not set: env wins", flagVal: 5, env: "2", want: 2},
		{name: "env not a number", env: "lots", wantErr: true},
		{name: "env zero", env: "0", wantErr: true},
		{name: "flag above limit", flagSet: true, flagVal: 101, wantErr: true},
		{name: "config negative", cfg: -1, wantErr: true},
		{name: "upper bound", env: "100", want: 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveMaxJobs(c.flagSet, c.flagVal, c.env, c.cfg)
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("resolveMaxJobs = %d, %v; want %d (error %v)", got, err, c.want, c.wantErr)
			}
		})
	}
}
