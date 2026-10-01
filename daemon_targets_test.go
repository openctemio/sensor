package main

import (
	"flag"
	"reflect"
	"testing"
)

// A server-controlled daemon scans only what the server dispatches. It used to
// default its own targets to "." and scan its working directory with every
// configured scanner at start and hourly.
func TestResolveTargets(t *testing.T) {
	cases := []struct {
		name             string
		configured       []string
		flagTarget       string
		flagSet          bool
		serverControlled bool
		want             []string
	}{
		{"server-controlled daemon, nothing configured", nil, ".", false, true, nil},
		{"server-controlled daemon, explicit -target", nil, "/src", true, true, []string{"/src"}},
		{"server-controlled daemon, explicit -target .", nil, ".", true, true, []string{"."}},
		{"server-controlled daemon, config targets", []string{"/repo"}, ".", false, true, []string{"/repo"}},
		{"one-shot or standalone daemon default", nil, ".", false, false, []string{"."}},
		{"flag wins over config", []string{"/repo"}, "/other", true, false, []string{"/other"}},
	}
	for _, c := range cases {
		if got := resolveTargets(c.configured, c.flagTarget, c.flagSet, c.serverControlled); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFlagWasSet(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("target", ".", "")
	fs.Bool("daemon", false, "")
	if err := fs.Parse([]string{"-daemon"}); err != nil {
		t.Fatal(err)
	}
	if flagWasSet(fs, "target") || !flagWasSet(fs, "daemon") {
		t.Fatal("flagWasSet must report only flags given on the command line")
	}
}
