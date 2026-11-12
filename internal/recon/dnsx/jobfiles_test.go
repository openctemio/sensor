package dnsx

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/jobfiles/jobfilestest"
)

// SECURITY: the cut label list and the host list a run reads are private job
// files: readable by the job's own run only.
func TestListsArePrivateToTheirJob(t *testing.T) {
	src := writeFile(t, "labels.txt", "www\nmail\napi\n")
	ctx, cut, cleanup, err := cutList(context.Background(), src, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if raw, _ := os.ReadFile(cut); strings.TrimSpace(string(raw)) != "www\nmail" {
		t.Fatalf("cut list = %q", raw)
	}
	jobfilestest.AssertJobPrivate(t, ctx, cut)

	ctx, hosts, cleanupHosts, err := writeJobList(context.Background(), "dnsx-input", []string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupHosts()
	jobfilestest.AssertJobPrivate(t, ctx, hosts)
}
