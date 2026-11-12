package jobfiles_test

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/sensor/internal/jobfiles"
	"github.com/openctemio/sensor/internal/jobfiles/jobfilestest"
)

func TestMain(m *testing.M) {
	jobfilestest.RunToolIfRequested()
	os.Exit(m.Run())
}

// SECURITY: a job file is readable by its own job's tool only.
func TestFileIsPrivateToItsJob(t *testing.T) {
	ctx, path, cleanup, err := jobfiles.File(context.Background(), "jobfiles-test", "targets.txt", []byte("a.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	jobfilestest.AssertJobPrivate(t, ctx, path)
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup left %s: %v", path, err)
	}
}
