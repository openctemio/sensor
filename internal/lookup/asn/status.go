package asn

import (
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/sensor/internal/lookup"
)

// DatasetState is what the sensor knows about its cached routing dataset,
// for the config report.
type DatasetState struct {
	// Age of the copy.
	Age time.Duration
	// LastResult is the outcome of the last refresh: ok, not_modified or
	// failed ("" when unknown).
	LastResult string
	// Source is the host the dataset is fetched from.
	Source string
}

// StaleAfter is the age after which a copy is reported as out of date: the
// refresh runs daily, so a week old means refreshes keep failing.
const StaleAfter = 7 * 24 * time.Hour

// State reads the cached dataset under cacheRoot (the lookup cache root),
// false when the tool has not downloaded it yet. A host-local mirror is
// reported by its host name.
func State(cacheRoot string) (DatasetState, bool) {
	path := filepath.Join(cacheRoot, "asn", dataset.Name)
	age, ok := lookup.Age(path)
	if !ok {
		if _, err := os.Stat(path + ".meta"); err != nil {
			return DatasetState{}, false
		}
	}
	m := lookup.ReadMeta(path)
	src := dataset.URL
	if v := os.Getenv(lookup.EnvASNDatasetURL); v != "" {
		src = v
	}
	if u, err := url.Parse(src); err == nil && u.Host != "" {
		src = u.Hostname()
	}
	return DatasetState{Age: age, LastResult: m.LastResult, Source: src}, ok
}
