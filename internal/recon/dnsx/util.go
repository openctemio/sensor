package dnsx

import (
	"os"
)

// createTempFile creates a temporary file with the given pattern.
func createTempFile(pattern string) (*os.File, error) {
	return os.CreateTemp("", pattern)
}

// removeTempFile removes a temporary file.
func removeTempFile(path string) {
	_ = os.Remove(path)
}
