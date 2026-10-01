#!/usr/bin/env bash
# =============================================================================
# sensor-rename.sh — the mechanical half of the agent → sensor rename of the
# sensor binary (RFC-023 §9.5). Re-runnable: on a tree that is already renamed
# it is a no-op, so a branch opened before the rename catches up by rebasing
# and running it.
#
# What it does, in order:
#   1. the SDK's codemod (sdk-go cmd/sensor-migrate) for uses of SDK
#      identifiers, in the default and the platform build — a no-op once the
#      module is on the sensor SDK;
#   2. type-aware rename of this module's own identifiers, import aliases and
#      comments, in both builds (scripts/rename/sensorrename);
#   3. git mv of .go files with "agent" in their name;
#   4. goimports on every changed file, then build + vet of both builds.
#
# What it does NOT do: string literals and struct tags (environment variables,
# flags, YAML keys, the protocol v1 wire), Dockerfiles, CI templates, docs and
# the module path (now github.com/openctemio/sensor). Those move in reviewed,
# hand-written commits, each with its upgrade path.
#
# Usage:  scripts/rename/sensor-rename.sh            (from the repo root)
#   SENSOR_MIGRATE  command to run the codemod (default: go run of the SDK
#                   version in go.mod)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export GOWORK=off

echo "sensor-rename: SDK identifiers (sensor-migrate)…"
sdk_version=$(go list -m -f '{{.Version}}' github.com/openctemio/sdk-go)
${SENSOR_MIGRATE:-go run "github.com/openctemio/sdk-go/cmd/sensor-migrate@$sdk_version"} -tags platform -sdk-version none

echo "sensor-rename: this module's identifiers, comments and files…"
go run ./scripts/rename/sensorrename -dir "$ROOT"

echo "sensor-rename: goimports…"
changed=$( (git diff --name-only --diff-filter=AMR -- '*.go'; git diff --cached --name-only --diff-filter=AMR -- '*.go'; git ls-files --others --exclude-standard -- '*.go') | sort -u | grep -v '^$' || true)
if [ -n "$changed" ]; then
  # shellcheck disable=SC2086
  if command -v goimports >/dev/null; then goimports -w $changed; else go run golang.org/x/tools/cmd/goimports -w $changed; fi
fi

echo "sensor-rename: build + vet gate (default and platform builds)…"
go build ./... && go build -tags platform ./...
go vet ./... && go vet -tags platform ./...
echo "sensor-rename: done."
