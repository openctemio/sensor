#!/bin/sh
# Build one ProjectDiscovery tool from source with the Go toolchain of the
# build stage, so the binary carries that toolchain's standard library (the
# prebuilt release binaries embed the Go version the upstream release used,
# which lags the stdlib fixes), and pin the Go modules whose fixed version
# upstream's go.mod has not picked up yet.
#
# usage: build-pd-tool.sh <tool> <version> <commit-sha> <out-dir>
#
# The tag is checked against the pinned commit, so a moved tag fails the
# build. A module is raised only when the tool depends on it and is older
# than the floor below (go get never lowers a version); go.sum comes from the
# module proxy, verified by the Go checksum database. Drop a floor once the
# pinned release's go.mod carries it.
set -eu

tool="$1"; version="$2"; commit="$3"; out="$4"

src="$(mktemp -d)"
git clone --quiet --depth 1 --branch "v${version}" "https://github.com/projectdiscovery/${tool}.git" "${src}"
cd "${src}"
[ "$(git rev-parse HEAD)" = "${commit}" ] || { echo "${tool} v${version}: tag does not point at ${commit}" >&2; exit 1; }

for floor in \
    github.com/klauspost/compress@v1.18.7 \
    golang.org/x/net@v0.60.0 \
    github.com/go-jose/go-jose/v4@v4.1.6 \
    github.com/getkin/kin-openapi@v0.149.0 \
    github.com/jackc/pgx/v5@v5.9.0 \
    github.com/go-git/go-git/v5@v5.19.2 \
    google.golang.org/grpc@v1.83.2; do
    mod="${floor%@*}"
    if go list -m "${mod}" >/dev/null 2>&1; then
        go get "${floor}"
    fi
done

# naabu loads libpcap at run time (no cgo), which makes the Go linker emit a
# dynamically linked executable whose interpreter is the build host's libc
# (musl on the alpine build stage). The runtime images are glibc (debian,
# distroless), so name the glibc loader; it is ignored for the static tools.
case "$(go env GOARCH)" in
    amd64) loader=/lib64/ld-linux-x86-64.so.2 ;;
    arm64) loader=/lib/ld-linux-aarch64.so.1 ;;
    *) echo "unsupported GOARCH $(go env GOARCH)" >&2; exit 1 ;;
esac

# -mod=mod fills in the go.sum entries the raised modules pull in.
CGO_ENABLED=0 go build -mod=mod -trimpath -ldflags="-s -w -I ${loader}" -o "${out}/${tool}" "./cmd/${tool}"
go version -m "${out}/${tool}" | sed -n '1,2p'
