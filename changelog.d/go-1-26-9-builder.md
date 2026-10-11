### Security: sensor binaries are built with Go 1.26.9

- The five image builders were pinned to a Go 1.26.8 image, so released sensor binaries lacked the Go 1.26.9 `net/http` fixes that govulncheck reports as reachable from sensor code (GO-2026-6611, GO-2026-6612, GO-2026-6613, GO-2026-6617 and others). The builders now use `golang:1.26.9-alpine` (pinned by digest) and `go.mod` names `toolchain go1.26.9`, so local builds and govulncheck use the patched standard library too.
