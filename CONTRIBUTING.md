# Contributing to the OpenCTEM Sensor

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone: `git clone https://github.com/YOUR_USERNAME/agent.git`
3. Install Go 1.26+
4. Build: `go build -o openctemio-sensor .`
5. Create branch: `git checkout -b feature/your-feature`
6. Make changes
7. Test: `go test ./...`
8. Commit and push
9. Open a Pull Request

## Code Style

- Use `gofmt` for formatting
- Follow Go best practices
- Write meaningful commit messages
- Add tests for new features

## Adding a New Tool

1. Create executor in `internal/executor/`
2. Register in `internal/executor/router.go`
3. Add CI templates in `ci/github/` and `ci/gitlab/`
4. Update README with tool documentation

## Releasing

Versioning follows the project rule (openctemio/openctem RFC-037): the version is the `vX.Y.Z` tag on `main`, proposed from the conventional commits since the last tag. Before 1.0.0, a breaking change (`type!:` or `BREAKING CHANGE:`) or a `feat` bumps the minor; anything else bumps the patch. A build that is not a release reports `<highest tag>-dev+<sha>` (`make`), never `git describe`.

1. Every PR that changes behaviour adds one file `changelog.d/<short-slug>.md` (see [`changelog.d/README.md`](changelog.d/README.md)); never edit the `[Unreleased]` section of `CHANGELOG.md`.
2. **Actions › Release Prepare › Run.** Start with `dry_run` (the default) to see the proposed version and changelog preview. Run it again with `dry_run` off to open `release/vX.Y.Z → main`: the `changelog.d/` fragments are folded into `CHANGELOG.md` as `[vX.Y.Z]`. Fill `version` to override the proposal.
3. Merge the release PR. **Release Tag** tags the merge commit, and the tag runs Release (GoReleaser) and Docker Publish. It then bumps `sensor.latest` in openctemio/openctem's `versions.yaml`.

Do not tag by hand. Without the `RELEASE_TOKEN` secret (a fine-grained PAT with Contents, Pull requests and Workflows read/write), you open the PR yourself from the link in the run summary, and the cross-repository PR is skipped.

## License

By contributing, you agree to license your contributions under Apache 2.0.
