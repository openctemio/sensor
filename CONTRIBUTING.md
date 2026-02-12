# Contributing to OpenCTEM Agent

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone: `git clone https://github.com/YOUR_USERNAME/agent.git`
3. Install Go 1.25+
4. Build: `go build -o agent .`
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

## License

By contributing, you agree to license your contributions under Apache 2.0.
