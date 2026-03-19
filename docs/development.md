# Development Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25+ | Build and test (module uses go 1.25.6) |
| PostgreSQL | 15+ | Development and testing database |
| Docker | any recent | Container builds and local images |
| golangci-lint | latest | Static analysis and linting |

## Building from Source

### Binary

```bash
go build -o noctis ./cmd/noctis/
```

### Using the Makefile

```bash
make build           # outputs to bin/noctis
make clean           # removes bin/
```

The Makefile injects version information at link time:

```
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
```

The module path is `github.com/Zyrakk/noctis`. Pass `VERSION` to override the default (`dev`):

```bash
make build VERSION=v0.3.1
```

## Running Tests

```bash
make test            # go test -race -count=1 ./...
make lint            # golangci-lint run ./...
```

Tests run with the race detector enabled (`-race`) and cache disabled (`-count=1`). The codebase has approximately 3,504 lines of test code across 14 packages.

## Docker Build

### Using the Makefile

```bash
make docker-build TAG=latest
```

This builds `ghcr.io/zyrakk/noctis:latest`. Override the image name with the `IMAGE` variable:

```bash
make docker-build IMAGE=myrepo/noctis TAG=v0.3.1
```

### Directly with Docker

```bash
docker build --build-arg VERSION=dev -t ghcr.io/zyrakk/noctis:dev .
```

### Build stages

The Dockerfile uses a two-stage build:

1. **Builder** — `golang:1.25-alpine`: installs git and CA certificates, downloads modules, compiles with `CGO_ENABLED=0`.
2. **Runtime** — `gcr.io/distroless/static-debian12:nonroot`: copies only the compiled binary, migration files, and prompt templates.

Artifacts copied into the runtime image:

- `/noctis` — compiled binary
- `/migrations/` — PostgreSQL DDL files
- `/prompts/` — LLM prompt templates

The container runs as the `nonroot` user. Default entrypoint:

```
/noctis serve --config /etc/noctis/config.yaml
```

## Project Structure

```
cmd/noctis/          — CLI entry point and commands
  main.go            — root command, version flag
  serve.go           — noctis serve  (main daemon)
  search.go          — noctis search + noctis stats
  source.go          — noctis source (list/approve/pause/remove)
  config_cmd.go      — noctis config validate
  telegram_auth.go   — noctis telegram-auth (--qr / --sms)

internal/
  analyzer/          — LLM-powered classification and enrichment
  archive/           — raw_content persistence layer (insert, search, stats)
  collector/         — Telegram, Paste, Forum, Web collectors + Tor transport
  config/            — YAML parsing, env var substitution, validation
  database/          — PostgreSQL connection pool and migration runner
  discovery/         — Source discovery engine (URL extraction, classification)
  dispatcher/        — Prometheus metrics recording
  health/            — HTTP health checks (/healthz, /readyz) + QR auth server
  ingest/            — Archive-everything pipeline + background workers
  llm/               — OpenAI-compatible LLM client interface + implementation
  matcher/           — Keyword/regex pattern matching engine
  models/            — Finding, IOC, Severity, Category, ActorProfile, Canary
  pipeline/          — Legacy pipeline (deprecated by ingest/)

migrations/          — PostgreSQL DDL (001_init, 002_graph, 003_pivot)
prompts/             — LLM prompt templates (classify, extract_iocs, severity, summarize, stylometry)
deploy/              — Kubernetes manifests (namespace, secrets, postgres, configmap, noctis)
testdata/            — Config test fixtures (minimal_config.yaml, valid_config.yaml)
```

## Extension Points

### Adding a New Collector

1. Create `internal/collector/mytype.go` implementing the `Collector` interface (`Name` and `Start` methods).
2. Add the config struct to `internal/config/config.go` under `SourcesConfig`.
3. Register it in `cmd/noctis/serve.go`: add a config check block that instantiates `collector.NewMyCollector()`.
4. Add the corresponding config section to `deploy/configmap.yaml`.
5. Write tests in `internal/collector/mytype_test.go`.

### Adding a New Dispatch Sink

1. Create a handler in `internal/dispatcher/`.
2. Wire it into the `alertFn` callback in `cmd/noctis/serve.go`.
3. Add the config struct to `internal/config/config.go` under `DispatchConfig`.

### Adding a New LLM Prompt

1. Create `prompts/newprompt.tmpl` using Go `text/template` syntax.
2. Add a response struct and method to `internal/analyzer/analyzer.go`, following the `Classify` / `ExtractIOCs` pattern.
3. Call the new method from the ingest pipeline or background workers as needed.

## CI/CD Pipeline

The workflow lives in `.github/workflows/build.yaml`.

| Property | Value |
|----------|-------|
| Trigger | Push to `main`, or semver tags (`v*`) |
| Architectures | `linux/amd64`, `linux/arm64` (QEMU + buildx) |
| Registry | `ghcr.io/zyrakk/noctis` |
| Auth | `GITHUB_TOKEN` (built-in, no extra secret needed) |
| Layer cache | GitHub Actions cache (`type=gha`) |

### Image tags produced

| Event | Tag(s) |
|-------|--------|
| Push to `main` | `latest` |
| Semver tag (e.g. `v1.2.3`) | `1.2.3`, `1.2` |

The `VERSION` build argument is set from `${{ github.ref_name }}` so the binary embeds the tag name at compile time.

## Codebase at a Glance

| Metric | Value |
|--------|-------|
| Go source lines | ~9,353 |
| Test lines | ~3,504 |
| Packages | 14 |
| Commits | 52 |
