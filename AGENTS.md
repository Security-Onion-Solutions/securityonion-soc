# Repository Guidelines

## Project Structure & Module Organization
- `cmd/sensoroni.go` bootstraps the console/agent process, reading `sensoroni.json`.
- `server/` holds HTTP handlers, stores, and server modules; `agent/` and `agent/modules/` manage scheduled jobs and collectors; `web/` contains websocket client/server helpers.
- `html/` serves the Vue/Vuetify UI, CSS, and JS (see `html/js/app.js` and `html/js/app.test.js`); `docs/api/` documents REST endpoints; `config/` defines config models and defaults.
- `scripts/` and `build.sh` provide automation; binaries and logs are written relative to the repo root unless overridden in config.

## Build, Test, and Development Commands
- Full pipeline: `./build.sh <version>` (defaults to `dev`) runs Jest unit tests, downloads Go deps, tidies modules, runs `go test ./...`, and builds a static binary embedding `BuildVersion`/`BuildTime` (set `REVKEYS` when packaging releases).
- Go tests only: `go test ./...` or target a package, e.g., `go test ./server -run TestName`.
- JS tests for the UI helpers: `jest test --config jest.config.js` from the repo root.
- Local run: `go run ./cmd/sensoroni.go -c sensoroni.json` to start the server/agent with the sample config; logs default to `logs/soc.log`.

## Coding Style & Naming Conventions
- Go: format with `gofmt -w .`; keep idiomatic Go naming (exported types/functions in PascalCase, locals in camelCase). Group related handlers/stores in their existing packages.
- JS in `html/js`: prefer existing patterns (ES modules, `const`/`let`, camelCase, top-level constants). Keep Vue/Vuetify templates consistent with current HTML structure.
- Config and JSON samples should remain minimized/compact and avoid trailing commas to match existing files.

## Testing Guidelines
- Place Go tests alongside code using `_test.go`; favor table-driven tests with `stretchr/testify` assertions already used in the repo.
- JS tests live next to their modules (e.g., `html/js/app.test.js`); mirror test names after the function/route being exercised.
- Add or update tests when changing handlers, module wiring, or UI logic; ensure both `go test ./...` and Jest runs succeed before opening a PR.

## Commit & Pull Request Guidelines
- Commits are short, imperative summaries (e.g., “Update grid member handler”, “Refactor tool results”) without trailing periods; group related changes per commit.
- PRs should include: a concise description, linked issues/tickets, test output for Go and JS, and UI screenshots/GIFs when altering `html/` assets.
- Call out config impacts (changes to `sensoroni.json` fields or default ports/paths) and any manual steps needed for deploys or licensing keys.
