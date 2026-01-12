# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Onion Console (SOC) is a Go/Vue application that serves as the primary UI for Security Onion, managing security sensors and providing threat analysis capabilities including an AI-powered assistant. Licensed under Elastic License 2.0.

## Build & Test Commands

```bash
# Full build pipeline (Jest + Go tests + binary)
./build.sh [version]    # defaults to 'dev'

# Individual test commands
go test ./...                              # All Go tests
go test ./server -run TestName             # Specific test
jest test --config jest.config.js          # JS tests

# Local development
go run ./cmd/sensoroni.go -c sensoroni.json

# Modern UI Build
cd ui && npm install && npm run build
```

## Architecture

**Dual-Process Model**: Server (HTTP/WebSocket) and Agent (background jobs) run as goroutines from single `cmd/sensoroni.go` entry point.

**Module System**: All functionality extends the `Module` interface (`module/module.go`):
- Server modules: `server/modules/` (elastic, assistant, kratos, salt, etc.)
- Agent modules: `agent/modules/` (analyze, export, importer, etc.)
- Modules enabled/disabled via `sensoroni.json` configuration

**Key Directories**:
- `server/` - HTTP handlers (`*handler.go`) and datastore interfaces
- `agent/` - Job scheduling and background processing
- `model/` - Shared data models
- `html/js/routes/` - Vue route components
- `web/` - HTTP/WebSocket utilities and middleware

**Handler Pattern**: Each API endpoint has a handler that registers routes via `Register*Routes(server, router, path)`. Handlers use datastore interfaces injected into the `Server` struct.

**RBAC**: Authorization via `CheckAuthorized(ctx, operation, target)` with permissions defined in `rbac/permissions/`.

**Modern UI**: New interface located in `ui/` built with Vue 3 and Vite.
- Source: `ui/src/`
- Build Output: `html/modern/` (accessed via `/modern/`)
- Tech Stack: Vue 3, Vite, TailwindCSS, Lucide Icons
- Coexistence: Runs alongside legacy global-variable Vue app in `html/js/`
- Composables: `ui/src/composables/` for shared reactive state

**Modern UI Composables** (use these instead of reimplementing):
- `useUsers()` - Fetches and caches users globally. Provides `getUserEmail(id)` and `getUserName(id)` to convert user IDs to display names. Auto-fetches on first use.
- `useFormatters()` - Date/time formatting utilities. Provides `formatDate(str)` for locale date/time, `formatUptime(seconds)` for "2d 5h" format, `formatRelativeTime(date)` for "5 minutes ago", and `formatDateForApi(date)` for API query format.
- `useStatusStyles()` - Status/severity styling utilities. Provides `getSeverityStyles(level)` for critical/high/medium/low badges, `getStatusStyles(status)` for open/closed states, `getJobStatusStyles(status)` for job states, `getNodeStatusColor(status)` for node health, and `getUsageColor(pct)`/`getProgressColor(pct)` for resource usage thresholds.

## Coding Conventions

- Go: `gofmt -w .`, PascalCase exports, camelCase locals
- JS: ES modules, `const`/`let`, camelCase, follow existing Vue/Vuetify patterns
- Tests: Table-driven with `stretchr/testify`, co-located `*_test.go` and `*.test.js` files

## Code Reuse (Modern UI)

**Before writing new code in `ui/src/`, always:**
1. Check `ui/src/composables/` for existing utilities (users, formatters, etc.)
2. Look at similar modules (Grid, Jobs, Cases) for patterns already solved
3. If implementing something reusable (data fetching, formatting, lookups), create a composable

**When to create a new composable:**
- The same logic would be needed in 2+ components
- It involves shared state (caching, global data)
- It's a utility function (formatting, validation, API helpers)

**Composable location:** `ui/src/composables/use{Name}.ts`

Never duplicate logic like user ID lookups, date formatting, or API fetch patterns - extract to composables instead.

## Git Workflow

- Main branch: `2.4/main`
- Commits: Short imperative summaries without trailing periods
- PRs require: passing tests, linked issues, UI screenshots for `html/` changes
