# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tlsee` is a CLI TLS certificate inspector built with the Go standard library
only — **no third-party dependencies**, and that is a deliberate constraint.
`tlsee scan <target>` prints a full certificate report; batch mode renders a
summary table; `tlsee sweep <host>` probes many ports for TLS endpoints.

## Commands

```bash
go build -o tlsee .                 # build
go test -race -count=1 ./...        # full test suite (matches CI)
go test -race -run TestName ./internal/tlsscan/   # single test
gofmt -l .                          # CI fails on any unformatted file
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

CI (`.github/workflows/ci.yml`) runs exactly: gofmt check, go vet, staticcheck,
build, `go test -race -count=1`, govulncheck. All must pass.

Tests never touch the external network: TLS endpoints are simulated with
`httptest.NewTLSServer` and `net.Listen` on `127.0.0.1:0`, including fake
STARTTLS servers. Keep new tests fully local and deterministic.

## Architecture

Three-layer design with strict responsibilities; data flows one way:

```
main.go  →  internal/cli  →  internal/tlsscan  →  internal/report
(exit)      (flags, dispatch,   (scan engine,       (text/JSON rendering
             exit codes)         produces Report)     of a Report)
```

- **`internal/cli`** — flag parsing, subcommand dispatch (`scan`, `sweep`,
  `version`, `help`), batch orchestration (bounded worker pool,
  `batchConcurrency = 16`), signal-wired context (Ctrl-C cancels in-flight
  dials cooperatively), and exit-code computation. This is the *only* layer
  (besides main) allowed to touch os-level details (terminal detection,
  env vars, files); everything below takes injected writers and contexts.
  `Run` never calls `os.Exit` — it returns the code; main exits.
- **`internal/tlsscan`** — the scanning engine. `Scan` handshakes with
  verification intentionally disabled so any certificate (expired,
  self-signed, wrong-host) can be inspected; trust and hostname match are then
  evaluated separately and reported as independent facts on the `Report`.
  `dial.go` holds plaintext dialing and all STARTTLS negotiations
  (smtp/imap/pop3/ftp/postgres/ldap); `sweep.go` holds the port-sweep engine
  and the curated port→protocol map.
- **`internal/report`** — renders a `tlsscan.Report` as text or JSON.
  Rendering is deterministic and **never consults the wall clock**: it relies
  entirely on precomputed report fields (`DaysRemaining`, `Expired`,
  `WarnDays`, ...). Keep it that way so render tests stay exact.

## Load-bearing invariants

- **Exit codes are a contract** (used by cron monitoring): `0` healthy,
  `1` runtime/connection error, `2` certificate problem or no-args usage.
  In batch mode the worst per-host code wins. `--insecure` suppresses only
  certificate problems, never connection failures. `Report.Healthy()` is the
  single source of truth shared by the exit code, the `--quiet` row filter,
  and the status headline — don't fork that logic.
- **Dead SANs and hygiene warnings are advisory only**: they appear in output
  but must never change the exit code or turn the headline red.
- **README, `writeUsage`, and per-subcommand usage text document the same
  behavior** — when changing flags or exit semantics, update all of them.
- **Version reporting**: releases inject the tag via
  `-ldflags "-X 'github.com/sysrow/tlsee/internal/cli.version=vX.Y.Z'"`
  (see `.github/workflows/release.yml`); `go install`ed binaries fall back to
  `debug.ReadBuildInfo`. Keep that ldflags path stable.
- Flag parsing supports interspersed positionals and a top-level `--`
  terminator via `parseInterspersed` (stdlib `flag` alone can't do this);
  both subcommands share it.
