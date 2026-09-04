# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tlsee` is a CLI TLS certificate inspector built with the Go standard library
only: **no third-party dependencies**, and that is a deliberate constraint.
`tlsee scan <target>` prints a full certificate report; batch mode renders a
summary table; `tlsee sweep <host>` probes many ports for TLS endpoints.

## Commands

```bash
go build -o tlsee .                 # build
go test -race -count=1 ./...        # full test suite (matches CI)
go test -race -run TestName ./tlsscan/            # single test
gofmt -l .                          # CI fails on any unformatted file
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

CI (`.github/workflows/ci.yml`) runs exactly: gofmt check, go vet, staticcheck,
build, `go test -race -count=1`, govulncheck. All must pass.

The `go` directive in `go.mod` (`go 1.25.11`) is a deliberate patch-level pin:
govulncheck in CI also scans the standard library, so the directive was bumped
to a release carrying the stdlib fixes (the toolchain auto-downloads it). Move
it forward when govulncheck reports a stdlib finding; never lower it.

Releases are cut by pushing a `v*` tag; `.github/workflows/release.yml` builds
five targets (linux/darwin amd64+arm64, windows amd64) with `CGO_ENABLED=0
-trimpath` and publishes them with checksums. Commit subjects follow
`type(scope): summary` (`feat(tlsscan): ...`, `feat(report): ...`, `docs: ...`).

## Tests

Tests never touch the external network: TLS endpoints are simulated with
`httptest.NewTLSServer` and `net.Listen` on `127.0.0.1:0`, including scripted
plaintext servers for STARTTLS (`runScriptedServer` in `tlsscan/core_test.go`)
and self-signed leaf servers for SAN ownership (`newSelfSignedCert`,
`runLeafServer`). DNS is faked by swapping the package-level `lookupIP` var
(restore it in `t.Cleanup`; such tests cannot use `t.Parallel`), which is why
it is a var. Tests live in the same package as the code they test (white-box)
so unexported helpers stay directly testable. Keep new tests fully local and
deterministic.

- CLI end-to-end tests (`internal/cli/run_test.go`) drive `Run` with
  `bytes.Buffer` writers. `tlsTestServerTarget` yields an untrusted self-signed
  target (exit 2) and `closedTarget` a refused one (exit 1). Always pass
  `--no-check`: the httptest certificate carries `example.com` SANs, and the
  liveness check would resolve them over real DNS. Pass `--color never` as
  well; `resolveColor` only detects a terminal on an `*os.File`, so a buffer
  never gets color under `auto` anyway.
- Render tests build fixed `Report` values (`fixedReport`, `batchRows`,
  `sweepFixture`) and assert exact text, which works only because rendering
  never reads the clock. Color assertions strip escapes with `stripANSI`.

## Design docs

Larger features start as a dated design spec in `docs/superpowers/specs/` and
an implementation plan in `docs/superpowers/plans/`. Read the spec for the
feature you are touching before changing its behavior; the stale-SAN spec
explains the ownership states and why the exit code stays untouched. When a
feature ships, update the spec's `Status:` line and tick the plan's steps so
the docs do not claim unimplemented work.

## Architecture

Three-layer design with strict responsibilities; data flows one way:

```
main.go   ->   internal/cli        ->   tlsscan             ->   internal/report
(exit)         (flags, dispatch,        (scan engine,            (text/JSON rendering
                exit codes)              produces Report)         of a Report)
```

- **`tlsscan`** is the scanning engine and the **only public package**: it lives
  outside `internal/` on purpose so the scanner is importable as a library.
  Treat its exported names (`Scan`, `Sweep`, `Options`, `Report`, `CertInfo`,
  `ParsePortSpec`, ...) and its JSON field tags as a compatibility surface;
  renaming one is a breaking change for both importers and `--json` consumers.
  `DeadSANs`, `SANsElsewhere`, and `IPCertsDiffer` are serialized without
  `omitempty` on purpose, so a consumer can tell "checked, nothing found" from
  "check not run"; `SANsNotProbed` (names beyond the `maxSANChecks = 100` cap,
  or skipped on cancellation) is `omitempty`.
  `Scan` handshakes with verification intentionally disabled so any certificate
  (expired, self-signed, wrong-host) can be inspected; trust and hostname match
  are then evaluated separately and reported as independent facts on the
  `Report`. `dial.go` holds plaintext dialing, the TLS handshake, and all
  STARTTLS negotiations (smtp/imap/pop3/ftp/postgres/ldap); `sweep.go` holds the
  port-sweep engine and the curated port-to-protocol map.
- **`internal/cli`** holds flag parsing, subcommand dispatch (`scan`, `sweep`,
  `version`, `help`), batch orchestration (bounded worker pool,
  `batchConcurrency = 16`), signal-wired context (Ctrl-C cancels in-flight
  dials cooperatively), and exit-code computation. This is the *only* layer
  (besides main) allowed to touch os-level details (terminal detection,
  env vars, files); everything below takes injected writers and contexts.
  `Run` never calls `os.Exit`; it returns the code and main exits.
- **`internal/report`** renders a `tlsscan.Report` as text or JSON.
  Rendering is deterministic and **never consults the wall clock**: it relies
  entirely on precomputed report fields (`DaysRemaining`, `Expired`,
  `WarnDays`, ...). Keep it that way so render tests stay exact. The sweep
  expiry threshold (`sweepWarnDays = 30`) lives here because `sweep` has no
  `--warn-days` flag; keep it equal to scan's default.

## Load-bearing invariants

- **Exit codes are a contract** (used by cron monitoring): `0` healthy,
  `1` runtime/connection error, `2` certificate problem or no-args usage.
  In batch mode the worst per-host code wins, and `exitCertProb` outranks
  `exitError`. `--insecure` suppresses only certificate problems, never
  connection failures. `Report.Healthy()` is the single source of truth shared
  by the exit code, the `--quiet` row filter, and the status headline; do not
  fork that logic. `sweep` never returns `2`: a complete run exits `0` with
  the findings in the table, and `1` on a usage or runtime error or when the
  sweep was interrupted before every port was probed
  (`SweepResult.PortsNotProbed > 0`, decided in `writeSweepResult`).
- **Dead SANs, moved SANs, and hygiene warnings are advisory only**: they appear
  in output but must never change the exit code or turn the headline red.
  `sanAdvisory` in `internal/report` is where the SAN notes are composed for the
  headline; it appends without touching the color the real problems set.
- **Magenta is reserved for one condition**: a SAN name that no longer points at
  the scanned host. Keeping it exclusive is what makes a moved name distinct
  from a healthy one (green) and a dead one (red). Do not reuse it elsewhere.
- **SAN ownership classification is free unless something looks wrong**: address
  sets are compared from data the scan already has, and a confirming handshake
  runs only for a name whose addresses are disjoint from the host's. Keep that
  ordering: reversing it puts a handshake on every name of every certificate.
- **`Scan` runs post-handshake enrichment on the caller's `ctx`, not on
  `scanCtx`.** `scanCtx` carries the single `--timeout` budget for
  connect + STARTTLS + handshake and is already depleted by then; reusing it for
  DNS/SAN/per-IP probing would trip their cancellation paths and report
  un-probed names as *dead*. Those steps carry their own capped per-probe
  timeouts (`maxProbeTimeout`).
- **Bounded worker pools must not leave zero-valued slots.** Four places share
  the pattern (`scanTargets`, `checkSANs`, `probeIPCerts`, `Sweep`): dispatch
  via `select` on the semaphore *and* `ctx.Done()`, and on cancellation either
  fill the remaining slots with an explicit error or truncate, but truncate
  **only after `wg.Wait()`**, since in-flight goroutines hold the slice header.
  A zero-valued row renders as a dead SAN, a bogus port 0, or panics the batch
  path (which requires exactly one of `Report`/`Err` to be set). `Sweep` also
  drops probes cut short in flight (`probePort` flags them via its second
  result) and counts both kinds in `PortsNotProbed`: a canceled dial fails
  exactly like a refused one, so it must never be reported as a closed port.
- **Weak TLS versions and insecure cipher suites are enabled on purpose** in
  `tlsHandshake` (`MinVersion: tls.VersionTLS10`, all suite IDs). Go's secure
  defaults would make the weak-version/weak-cipher hygiene warnings unreachable.
  Do not "harden" this: it is an inspector, not a client.
- **Certificate- and target-derived strings are sanitized on the text and table
  paths** (`sanitize`/`sanitizeJoin` in `internal/report`) to strip ANSI and
  other control bytes from attacker-influenced output; a tab becomes a space so
  it cannot forge a tabwriter column. JSON paths are deliberately left alone
  (`encoding/json` already escapes control characters).
- **The batch table is laid out monochrome first, then colorized.** tabwriter
  measures bytes, so coloring before layout would count invisible escape bytes
  and misalign columns. `colorizeStatusCell` recolors the already-padded status
  word in place.
- **`--quiet` routes even a single target through the batch path**, so
  `scan host --quiet --json` emits a JSON *array* while `scan host --json` emits
  a single object. This shape difference is documented in `writeUsage`; keep it
  documented if it changes.
- **README, `writeUsage`, and per-subcommand usage text document the same
  behavior**: when changing flags or exit semantics, update all of them.
- **Version reporting**: releases inject the tag via
  `-ldflags "-X 'github.com/sysrow/tlsee/internal/cli.version=vX.Y.Z'"`
  (see `.github/workflows/release.yml`); `go install`ed binaries fall back to
  `debug.ReadBuildInfo`. Keep that ldflags path stable.
- Flag parsing supports interspersed positionals and a top-level `--`
  terminator via `parseInterspersed` (stdlib `flag` alone can't do this);
  both subcommands share it. Explicitly requested help goes to **stdout** and
  exits `0`; usage shown because of an error goes to stderr.
