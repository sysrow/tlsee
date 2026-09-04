# tlsee

A small, friendly TLS certificate inspector. `tlsee scan <target>` connects to
a host's TLS port, retrieves the presented certificate chain, and prints a
clear, aligned report: the certificate's SAN DNS names, issuer and subject, the
validity window with days remaining, whether the chain is trusted, whether the
hostname matches, the negotiated TLS version and cipher suite, and the host's
resolved A/AAAA DNS records.

It can scan many hosts at once (positional arguments and/or a `-f` host file)
into a summary table, run quietly for cron monitoring (`-q`), sweep a host's
ports to find every TLS endpoint (`tlsee sweep`), negotiate STARTTLS before the
handshake (`--starttls`), and connect to every resolved address to catch a
load-balancer backend serving a stale certificate (`--all-ips`).

Verification is intentionally skipped during the handshake so that any
certificate can be inspected, including expired, self-signed, or wrong-host
certificates. Trust and hostname matching are then evaluated and reported as
separate facts. It works against public hosts and internal targets alike
(`localhost:8443`, `127.0.0.1`, internal IPs).

By default it also performs a **SAN liveness check**: every DNS name in the
certificate's SAN list is resolved (A/AAAA) and TCP-probed on the scanned port,
so dead or stale entries are surfaced -- a name that no longer resolves, or
whose host is unreachable. Each reachable name is also checked to still point
at the scanned host (see [SAN liveness](#san-liveness)). This catches names
left on a certificate after the service behind them was decommissioned or
moved elsewhere.

Built with the Go standard library only. No third-party dependencies.

## Install

```bash
# Install the latest release with the Go toolchain
go install github.com/sysrow/tlsee@latest

# Or build from a clone
go build -o tlsee .
```

Prebuilt binaries for Linux and macOS (amd64, arm64) and Windows (amd64) are
attached to each [GitHub release](https://github.com/sysrow/tlsee/releases).

## Usage

```bash
# External host
tlsee scan example.com

# Local TLS server on a non-default port
tlsee scan localhost:8443

# Other accepted target forms
tlsee scan https://example.com
tlsee scan 127.0.0.1:8443
tlsee scan [::1]:8443

# JSON output
tlsee scan example.com --json

# Many hosts at once: a summary table
tlsee scan a.example.com b.example.com c.example.com
tlsee scan -f hosts.txt --table

# Quiet monitoring: print only problems, nothing when all healthy
tlsee scan -f hosts.txt -q

# STARTTLS (submission, IMAP, POP3, FTP, PostgreSQL, LDAP)
tlsee scan mail.example.com --port 587 --starttls smtp

# Compare the certificate served by every resolved address
tlsee scan example.com --all-ips

# Sweep a host's ports for TLS endpoints
tlsee sweep example.com
tlsee sweep example.com --ports 443,8443,9000-9100

# Version
tlsee version
```

## Scan flags

`tlsee scan <target>... [flags]`

| Flag          | Default | Description                                                  |
| ------------- | ------- | ------------------------------------------------------------ |
| `--port`      | `443`   | Port to use when the target omits one.                       |
| `--timeout`   | `10s`   | Dial and handshake timeout.                                  |
| `--sni`       | host    | SNI server name override (defaults to the target host).      |
| `--starttls`  | (none)  | Negotiate STARTTLS first: `smtp`, `imap`, `pop3`, `ftp`, `postgres`, `ldap`. |
| `--all-ips`   | `false` | Connect to every resolved A/AAAA address and compare certificates. |
| `--json`      | `false` | Emit JSON instead of text (a single report, or an array in batch mode). |
| `--color`     | `auto`  | Color output: `auto`, `always`, or `never`.                  |
| `--warn-days` | `30`    | Warn when the certificate expires within this many days.     |
| `--no-check`  | `false` | Skip the SAN checks (resolve, TCP-probe, and confirm each name still points at the host). |
| `--table`     | `false` | Always print the summary table, even for a single target.    |
| `-q`, `--quiet` | `false` | Print only problems; print nothing when everything is healthy. |
| `-f`, `--file`  | (none)  | Read targets from a file (one per line; `#` comments and blank lines ignored). |
| `--insecure`  | `false` | Always exit `0` even when the certificate has problems.      |

Color is emitted only when `--color=always`, or when `--color=auto` and stdout
is a terminal and `NO_COLOR` is unset. JSON output is never colored.

## Batch scanning

Pass more than one target, supply `-f/--file`, or set `--table`, and `tlsee`
scans every host concurrently and prints a summary table with one row per host:

| Column   | Meaning                                                            |
| -------- | ----------------------------------------------------------------- |
| `HOST`   | The target as given.                                              |
| `DAYS`   | Days remaining, or `ERR` when the host could not be scanned.      |
| `STATUS` | `VALID`, `EXPIRING`, `EXPIRED`, `UNTRUSTED`, `MISMATCH`, or `ERROR`. |
| `NOTE`   | Count of dead/stale SAN names, or the error text for failed hosts. |

Rows are sorted by urgency: hosts that failed to scan first, then the fewest
days remaining. `--json` emits a JSON array of reports, with `{host, error}`
objects for hosts that could not be scanned. The exit code is the worst per-host
code: `2` if any certificate has a problem, `1` if any host failed to scan,
otherwise `0`.

## Quiet monitoring

`-q`/`--quiet` makes `tlsee scan -f hosts.txt -q` a clean cron check: a healthy
certificate prints nothing and exits `0`; only problems are printed. In batch
mode only the non-healthy rows are shown (and the JSON array is filtered the same
way); the exit code still reflects every host.

## STARTTLS

`--starttls PROTO` upgrades a plaintext connection to TLS before the handshake,
so certificates can be inspected on submission, mail, and other protocols that
do not use implicit TLS:

| Protocol   | Typical ports | Mechanism                          |
| ---------- | ------------- | ---------------------------------- |
| `smtp`     | 25, 587       | `STARTTLS`                         |
| `imap`     | 143           | `a1 STARTTLS`                      |
| `pop3`     | 110           | `STLS`                             |
| `ftp`      | 21            | `AUTH TLS`                         |
| `postgres` | 5432          | SSLRequest                         |
| `ldap`     | 389           | StartTLS extended request (best effort) |

## Per-address certificates

`--all-ips` connects to every resolved A/AAAA address of the host (presenting
the host name as SNI) and reports each address's certificate. If the reachable
addresses do not all present the same leaf, a prominent note is shown -- this
catches a load-balancer backend serving a stale or mismatched certificate.

## Sweep

`tlsee sweep <host>` probes many ports of a single host for TLS and prints a
table sorted by port (`PORT`, `PROTO`, `CERT`, `STATUS`). By default it scans a
curated list of well-known TLS and STARTTLS ports (HTTPS, IMAPS, POP3S, SMTPS,
LDAPS, FTPS, DoT, AMQPS, IRCS, MQTTS, and the STARTTLS upgrades for SMTP, IMAP,
POP3, LDAP, FTP, and PostgreSQL).

| Flag        | Default | Description                                                     |
| ----------- | ------- | --------------------------------------------------------------- |
| `--ports`   | curated | Comma list and/or ranges, e.g. `443,8443,9000-9100`. Ports not in the curated map attempt direct TLS. |
| `--full`    | `false` | Scan all ports `1-65535`. Slow.                                 |
| `--timeout` | `3s`    | Per-port probe timeout, kept short so closed ports fail fast.   |
| `--json`    | `false` | Emit JSON instead of text.                                      |
| `--color`   | `auto`  | Color output: `auto`, `always`, or `never`.                     |

## SAN liveness

For each DNS name in the certificate's SAN list, `tlsee` reports one of:

| State                        | Meaning                                                        |
| ---------------------------- | ------------------------------------------------------------- |
| `open`                       | Resolves to the scanned host and every address accepts a connection on the port. |
| `partial`                    | Resolves to the scanned host and some addresses are reachable (e.g. IPv4 up, IPv6 down). |
| `open (other IP, same cert)` | Resolves to a different address, but that endpoint serves the same certificate (a CDN or second front-end). |
| `elsewhere (other cert)`     | Resolves to a different address serving a different certificate: the name has moved away and is stale on this certificate. |
| `elsewhere (unverified)`     | Resolves to a different address, but the confirming handshake failed, so it is unclear which. |
| `unreachable`                | Resolves but no address accepts a connection.                 |
| `NO DNS (stale?)`            | Does not resolve at all -- likely a stale name on the cert.   |
| `wildcard (not probed)`      | A `*.` name, which cannot be resolved directly.               |

Each name is also checked against the scanned host itself. When a name resolves
to addresses the host does not have, `tlsee` opens one further handshake to that
address (presenting the name as SNI) and compares the certificate: the same leaf
means a second front-end, a different leaf means the name has moved to another
host and is stale on this certificate. Names that have moved are counted in the
status headline as `N SANS ELSEWHERE` and shown in magenta. Like dead SANs they
are advisory and do **not** change the exit code. The comparison costs no extra
connection for names that still point at the scanned host.

Names that are `unreachable` or `NO DNS` are counted as **dead SANs** and shown
in the status headline. Each probe uses a short timeout (capped at 3s) and runs
concurrently. Dead SANs are reported but do **not** change the exit code, which
reflects the certificate's own validity. Use `--no-check` to skip the check for
a faster scan.

## Hygiene warnings

A scan also reports informational hardening warnings derived from the
connection: a weak TLS version (below 1.2), a weak signature algorithm (SHA-1 or
MD5), a weak RSA key (under 2048 bits), and a weak negotiated cipher suite. These
are advisory only: they do **not** change the exit code or the status headline.

## Exit codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | Healthy: trusted chain, hostname matches, valid, and not expiring soon. Also when help is explicitly requested (`help`, `-h`, `--help`), which is written to stdout. |
| `1`  | Runtime error: bad flags, missing target, unknown command, or connection failure. |
| `2`  | Usage shown for no arguments, or a certificate problem: expired, not yet valid, untrusted, hostname mismatch, or expiring within `--warn-days`. A certificate problem is suppressed by `--insecure`. |

With `--insecure`, the certificate is still retrieved and printed; only the
exit code is forced to `0`.

In batch mode the exit code is the worst per-host code: `2` if any certificate
has a problem, `1` if any host failed to scan, otherwise `0`. The `sweep`
subcommand always exits `0` on a successful run (port findings are reported in
the table, not the exit code) and `1` only on a usage or runtime error.
