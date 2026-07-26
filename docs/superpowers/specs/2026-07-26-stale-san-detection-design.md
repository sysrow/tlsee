# Stale SAN detection: names that no longer point at the scanned host

Date: 2026-07-26
Status: approved, not yet implemented

## Problem

The SAN liveness check answers "does this name resolve and is something
listening on the port?" It does not answer "does this name still point at the
host I just scanned?"

A certificate routinely outlives the routing of the names on it. A service moves
to a new host, DNS follows, but the old host keeps serving a certificate that
still lists the moved name. Today `tlsee` renders that name green as `open`,
because the new host does answer on the port. The operator gets no signal that
three of the four names on the certificate they are about to renew have nothing
to do with that host any more.

Concretely: host `A` at `192.0.2.10` serves a certificate whose SAN list
includes `moved.example.com`, but that name now resolves to `198.51.100.20`,
a different host. `tlsee scan A` reports `moved.example.com ... open`.

## Goal

Classify every reachable SAN name as still pointing at the scanned host or as
having moved elsewhere, and surface the difference in the report.

## Non-goals

- Changing the exit code. Exit codes stay a contract: `0` healthy, `1` runtime
  error, `2` certificate problem. A moved SAN name is advisory, like a dead SAN.
- Changing `Report.Healthy()`, the `--quiet` row filter, or `--insecure`.
- Adding a flag. The check rides along with the existing SAN liveness check and
  is disabled by the existing `--no-check`.

## Approach

Hybrid, in two stages, so the common case costs nothing:

1. **Address comparison (free).** The scan already knows the host's own
   addresses (`Report.ResolvedIPs`) and each SAN name's addresses (collected by
   the liveness probe). A non-empty intersection means the name still points at
   the scanned host. Done — no network call.
2. **Certificate confirmation (only when addresses disagree).** For a name whose
   addresses are disjoint from the host's, open one TLS handshake to its first
   reachable address with SNI set to that name, and compare the leaf SHA-256
   with the scanned host's leaf. This distinguishes a CDN or second front-end
   serving our certificate from a name that genuinely moved away.

Address comparison alone would flag every CDN-fronted name as moved.
Certificate comparison alone would pay for a full handshake per name even when
every name is correct. The hybrid pays only on names that already look
suspicious.

Classification runs only for names that are `Resolved && Reachable`. A name that
is already dead (`NO DNS`, `unreachable`) needs no further diagnosis, and a
wildcard name is never resolved or probed in the first place, so both keep
`OwnershipUnknown` and render exactly as they do today.

## Data model

`tlsscan.SANCheck` gains one field holding mutually exclusive states rather than
another pair of booleans:

```go
// SANOwnership classifies whether a SAN name still points at the scanned host.
type SANOwnership string

const (
    // OwnershipUnknown means the comparison could not be made, because the
    // scanned host's own addresses are unknown (an IP-literal target with
    // ResolveDNS off, or a resolution failure).
    OwnershipUnknown SANOwnership = ""
    // OwnershipSameHost means the name resolves to at least one address the
    // scanned host also resolves to.
    OwnershipSameHost SANOwnership = "same-host"
    // OwnershipSameCert means the name resolves elsewhere, but that endpoint
    // presents the same leaf certificate: a CDN or a second front-end.
    OwnershipSameCert SANOwnership = "same-cert"
    // OwnershipOtherCert means the name resolves elsewhere and that endpoint
    // presents a different certificate: the name has moved away.
    OwnershipOtherCert SANOwnership = "other-cert"
    // OwnershipUnverified means the name resolves elsewhere but the confirming
    // handshake failed, so which of the two is unclear.
    OwnershipUnverified SANOwnership = "unverified"
)
```

The field on `SANCheck`, and a counter on `Report`:

```go
Ownership     SANOwnership `json:"ownership,omitempty"`  // on SANCheck
SANsElsewhere int          `json:"sansElsewhere"`        // on Report
```

`SANsElsewhere` counts names classified `OtherCert` or `Unverified`. It mirrors
the existing `DeadSANs` and, like it, never feeds the exit code.

`SANsElsewhere` is serialized without `omitempty` so a JSON consumer can tell
"checked, none moved" (`0`) from a scan that did not run the check.

## Detection logic

New unexported helper in `tlsscan`, kept pure so it is testable without a
network, following the precedent of `hygieneWarnings`:

```go
// classifyAddrs reports whether any of the name's addresses belongs to the
// scanned host, and if not, which address to use for the confirming handshake.
func classifyAddrs(addrs []AddrCheck, hostAddrs map[netip.Addr]bool) (sameHost bool, probeIP string)
```

Addresses are compared as `netip.Addr`, not strings, so two spellings of one
IPv6 address compare equal.

The host's address set is built from `Report.ResolvedIPs`; for an IP-literal
target the literal itself is the set. An empty set yields `OwnershipUnknown` for
every name.

The confirming handshake reuses the existing `probeIPCert` unchanged
(`tlsscan/tlsscan.go:561`) — it already retrieves a leaf fingerprint from a
given address with a given SNI, and already handles STARTTLS, so `--starttls`
targets work without extra code. SNI is set to the SAN name, not the scanned
host, because the question is what that name is served by.

`checkSANs` and `checkSAN` take one new parameter, a small struct rather than
three loose arguments:

```go
// sanContext carries what a SAN liveness check needs to know about the scan it
// belongs to, so a name can be classified as still pointing at the scanned host
// or as having moved elsewhere.
type sanContext struct {
    hostAddrs   map[netip.Addr]bool // the scanned host's own addresses
    fingerprint string              // the scanned host's leaf SHA-256
    startTLS    string              // mechanism for the confirming handshake
}
```

In `Scan`, `checkSANs` is already called after DNS resolution populates
`ResolvedIPs`, so no reordering is needed. The confirming handshakes run inside
the existing bounded SAN probe pool (`sanProbeConcurrency`) and under the
existing per-probe timeout, on the caller's `ctx` — not on the depleted
`scanCtx`.

## Rendering

`internal/report` gains one palette entry:

```go
colorMagenta = "\033[35m"
```

`sanLiveness` maps the new states:

| Ownership                | State text                    | Color   |
| ------------------------ | ----------------------------- | ------- |
| `SameHost`, `Unknown`    | `open` / `partial` (unchanged)| green / yellow |
| `SameCert`               | `open (other IP, same cert)`  | green   |
| `OtherCert`              | `elsewhere (other cert)`      | magenta |
| `Unverified`             | `elsewhere (unverified)`      | magenta |

Magenta is a new color reserved for this one condition, so a moved name is
visually distinct from both a healthy name (green) and a dead or degraded one
(red / yellow).

The ownership state replaces `open` / `partial` rather than being appended: a
name having moved matters more than one of its addresses being down, and the
per-address detail is not lost — the address column still marks the specific
address `(down)`.

The status headline gains `| N SANS ELSEWHERE` alongside the existing
`| N DEAD SAN(S)` advisory. The headline is a single string in a single color,
so it keeps the existing color priority (a real certificate problem outranks a
dead SAN, which outranks a moved SAN); magenta is not introduced there. As with
dead SANs, a moved SAN must never turn the headline red.

In the batch table, the `NOTE` column appends `N elsewhere` when the count is
non-zero.

Note for whoever implements this: in the SAN liveness block the state cell is
colored before it reaches the tabwriter, which is safe only because it is the
last column. If a column is ever added after it, the batch-table pattern
(lay out monochrome, colorize afterwards) must be adopted here too.

## Testing

Pure-function tests, no network:

- empty host address set yields `Unknown`
- intersecting addresses yield `SameHost` and select no probe address
- disjoint addresses yield a probe address
- two spellings of one IPv6 address compare equal
- `SANsElsewhere` counts `OtherCert` and `Unverified`, not `SameCert`

Network tests against local listeners on `127.0.0.1:0` with the `lookupIP` seam,
following the existing pattern:

- name resolving to a second local TLS server with a different certificate
  yields `OtherCert`
- name resolving to a second local listener presenting the same certificate
  yields `SameCert`
- name whose confirming handshake fails yields `Unverified`
- a name that shares the host's address triggers no handshake at all
  (asserted with a counter, to prove the free path stays free)

Render tests cover each state's text and color, that `--color=never` and
`NO_COLOR` suppress magenta, and that the headline never turns red from a moved
SAN. A JSON test covers the new fields.

## Documentation

README's "SAN liveness" table, `writeUsage`, and the scan usage text all
describe SAN states, so all three need the new states. CLAUDE.md's invariant
list needs the magenta-is-only-for-moved-SANs note and the extension of the
advisory-only rule to moved SANs.
