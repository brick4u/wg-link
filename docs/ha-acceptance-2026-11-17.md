# Generic Lease activation acceptance — 2026-11-17

## Scope and implementation

Optional whole-group activation uses standard client-go Lease election. Named
container readiness is an optional candidacy condition; no application protocol,
VPN implementation or cloud provider is embedded in wg-link. Lease-aware peer
selection filters Ready EndpointSlice Pod UIDs to the Lease holder. Legacy
configuration retains its previous behavior and needs no Lease RBAC.

The kernel gate protects managed WireGuard INPUT destination and OUTPUT source
ports with both an absolute deadline and relative timeout. Acknowledged closure
precedes early Lease release. A request-start-bounded acknowledged Lease write,
recent successful eligibility observation and successfully applied configuration
are all required before opening. Defaults: Lease15s, renew10s, kernel window3s.
Application probe debouncing remains a deployment responsibility.

## Internal service baseline

A dedicated three-node test namespace contained 14 Pods: three gateway candidates,
two DNS servers, three HAProxy/WG proxies, three authenticated VerneMQ backends,
support gateway/client and a synthetic remote client. A fourth WG link modeled
the remote LAN only for this internal test; it was not an IPsec transport proof.

Verified with the published implementation:

- Three healthy application containers elect one active gateway.
- Both DNS servers answer UDP/TCP queries from the remote client and support;
  sinkhole A/AAAA policies are checked.
- Three independent MQTT paths pass CONNECT, SUBSCRIBE and QoS1 publish/echo.
  Actual backend sessions report the original source through PROXY v2.
- Support echo succeeds in both directions.
- Application-unhealthy demotion selects a different healthy candidate and all
  six service endpoints converge without manual endpoint writes.
- A newly recreated DNS/WG client selects the successor.
- Zero healthy candidates leave all gateway WG interfaces absent and gates closed;
  clients deliberately retain their last authenticated endpoint, not a default
  routing fallback.
- Recovery restores all service paths.

## Fault cases

The optional fault mode uses a test-only shell parent so the WG child can be
suspended. Linux protects namespace PID1 from this same-namespace SIGSTOP method.
Signals verify process ID, command name and process birth time; resume is bounded
and guaranteed through the test's normal finally path.

| Fault | Observed kernel closure | Other application still alive | Successor and service traffic |
|---|---:|---|---|
| WG child SIGSTOP | 1.95 s after acknowledged stop | Yes | Passed |
| Only gateway Pod's API connection blocked | 9.43 s after partition installation | Yes | Passed |
| Selected instance cannot reconcile its WG interface | 1.92 s after injected alias conflict | Yes | Passed without Pod/container restarts |

Closure was observed before ownership handoff in the suspend/API cases, and
before successor validation in the local configuration-failure case. The stopped
process was resumed, the scoped API partition removed and the test interface
alias restored using exact interface identity checks. These are sampled
observations, not universal timing bounds. An interrupted controller or unrelated
node failure was not injected simultaneously.

## Public IPsec composition

A separate reviewed controller combines the same six service roles with real
IPvlan/public IPsec and hard Floating-IP moves, retaining the old gateway and
peer processes. It uses five separate IKEv1 CHILDs for exact benchmark selector
pairs (health, DNS1, DNS2, broker and support), never a default selector on the
host-network test peer. Recovery verifies the entire five-reqid inventory and
exact outer endpoints/selectors. No unrelated host routing, firewall or sysctl
configuration is changed.

Both the initial and final native-ESP public roundtrips passed all six service
paths before and after both moves, including actual backend source identity and
increasing byte/packet counters for every CHILD on both sides. The controlled
peer and gateway containers retained their identities/restart counts.

The final run observed 3.34, 3.69 and 5.40 seconds from first observed application
readiness to completed DNS probe across its three epochs. These sequential
controller observations include API calls, six endpoint checks, CHILD verification
and probe execution; they are not packet-outage timestamps or guaranteed maxima.

An intermediate repeat failed within its budget while an implicit provider
unassignment task took 128 seconds, although the returned assignment task had
completed after six seconds. This failure is retained, not counted as a pass.
The controller now separately records assignment acknowledgement and confirmation
that all tasks of the test Floating IP settled before proceeding. Provider-specific
timers, production policy routing, external support ingress and device TCP
reconnect backoff require their own cutover checks.

## Safety limits and reproduction

Use [ha_service_acceptance.py](../tests/ha_service_acceptance.py) for internal
baseline/fault tests and [ipvlan_ha_service_acceptance.py](../tests/ipvlan_ha_service_acceptance.py)
for the public composition. Both require explicit execution, pinned images,
private evidence storage and isolated owned resources. Public tests additionally
require the private approval file and original strict Floating-IP identity and
restoration guards. Never use production VPN credentials or a production IP.

A Lease alone does not fence a surviving kernel interface. The gate is necessary.
The absolute condition protects against an ordinary late stale refresh; relative
expiry bounds an already installed grant during clock rewind. Combined clock
rewind and stale-process replay still requires bounded clock/fault assumptions.
Container Ready is the last kubelet-reported state, not a timestamped dataplane
heartbeat. An API outage deliberately trades availability for exclusive authority.

Final tested runtime image:

```text
ghcr.io/brick4u/wg-link@sha256:3d75bb2e9838a3bccd1a318e22ca9a5463871db3da319fdb1a18a37d1aabeece
```

It includes acknowledged closed-state caching, forced closure after uncertain
nft outcomes, and ownership yielding with renewal-deadline cooldown after a local
configuration failure. Baseline, all three fault cases and the final public
composition used the published artifacts, not a locally substituted binary.

Private evidence SHA-256 values are retained by the operator; no infrastructure
addresses, cloud IDs, credentials or private test artifacts belong in this repo.
