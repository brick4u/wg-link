# Integrated gateway test – 2026-11-03

**PASS: 21 grouped checks**, including component recovery and cleanup.

## Setup

Six isolated Pods on three dev nodes:

| Pod | Components |
|---|---|
| Simulated APN peer | strongSwan, application probe |
| APN gateway | strongSwan, wg-link, VICI exporter, application probe |
| Shared DNS | Unbound, wg-link, application probe |
| Support gateway | wg-link, application probe |
| Support client | wg-link, application probe |
| Mock Internet endpoint | HTTP/TCP/UDP echo services |

Environment: Kubernetes 1.36.2, Talos 1.14.5, Flannel with VXLAN and KubeSpan.
The APN peer, gateway and DNS initially run on separate nodes. Inner test
addresses use the reserved benchmarking range `198.18.0.0/15`.

| Component | Tested immutable image |
|---|---|
| wg-link | `ghcr.io/brick4u/wg-link@sha256:5b7860b6577c454e4605cd7a1360dbff39bb3a93045168c91dce3ef4ebac5f98` |
| strongSwan 6.1.0, IKEv1 enabled | `ghcr.io/brick4u/strongswan-ikev1@sha256:c38543f1a0818d27453d263674dc2bf7ef24fd1aaf7495c2ca31d29d22760f4d` |
| Unbound 1.26.2 | `klutchell/unbound@sha256:50cbeb32b5838a829a7226b19cb151f9535bd7f9f3190f950780f452fe807478` |
| VICI exporter 1.10.2 | `torilabs/ipsec-prometheus-exporter@sha256:281865b434091b42233c3ca3912fe0ebdc2704f38f80e54816dae094784a88ab` |

The gateway image contains the external-interface and masquerade extension
from runtime source commit `cecd13518ac217d4babff7e79461f44a6c926c57`.

## Data paths and policy

- IKEv1 with PSK, AES-256/SHA-256/ECP-384 and NAT-T over UDP/4500.
- Support client → support gateway → APN gateway → IPSec → APN application,
  tested in both directions with ICMP, TCP and UDP.
- Both shared DNS addresses answer over UDP and TCP. Local policy zones provide
  an allowed answer and a loopback sinkhole answer.
- Original APN source addresses reach DNS and the internal application endpoint.
- Mock Internet HTTP/TCP/UDP services observe the gateway Pod IP after masquerade.
- Denied TCP/UDP ports and a denied internal destination are checked against
  actual listening services.
- The VICI exporter reports IKEv1, installed CHILD_SAs and positive encrypted
  inbound/outbound packet and byte counters.

Firewall and NAT come from wg-link's `forwarding` configuration. The gateway
explicitly scopes `eth0` through `externalInterfaces`, permits the required
forwarding paths, and applies masquerade only to the selected egress destination.

Kernel counters after the run:

| Table owner | Accepted packets | Dropped packets | Masqueraded new flows |
|---|---:|---:|---:|
| APN gateway | 286 | 6 | 3 |
| Support gateway | 60 | 3 | — |

## Healthchecks

The gateway uses two separate Kubernetes probes:

| Probe | Check | Configuration |
|---|---|---|
| Liveness | `swanctl --stats` | 10 s period, 6 failures |
| Readiness | Ping an APN target from a gateway-local transit address | 3 s period, 2 s timeout, 2 failures |

During a simulated APN outage, gateway readiness becomes false while daemon
liveness remains successful. Container identities and restart counts stay
unchanged. Readiness recovers when the tunnel is restored.

**The outer IKE Service publishes not-ready addresses.** This lets the APN peer
reach UDP/500 and UDP/4500 to establish or repair the tunnel while gateway data
readiness is false. The WireGuard discovery Service uses normal readiness.
This separation avoids a tunnel-bootstrap dependency cycle.

## strongSwan restart and exporter reconnect

The test terminates only charon as container PID 1. Kubernetes restarts that
container; its standard startup configuration loads the tunnel configuration.
The APN peer restores the tunnel using the configured DPD/restart behavior.

- Support and DNS traffic recover automatically.
- VICI metrics recover through the recreated socket in the shared runtime volume.
- Gateway Pod identity stays the same.
- wg-link, exporter and probe container identities/restart counts stay unchanged.

The complete restart verification, including control calls, readiness, data-path
and metric checks, took **8.86 s**. The outage/liveness separation check took
**10.08 s**, including its deliberate fault and restoration.

## Cleanup and reproduction

The test namespace, Pods, Services, Secrets and RBAC resources were removed.
All three nodes remain Ready with unchanged identities and scheduling state.
The [test harness](../tests/system_acceptance.py) requires explicit kubeconfig,
three distinct node names, immutable image digests and `--execute`.

Private raw evidence is kept outside version control. Its SHA-256 is
`b59e9649bc6cbdec1177e15705fc642f9bd067336950e60b718d35652372c97f`.
