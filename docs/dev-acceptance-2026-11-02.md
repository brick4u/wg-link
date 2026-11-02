# Dev acceptance – 2026-11-02

**Passed:** 91 traffic checks, gateway relocation and recreation, live ACL
changes and cleanup on three nodes.

## Candidate and environment

- Runtime source: `6c4ae6617d1df0b16537331ba2e0b197ae2196e2`.
- Published image: `ghcr.io/brick4u/wg-link@sha256:23ef90d87204f1b4a037d1547b11d29a1d8b0f819ca5a727cae3684e50f5ff64`.
- Image revision label checked against the source commit; image CI passed.
- Three dev nodes: Talos 1.14.5, Kubernetes 1.36.2, Flannel 0.28.8 with VXLAN and KubeSpan.
- Initial placement: client, two-interface router and target each on a separate node.
- No CNI, node routing, host firewall, node scheduling configuration or production workload changes.

The [acceptance harness](../tests/kubernetes_acceptance.py) uses an isolated,
ownership-labelled namespace, temporary keys, namespaced read-only discovery
RBAC, ordinary Pod networking and only the required container capabilities.
All application/probe images are pinned by digest and prewarmed on all nodes.
Test settings: one replica with `Recreate`, WireGuard MTU 1280, internal peer
keepalive 1 s, readiness period 1 s, termination grace 3 s. Different deployment
settings can change recovery times.

## Functional checks

- Bidirectional ICMP, TCP and UDP through both WireGuard legs.
- Original inner source IP preserved; no NAT.
- Allowed port 18080 and denied port 18081, with positive local listener controls.
- Unauthorized target denied; kernel nft accept/drop counters checked.
- Live ConfigMap ACL revocation and restoration without router restart.
- Existing TCP connection blocked during revocation and resumed on the same socket tuple, without reconnecting.
- Gateway relocation, Pod recreation, scale-to-zero recovery, and Service recreation with a different ClusterIP.
- EndpointSlice state and actual kernel WireGuard endpoints checked after each mutation.

## Measurements

Continuous ICMP sampling interval: **200 ms**; timeout: **600 ms**. These are
individual observations, not an SLA or percentile estimate.

“Receive gap” is the maximum observed interval between successful replies during
a mutation, including sampling granularity. “Confirmed recovery” runs from the
pre-mutation marker to the fifth successful probe after endpoint convergence;
it includes command execution, scheduling and startup.

| Scenario | First run: receive gap | First run: confirmed recovery | Clean repeat: receive gap | Clean repeat: confirmed recovery |
|---|---:|---:|---:|---:|
| Move router to another node | 6.40 s | 7.27 s | 6.40 s | 7.41 s |
| Delete/recreate router Pod | 6.20 s | 7.21 s | 6.00 s | 7.15 s |
| Scale router 0 → 1 | 10.40 s | 11.31 s | 10.20 s | 11.10 s |
| Recreate Service with changed ClusterIP | No failed probes; normal maximum gap 0.202 s | 2.98 s | No failed probes; normal maximum gap 0.202 s | 3.22 s |

Scale-to-zero includes **3 seconds of deliberate downtime**, plus termination
and startup. Service recreation leaves the gateway Pod running; discovery uses
Pod endpoints, not the ClusterIP, so existing traffic need not stop.

The first execution passed every runtime assertion and removed its namespace,
but the final summary gate incorrectly rejected the additional ACL timing
scenario. The gate was corrected and regression-tested; the complete repeat then exited
successfully with **91 traffic checks**, validated latency evidence, and the
same-TCP-session revocation/restoration proof. The application image is unchanged
between runs. The first process exit is not represented as a clean pass.

ACL deny/restore intervals intentionally include Kubernetes ConfigMap projection
delays and are not endpoint-failover measurements. The router was not restarted
for these changes.

## Scope and cleanup

The tests move and recreate gateway Pods. Cluster nodes remain running.

Both runs: isolated namespace deleted; no test namespaces remain. All three
nodes remain Ready, with unchanged node identities and scheduling state.
No production workload or node configuration was modified.

The release commit adds documentation and test-evaluation checks only; its
runtime Go sources, module dependencies and Dockerfile match the tested
candidate. Release-image runtime layers are checked against the candidate.

Private raw evidence is retained outside version control. SHA-256 digests:

- First execution: `5ce3e8924570109511717a1704cac4ef393dba45d8741ae2e1c62e8fdc97c735`.
- Clean repeat: `5971c806812ae45b86e30e8db3de8a2c5b5efaf78701dbec62e398735f9d455e`.
