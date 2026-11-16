# APN broker-proxy acceptance – 2026-11-16

**PASS: 25 grouped checks on three dev nodes**, including 1,000 concurrent
MQTT clients after tunnel recovery, separate DNS instances and proxy lifecycle isolation.

## Topology

Thirteen disposable Pods, with APN peer, IPsec gateway and broker backends
spread across three nodes:

| Component | Instances | Function |
|---|---:|---|
| Simulated APN peer | 1 | IKEv1/NAT-T and MQTT/device traffic |
| IPsec gateway | 1 | strongSwan, wg-link firewall/DNAT/NAT, VICI exporter |
| DNS | 2 | Independent Unbound + wg-link, one virtual address each |
| Support gateway/client | 2 | Routed support access to the APN |
| Broker proxy | 3 | One HAProxy + wg-link Pod per independent broker |
| VerneMQ backend | 3 | Authenticated MQTT with PROXY-v2 listeners |
| Mock Internet endpoint | 1 | HTTP/TCP/UDP egress checks |

Each proxy has a unique WireGuard identity and virtual address. Its Deployment
uses one replica and `Recreate`, preserving the single-ready-endpoint discovery
contract. Original device broker destinations use the documentation address
`192.0.2.80` and three distinct TCP ports. Scoped gateway DNAT maps each port to
its corresponding proxy virtual address; forward ACLs authorize the translated
address and service port. No source NAT is applied on this internal path.

HAProxy connects directly to the appropriate VerneMQ ClusterIP Service by DNS
name, with Kubernetes DNS resolvers and `send-proxy-v2`. VerneMQ observes the
original APN address `198.18.10.2`. The test uses real MQTT CONNECT, authenticated
SUBSCRIBE and QoS1 PUBLISH/PUBACK with subscribed message echoes.

## Tested images

| Component | Immutable image |
|---|---|
| wg-link | `ghcr.io/brick4u/wg-link@sha256:c27bec1720e924012f9306a8f14d87351e19547ed2f744a1b35ff8abedf23f8b` |
| strongSwan 6.1.0 | `ghcr.io/brick4u/strongswan-ikev1@sha256:c38543f1a0818d27453d263674dc2bf7ef24fd1aaf7495c2ca31d29d22760f4d` |
| HAProxy 3.2.26 | `haproxy@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c` |
| VerneMQ 2.1.1 | `ghcr.io/micw/vernemq-docker@sha256:8fb3b4e2bef3b2700a965477ab67b8122ccb36d06aa6a9920d2f23c7293028a7` |
| Unbound 1.26.2 | `klutchell/unbound@sha256:50cbeb32b5838a829a7226b19cb151f9535bd7f9f3190f950780f452fe807478` |
| VICI exporter 1.10.2 | `torilabs/ipsec-prometheus-exporter@sha256:281865b434091b42233c3ca3912fe0ebdc2704f38f80e54816dae094784a88ab` |

The runtime wg-link source is `218c968549efaa114400a5e6c7f3e5ea3ebd71fa`.
[CI build and existing integration tests](https://github.com/brick4u/wg-link/actions/runs/43881889657)
passed. The VerneMQ image is the source-built image used by the existing broker setup.

## Results

| Check | Result |
|---|---|
| IKEv1/PSK, AES-256/SHA-256/ECP384, NAT-T | Passed |
| Support ↔ APN ICMP/TCP/UDP and denied services | Passed |
| Two independent DNS addresses, UDP/TCP policy answers | Passed |
| Internal source preservation and destination-scoped Internet masquerade | Passed |
| All three original broker ports routed to the correct proxy/backend | Passed |
| Original APN identity observed in actual VerneMQ sessions | Passed |
| Unknown original broker IP/port negative controls | Passed |
| Local daemon liveness versus APN datapath readiness | Passed |
| strongSwan container restart, automatic tunnel recovery and VICI reconnect | Passed |

DNAT kernel counters recorded 337, 335 and 335 new flows to the three respective
proxy addresses. A direct connection to an explicitly allowed proxy VIP/service
is also permitted by its forwarding ACL; original broker destination mapping is
not an additional access-control boundary.

### HAProxy configuration reload

A projected ConfigMap changes the first proxy's client/server timeouts from
2 hours to 3 hours. The test validates the new configuration with `haproxy -c`
and sends SIGUSR2 to the standard master process. It confirms a new worker PID,
a fresh successful MQTT connection and eleven repeated exchanges on the original
held connections over at least ten seconds.

All three held MQTT sockets, broker session PIDs/start times, Pod/container
identities and IPsec SA identifiers/SPIs remain unchanged. The full check took
25.88 seconds, including configuration projection, control calls and assertions.
Existing workers continue serving their established sessions during a graceful reload.

### Independent proxy replacement

The first proxy Pod is deleted with a UID precondition and recreated by its
Deployment. The test verifies a different Pod IP, one ready EndpointSlice and
automatic WireGuard endpoint update. Its original connection closes; new
connections through the same virtual address succeed.

The other two MQTT connections retain their socket and broker-session identities.
IPsec SAs, DNS, support and unrelated containers remain unchanged. The complete
replacement verification took 18.79 seconds, including termination/startup and
control checks.

### Tunnel recovery and reconnect burst

The test terminates only gateway charon, then relies on standard startup loading
and the peer's DPD/restart behavior. The complete tunnel/data/metric recovery
check took **11.06 seconds**. Other gateway containers retained their identities.

Immediately afterwards, the driver submits 1,000 clients with zero pacing delay
and at most sixteen simultaneous handshakes:

| Measurement | Observed |
|---|---:|
| Requested / established | **1,000 / 1,000** |
| Establishment errors | **0** |
| CONNECT + SUBSCRIBE + initial QoS1 roundtrip completion | **0.842 s** |
| Observed completion rate | **1,187 clients/s** |
| Distribution across brokers | 334 / 333 / 333 |
| Online clients independently verified at VerneMQ | **1,000** |
| Complete burst check including subsequent exchanges/session/resource inspection | 8.27 s |

These measurements describe the bounded three-node dev workload and its small
QoS1 messages. The test driver opens each client once and never reconnects a
held socket automatically.

### Resource samples

While the clients were held, Metrics API samples reported about **14 MiB and
21–24 mCPU per HAProxy container**, plus **9.5–10.3 MiB per wg-link sidecar**.
HAProxy worker RSS was **18.5–18.7 MiB** at 333–334 connections per broker.
Master and worker RSS share pages and must not be added together. Metrics API
samples are interval-based observations, not peak-memory measurements.

## Corrections identified during integration

- VerneMQ ACL syntax grants read/write with `topic isolated/#`; `topic readwrite
  isolated/#` describes a different literal topic filter. Offline regression
  assertions now check the intended ACL.
- The simulated peer originally resolved its IKE endpoint through cluster DNS
  during tunnel recovery. Its broad test traffic selector could briefly route
  those resolver requests through the unavailable tunnel. Bootstrap Services are
  now allocated before workloads; the peer uses the stable gateway ClusterIP
  directly and explicitly configures initial IKE ports 500. This keeps outer
  tunnel establishment independent from inner DNS.

## Reproduction and cleanup

Run [system_acceptance.py](../tests/system_acceptance.py) with explicit kubeconfig,
three node names, all image digests, `--execute`, `--connection-count 1000` and
`--connection-interval 0`. `--help` lists the complete options. Test credentials
are generated per run; the MQTT control listener binds only loopback.

The final run used the corrected configuration from namespace creation onwards.
All thirteen Pods and their namespace-scoped Services, Secrets, RBAC and
Deployments were removed. All three nodes retained their identities, scheduling
state and Ready condition. Production gateway and broker resources were unchanged.

Private final evidence SHA-256:
`211d2950eeefd8c7a0341565a84e260173c8a4c53e282cad5b8808c0ce1e4b08`.
