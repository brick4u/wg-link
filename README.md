# wg-link

Pod-local WireGuard networking with Kubernetes endpoint discovery. Runs in a
Pod's network namespace, as a standalone container or beside another gateway.
No CNI changes, node routes, CRDs, or central controller are required.

See the [three-node test report and measured recovery times](docs/dev-acceptance-2026-11-02.md)
and the [integrated IPSec, DNS, NAT and monitoring test](docs/system-acceptance-2026-11-03.md).
The [broker-proxy acceptance](docs/proxy-acceptance-2026-11-16.md) adds source-preserving
DNAT, separate HAProxy Pods and a 1,000-client MQTT reconnect test.

## Scope

- Multiple WireGuard interfaces, explicit addresses/routes, and peer configuration.
- Literal-IP endpoints, authenticated mobile endpoint learning, or Kubernetes
  Service references resolved to direct Pod IPs through EndpointSlices.
- Polling reload of configuration and key files, including Kubernetes projected
  volume updates (polled every second). Mount whole directories, **not `subPath`**. Key rotation can
  interrupt sessions and requires coordination with peers.
- Optional, explicit forwarding ACLs between owned WireGuard interfaces and
  allowlisted namespace-local interfaces, with narrowly scoped IPv4 masquerading
  and destination NAT.
  Creating interfaces alone does not enable forwarding.
- **No provider-specific routing, general firewall, IPAM, or key-generation
  management.** Supply routes separately.
  NetworkPolicy does not replace inner-tunnel ACLs.

Requires Linux kernel WireGuard support already available on the node, reachable
UDP endpoints, and `NET_ADMIN` in the Pod network namespace. No `hostNetwork`,
host mounts, `SYS_MODULE`, or privileged container is required. Cluster admission
policy must permit `NET_ADMIN`; the agent does not load kernel modules.

## CLI

```sh
go build -o wg-link ./cmd/wg-link
./wg-link -config ./config.yaml -check
./wg-link -config /etc/wg-link/config.yaml -listen :9090
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `-config` | `/etc/wg-link/config.yaml` | YAML configuration |
| `-listen` | `:9090` | Health and metrics HTTP listener |
| `-kubeconfig` | unset | Explicit kubeconfig; otherwise in-cluster credentials for discovery |
| `-check` | false | Validate configuration and key files, then exit; no API access or `NET_ADMIN` needed |

The container uses Go 1.27.3 and Alpine 3.24.3 and includes `nftables`.
The `nft` executable is required even when forwarding configuration is omitted:
reconciliation discovers any previously owned forwarding boundary.
The GitHub Actions workflow
publishes `ghcr.io/brick4u/wg-link` by default using the repository `GITHUB_TOKEN`:

| Git ref | Image tag |
| --- | --- |
| Branch `master` | `master` |
| Tag `1.0.0` | `1.0.0` |

Release tags must be numeric `MAJOR.MINOR.PATCH`, without a `v` prefix. No
implicit `latest` tag is published. Pull requests run tests and build images
without publishing. Images target `linux/amd64` and `linux/arm64`.

For an external registry, set repository variable `CONTAINER_IMAGE` to the full
image path and secrets `REGISTRY_USERNAME` / `REGISTRY_PASSWORD`. GHCR package
visibility and organization package permissions are configured on GitHub.
Publication requires the repository to have the appropriate registry rights.
The project license has not yet been selected.

## Configuration

See [examples/config.yaml](examples/config.yaml) for two interfaces and Service
and mobile peers. Replace all key placeholders and documentation addresses.
Supply existing base64 WireGuard private keys and optional preshared keys as
files; public keys belong in the configuration. Never commit real private keys.
Relative key paths resolve relative to the configuration file.

- `interfaces`: `name`, `addresses` (CIDRs), `mtu`, `listenPort`,
  `privateKeyFile`, `routes` (canonical CIDR strings), and `peers`.
- Each peer has `publicKey`, `allowedIPs` (canonical CIDRs), optional
  `presharedKeyFile`, and `persistentKeepalive` (integer seconds, 0–65535;
  zero disables keepalives).
- Choose **either** `endpoint: 203.0.113.200:51820` **or**
  `service: {namespace: wg-link, name: peer-gateway, port: wireguard}`.
  Static endpoints accept literal IPs only, not DNS names; bracket IPv6 addresses.
- Omit both `endpoint` and `service` for mobile peers whose endpoint WireGuard
  learns from authenticated traffic. The client must initiate contact.
- `allowedIPs` controls WireGuard peer selection/accepted source prefixes;
  `routes` explicitly controls kernel destination routes. Configure both as
  needed. Validate MTU against the actual underlay; 1280 is an example, not a
  universal optimum.

Discovery selects the named UDP port from Service-owned EndpointSlices and uses
its direct endpoint IP, not the Service ClusterIP. An endpoint must be explicitly
ready and not terminating. Exactly **one distinct IP:port** must qualify; zero
or multiple candidates are unavailable, not a load-balancing choice. API watches
reconnect through client-go. Reloads add watches for newly referenced namespaces,
including the first Service-backed peer. Watched namespace scope accumulates
until the agent restarts, even when references are removed from configuration.
Discovery is not HA: there is no WireGuard session, IPSec, NAT, or conntrack
state synchronization.

### Optional forwarding

Set `forwarding.enabled: true` and declare explicit `rules` to forward traffic
between WireGuard interfaces managed by this container or explicitly allowlisted
namespace-local interfaces. The example permits
only TCP destination port 443 from one access peer to a transit subnet.
Forwarding does not add routes or change WireGuard `allowedIPs`; configure both
and the remote return routes separately.

Each rule requires:

| Field | Meaning |
| --- | --- |
| `from`, `to` | Ingress and egress interfaces declared in `interfaces` or `forwarding.externalInterfaces`; the same interface is permitted |
| `source`, `destination` | Canonical network CIDRs of the same address family; these select IPv4 or IPv6 |
| `protocols` | Nonempty list of `icmp` (IPv4), `icmpv6` (IPv6), `tcp`, or `udp`; no duplicates |
| `ports` | Optional unique integer destination ports, 1–65535; allowed only with TCP/UDP protocols |

Omitting `ports` or using `ports: []` permits **all destination ports** for the
listed TCP/UDP protocols. Use separate rules for ICMP and port-limited TCP/UDP.
An enabled configuration with no rules denies all forwarded traffic involving
scoped interfaces. A disabled configuration must not contain rules, masquerade,
or DNAT entries.

#### External interfaces and IPv4 masquerading

These fields were added on `master` after `1.0.0`. The
[integrated test report](docs/system-acceptance-2026-11-03.md) records the tested image digest.

`externalInterfaces` is an optional list of existing namespace-local interface
names, for example `[eth0]`. Names must be valid, unique, and distinct from
`interfaces`; `.` and `..` are invalid. External links must not carry the wg-link
ownership alias. wg-link never creates, deletes, or reconfigures these links.
Enabled configurations require every listed link to exist before allows commit;
remote tunnel/SA availability is not checked. Adding `eth0` scopes its forwarded
traffic to this firewall's default deny, so declare every required flow explicitly.

```yaml
forwarding:
  enabled: true
  externalInterfaces: [eth0]
  rules:
    - from: eth0
      to: eth0
      source: 198.18.10.0/24
      destination: 203.0.113.0/24
      protocols: [tcp, udp]
  masquerade:
    - from: eth0
      to: eth0
      source: 198.18.10.0/24
      destination: 203.0.113.0/24
```

Each `masquerade` entry requires `from`, `to`, `source`, and `destination`.
Endpoints use the same interface declarations as ACLs; source and destination
must both be explicit canonical IPv4 CIDRs. IPv6 NAT is rejected. There are no
NAT protocol/port fields: filter rules govern permitted flows. Same-interface
forwarding supports policy-based IPsec ingress and Internet egress on one link.
The owned `inet wg_link` table's NAT postrouting chain uses priority `srcnat` and
matches original ingress (`iifname`), egress (`oifname`), source, and destination
before `masquerade`. Destinations outside the configured NAT prefixes remain
untranslated. NAT alone grants no forwarding permission. No global ruleset flush
or foreign table changes occur.

#### Scoped IPv4 destination NAT

`forwarding.dnat` translates an explicit original destination and service port
in the owned table's NAT `prerouting` chain, at priority `dstnat`:

```yaml
forwarding:
  enabled: true
  externalInterfaces: [eth0]
  dnat:
    - from: eth0
      source: 198.18.10.0/24
      destination: 192.0.2.80/32
      protocol: tcp
      port: 12101
      targetIPAddress: 198.18.60.1
      targetPort: 1883
  rules:
    - from: eth0
      to: wg-proxy
      source: 198.18.10.0/24
      destination: 198.18.60.1/32
      protocols: [tcp]
      ports: [1883]
```

Declare `wg-proxy` in `interfaces` and configure its peer, `allowedIPs`, routes,
and return path separately. All addresses above are documentation/test addresses.

| DNAT field | Requirement |
| --- | --- |
| `from` | Valid ingress interface declared in `interfaces` or `externalInterfaces` |
| `source` | Explicit canonical IPv4 CIDR |
| `destination` | Explicit canonical IPv4 **/32** CIDR |
| `protocol` | `tcp` or `udp` |
| `port` | Original destination port, integer 1–65535 |
| `targetIPAddress` | Literal IPv4 address, not a hostname or CIDR |
| `targetPort` | Mandatory translated destination port, integer 1–65535 |

The rule matches ingress, source, original destination, protocol, and destination
port before `counter dnat ip to IP:port`. Duplicate or overlapping source matches
for the same ingress, original destination, protocol, and port are rejected,
even with identical targets. Different original ports on the same public IP are
supported. There is no output DNAT or automatic SNAT. To preserve the APN source,
do not configure a matching masquerade rule for the translated proxy flow.

Forwarding ACLs run **after DNAT**: grant the translated destination and target
port, not the original public IP/port. Reverse ACLs match the proxy's source IP
and target service port before reverse NAT. NAT alone grants no forwarding
permission. These ACLs cover routed traffic; a target local to the agent's own
network namespace traverses INPUT, not FORWARD, and is not protected by them.

For an APN proxy topology, use a separate HAProxy + wg-link Pod per broker with
a stable internal proxy address routed over WireGuard. DNAT the broker's original
public IP/port to that proxy IP/port without masquerading. HAProxy receives the
APN source and opens the broker connection with `send-proxy-v2`; enable PROXY
protocol on the corresponding VerneMQ listener. HAProxy must only accept trusted
APN traffic, and the VerneMQ PROXY listener must only accept trusted proxies.
Neither HAProxy nor VerneMQ configuration is managed by wg-link.

NAT is stateful: existing connections follow their existing conntrack bindings,
including after a DNAT rule is removed or its target changes. wg-link does not
flush conntrack. Removing the corresponding forwarding ACL denies those routed
connections unless another current ACL permits the same translated flow. Removing
only a DNAT rule does **not** revoke existing sessions when the target remains
allowed, including targets shared by other rules. Stage or disable forwarding to
remove all scoped allows; deny-only staging contains no NAT chains or rules.

Each allow rule admits matching new/established traffic and exact per-rule
reverse `ESTABLISHED` replies: reversed interfaces and CIDRs, the same protocol,
and source ports matching the original destination ports when restricted.
There is no global established-state bypass. Removing an ACL also revokes its
existing connections unless another current rule permits them. There is **no
broad `RELATED` allowance**; related ICMP errors are conservatively denied.

The scoped default is drop for any forwarded packet entering or leaving an
owned or allowlisted external interface unless explicitly allowed. Unrelated forwarding is unchanged;
other firewall tables can still deny permitted traffic. These ACLs do not manage
traffic to/from the container itself or provide a general firewall.

The agent owns only nftables table `inet wg_link`, identified by table comment
`wg-link:v1`, and replaces its rules in one atomic `nft` batch. A same-named table
without that ownership comment is a conflict, not something the agent overwrites.
Do not share the table or its ownership marker with other processes.

Changed configurations first stage a deny-only boundary, validate required
forwarding sysctls and reconcile interfaces, peers and routes. Only then are the
final allows and NAT committed. Deny-only staging and disabled configurations
contain no NAT rules. A failed reconciliation remains denied; a successful
reload can briefly interrupt forwarding. Unchanged configurations do not churn
the ruleset. Address-generated routes that would shadow another interface's
explicit routes are rejected before network changes.

Once enabled, disabling or omitting `forwarding` removes the allows but retains
a **deny-only boundary**, including historical interface names, across reloads
and agent restarts in the same network namespace. Forwarding sysctls remain
unchanged. Clean removal requires Pod/network-namespace recreation or deliberate
operator cleanup after reviewing leak risk; stopping the agent is not cleanup.

Only families used by enabled rules (or IPv4 masquerading/DNAT) require forwarding sysctls:
`net.ipv4.ip_forward=1` and/or `net.ipv6.conf.all.forwarding=1`. If already `1`,
the agent skips writing. Otherwise it attempts to enable the required family;
a read-only `/proc/sys` causes reconciliation to fail. Preconfigure the values
through permitted Pod `securityContext.sysctls` (subject to cluster admission)
or another approved preconfiguration mechanism. `NET_ADMIN` cannot bypass a
read-only proc filesystem; do not use a privileged-container workaround.

## Kubernetes example

[examples/kubernetes.yaml](examples/kubernetes.yaml) contains a Deployment,
Service, ServiceAccount, and namespaced read-only RBAC for Services and
EndpointSlices (`get/list/watch`). There are no Secret API permissions. For
peers in other namespaces, add the same Role and a RoleBinding in each target
namespace, binding the agent's ServiceAccount; do not grant cluster-wide access.

Prepare resources before starting the Deployment. These commands are setup
instructions, not an action performed by this repository:

```sh
kubectl create namespace wg-link
# First edit the example: replace public keys, addresses, and peer reference.
kubectl -n wg-link create configmap wg-link-config \
  --from-file=config.yaml=examples/config.yaml
kubectl -n wg-link create secret generic wg-link-keys \
  --from-file=transit-private=/secure/transit-private \
  --from-file=transit-psk=/secure/transit-psk \
  --from-file=access-private=/secure/access-private
# Review the image reference and all configuration before applying:
kubectl apply -f examples/kubernetes.yaml
```

The manifest exposes this Pod as Service `wg-link`; it does **not** supply the
separate `peer-gateway` workload referenced by the configuration. Deploy a
reciprocal peer with matching public keys, AllowedIPs, routes, and named UDP
Service port. The example Service is ClusterIP only: external mobile access
requires separately arranged UDP exposure and firewall policy. Permit required
API/UDP traffic through any NetworkPolicies. Do not publish the HTTP management
port publicly; it has no authentication.

Keep one replica and `Recreate` for each gateway. Updates may interrupt traffic;
a second replica is not stateful failover. The container runs as UID 0 with all
capabilities dropped except `NET_ADMIN`, read-only root filesystem, and no host
access. Directory mounts allow ConfigMap/Secret updates to be picked up after
Kubernetes projection and the agent's polling interval; no rollout is required.

## Health and operational limits

- `/healthz`: agent liveness, not remote peer availability.
- `/readyz`: local network reconciliation readiness, **not** remote endpoint or
  handshake readiness. This permits both peers to bootstrap discovery.
- `/metrics`: Prometheus-format operational metrics. Monitor discovery errors,
  missing/ambiguous endpoints, and tunnel traffic separately from readiness.

### Ownership and fail-closed routes

Use a dedicated network namespace and one agent per namespace. The agent owns
WireGuard links marked with alias `wg-link:v1`; it refuses conflicting foreign
interfaces. It reconciles addresses and peers on owned links and removes owned
interfaces absent from configuration. Routes use protocol 196 and metrics
42760 (interface route) / 42761 (blackhole guard) in the main routing table.
Do not share these ownership markers with other processes.

For every explicit `routes` prefix, a blackhole guard is installed before
interface changes. Removing a route or interface removes its forwarding path
but **retains the blackhole guard**, including across agent restarts in the
same network namespace. Recreate the Pod/network namespace for clean removal,
or have an operator explicitly remove the obsolete guard after reviewing leak
risk. Stopping the agent alone does not clean up kernel networking.

Missing or ambiguous discovery does **not** revoke an existing peer endpoint:
the last known/authenticated endpoint is retained. A new peer without an
endpoint cannot initiate traffic. Tunnel routes/guards prevent ordinary fallback
to a less-specific default route; they are not firewall rules and do not protect
against competing more-specific routes, policy routing, or another privileged
network manager. Explicitly list all protected destinations in `routes`.
Invalid reloads retain the previous kernel configuration and make readiness
fail; reconciliation failures can leave partially applied changes.

Gateway forwarding/ACLs, actual cross-node reachability, endpoint replacement,
key reload, MTU, and negative leak tests require validation in your environment.
No production deployment or end-to-end connectivity guarantee is implied by
these examples.

## Optional exclusive activation

A configuration may opt the entire interface group into Kubernetes Lease-based
activation. Application health remains outside wg-link: kubelet readiness probes
on named containers determine candidacy. Do not list the wg-link container itself
or depend on Pod Ready, which includes wg-link's own activation readiness.

```yaml
activation:
  kubernetesLease:
    name: gateway-active
    requireReadyContainers: [application]
    leaseDuration: 15s
    renewDeadline: 10s
    retryPeriod: 1s
  fenceTimeout: 3s
```

Supply `POD_NAME`, `POD_NAMESPACE`, `POD_UID` through the Downward API and set
`WG_CONTAINER_NAME` to this container's name. The application must run in an
ordinary Pod network namespace, not hostNetwork. Fixed, unique positive
WireGuard listen ports are required; activation settings and the listen-port set
are restart-required. Readiness is successful only after an eligible holder has
configured its interfaces and opened the kernel gate. Standbys retain protected
blackhole routes but remove owned WireGuard interfaces. A selected instance that
cannot apply its interface configuration yields ownership and waits one renewal
deadline before competing again, so it cannot indefinitely block healthy peers.

The namespace Role requires Pod `get` and Lease `get/list/watch/create/update`.
No provider credentials or application-specific APIs are used. A Service peer can
optionally set `leaseName: gateway-active`; discovery filters ready EndpointSlice
Pod UIDs to the current Lease holder. Without `leaseName`, no Lease permission is
required and existing discovery behavior is retained. Missing or ambiguous
selection keeps an existing authenticated endpoint, without routing fallback.

A separate owned nftables table fences only the managed UDP INPUT destination
and OUTPUT source ports. Opening requires an absolute wall-clock deadline and a
relative kernel timeout. Kernel expiry still applies if userspace stops running.
Late owned-Lease acknowledgements are bounded by request start time; confirmed
fence closure precedes early ownership release. A previously acknowledged closed
gate is reused without repeated nft writes; uncertain write outcomes always force
another close attempt. External modification of this owned table is unsupported.
Other protocols and ports are not gated. Lease election is not itself a fencing guarantee: combined clock
rewind and delayed stale execution remain a bounded-clock/fault assumption.

Failed Pod GETs retain the last successful eligibility observation only within
`renewDeadline`; they do not immediately demote a healthy owner. The gate never
extends beyond that observation budget or the latest acknowledged Lease-write
budget. With the defaults, complete API loss therefore closes within about ten
seconds; a stalled process loses its kernel allowance within three seconds.
An explicit successful observation of an unready required container closes
immediately. Container Ready is the last kubelet-reported result, not a
timestamped application heartbeat. Readiness-probe targets and thresholds
remain the deployment's responsibility. The optional mode requires Linux,
NET_ADMIN, nftables and namespace-scoped Kubernetes access; legacy mode does not
acquire a Lease or require Pod lookup.

## Development and tests

```sh
go test -race -count=1 ./...
go vet ./...
python3 -m unittest discover -s tests -p 'test_*.py' -v
docker build -t wg-link:test .
WG_LINK_IMAGE=wg-link:test bash tests/integration.sh
docker pull python:3.14-alpine@sha256:eb2c62658b8d51bff0acc408504b76521d02030de56a8a3c1e830083e89b89d2
python3 tests/forwarding_integration.py --execute \
  --probe-image python:3.14-alpine@sha256:eb2c62658b8d51bff0acc408504b76521d02030de56a8a3c1e830083e89b89d2
```

The integration test uses two disposable containers on an isolated Docker
network with kernel WireGuard and `NET_ADMIN` (`NET_RAW` only for test pings).
It checks bidirectional traffic, live key/peer reload and retained blackhole
routes after route removal. It does not change host routes or use host networking.
Throwaway test keys stay outside the checkout and are removed during cleanup.
The three-gateway forwarding integration adds source-preserving ICMP/TCP/UDP,
steady-state address checks, allowed/denied ports and destinations, kernel nft
counters, and live ACL revocation/restoration of a held TCP connection without
reconnecting. Informer tests use a fake Kubernetes client; they do not replace
cross-node acceptance. CI runs measurement unit tests, formatting, vet, race
tests, both container integrations and multiarchitecture image builds.

### Isolated Kubernetes acceptance

The [Kubernetes acceptance test](tests/kubernetes_acceptance.py) runs in dev
on three nodes. It requires immutable application/probe image digests and
explicit `--execute`. It creates a unique
ownership-labelled namespace and removes it on success or failure. It never
drains, reboots, reprovisions or changes scheduling settings of shared nodes.

The topology is client → two-interface router → target on three initial nodes.
It validates allowed/denied ICMP/TCP/UDP, original source IP, live ACL changes,
router relocation, Pod recreation, scale-to-zero recovery, and Service recreation
with a changed ClusterIP. The images are prewarmed on all three nodes.

Continuous ICMP probes use a 200 ms interval and 600 ms timeout. Results distinguish
the observed successful-reply gap from change-marker → fifth successful probe
after EndpointSlice/kernel-endpoint convergence. The latter includes Kubernetes
command, scheduling and startup time. The test moves gateway Pods between
running nodes.
Complete latency evidence and successful cleanup are required for a passing run.

### Integrated APN and broker-proxy acceptance

The [system test](tests/system_acceptance.py) exercises IKEv1/NAT-T, two independent
Unbound instances, support routing, Internet masquerade and three separate
HAProxy + wg-link proxy Pods connected directly to authenticated VerneMQ backends.
Devices keep their original broker destination IP and ports. Scoped DNAT routes
them over WireGuard; HAProxy supplies the APN client address through PROXY v2.
Backend connections use ordinary Kubernetes Service DNS names.

The test requires an explicit kubeconfig, three distinct node names, immutable
`--wg-image`, `--strongswan-image`, `--unbound-image`, `--exporter-image`,
`--probe-image`, `--haproxy-image` and `--broker-image` digests, and `--execute`.
Run `python3 tests/system_acceptance.py --help` for the full argument list.
`--connection-count` selects 3–1000 concurrent authenticated MQTT clients;
`--connection-interval 0` submits a bounded burst with at most 16 simultaneous
handshakes. All resources are confined to an ownership-guarded temporary namespace.

Checks include actual MQTT CONNECT/SUBSCRIBE/QoS1 publish-and-echo, broker-observed
client IPs, sustained held connections during a standard HAProxy master-worker
reload, proxy-Pod replacement isolated from other brokers and IPsec, and a
reconnect burst after tunnel recovery. Only local IKE bootstrap publishes
not-ready endpoints; WireGuard discovery selects a single ready proxy per broker.

### Public IPvlan and IPsec failover acceptance

The [IPvlan test](tests/ipvlan_acceptance.py) first checks the normal Flannel path,
then a secondary public `/32` with source routing and external UDP/TCP replies.
The [IPsec test](tests/ipvlan_ipsec_acceptance.py) adds native ESP or forced
ESP-in-UDP, cold initiation from either end, hard test-Floating-IP moves,
protected traffic observations, rekey, reauthentication and Pod recreation.
See the [measured results and limitations](docs/ipvlan-ipsec-acceptance-2026-11-17.md).

Both tools require explicit environment arguments and `--execute`. The IPsec
tool additionally requires mutation acknowledgements and a private approval file.
Its host-network test peer has an independently armed, process-qualified recovery
helper and exact benchmark selectors. Use dedicated test resources, never
production VPN credentials or a production Floating IP. Run each tool with
`--help` and review the safety requirements before execution.
