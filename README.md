# wg-link

Pod-local WireGuard networking with Kubernetes endpoint discovery. Runs in a
Pod's network namespace, as a standalone container or beside another gateway.
No CNI changes, node routes, CRDs, or central controller are required.

**Initial implementation; not production-validated.**

## Scope

- Multiple WireGuard interfaces, explicit addresses/routes, and peer configuration.
- Literal-IP endpoints, authenticated mobile endpoint learning, or Kubernetes
  Service references resolved to direct Pod IPs through EndpointSlices.
- Polling reload of configuration and key files, including Kubernetes projected
  volume updates (polled every second). Mount whole directories, **not `subPath`**. Key rotation can
  interrupt sessions and requires coordination with peers.
- Optional, explicit forwarding ACLs between WireGuard interfaces managed by the
  same container. Creating two interfaces alone does not enable forwarding.
- **No NAT, provider-specific routing, general firewall, IPAM, or key-generation
  management.** Supply return routes and any required external NAT separately.
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
between WireGuard interfaces managed by this container. The example permits
only TCP destination port 443 from one access peer to a transit subnet.
Forwarding does not add routes or change WireGuard `allowedIPs`; configure both
and the remote return routes separately.

Each rule requires:

| Field | Meaning |
| --- | --- |
| `from`, `to` | Ingress and egress interfaces declared in `interfaces`; only owned WireGuard links are supported |
| `source`, `destination` | Canonical network CIDRs of the same address family; these select IPv4 or IPv6 |
| `protocols` | Nonempty list of `icmp` (IPv4), `icmpv6` (IPv6), `tcp`, or `udp`; no duplicates |
| `ports` | Optional unique integer destination ports, 1–65535; allowed only with TCP/UDP protocols |

Omitting `ports` or using `ports: []` permits **all destination ports** for the
listed TCP/UDP protocols. Use separate rules for ICMP and port-limited TCP/UDP.
An enabled configuration with no rules denies all forwarded traffic involving
owned interfaces. A disabled configuration must not contain rules.

Each allow rule admits matching new/established traffic and exact per-rule
reverse `ESTABLISHED` replies: reversed interfaces and CIDRs, the same protocol,
and source ports matching the original destination ports when restricted.
There is no global established-state bypass. Removing an ACL also revokes its
existing connections unless another current rule permits them. There is **no
broad `RELATED` allowance**; related ICMP errors are conservatively denied.

The scoped default is drop for any forwarded packet entering or leaving an
owned interface unless explicitly allowed. Unrelated forwarding is unchanged;
other firewall tables can still deny permitted traffic. These ACLs do not manage
traffic to/from the container itself or provide a general firewall.

The agent owns only nftables table `inet wg_link`, identified by table comment
`wg-link:v1`, and replaces its rules in one atomic `nft` batch. A same-named table
without that ownership comment is a conflict, not something the agent overwrites.
Do not share the table or its ownership marker with other processes.

Once enabled, disabling or omitting `forwarding` removes the allows but retains
a **deny-only boundary**, including historical interface names, across reloads
and agent restarts in the same network namespace. Forwarding sysctls remain
unchanged. Clean removal requires Pod/network-namespace recreation or deliberate
operator cleanup after reviewing leak risk; stopping the agent is not cleanup.

Only families used by enabled rules require forwarding sysctls:
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

## Development and tests

```sh
go test -race -count=1 ./...
go vet ./...
docker build -t wg-link:test .
WG_LINK_IMAGE=wg-link:test bash tests/integration.sh
```

The integration test uses two disposable containers on an isolated Docker
network with kernel WireGuard and `NET_ADMIN` (`NET_RAW` only for test pings).
It checks bidirectional traffic, live key/peer reload and retained blackhole
routes after route removal. It does not change host routes or use host networking.
Throwaway test keys stay outside the checkout and are removed during cleanup.
Informer tests use a fake Kubernetes client; they do not replace cross-node
Kubernetes acceptance tests. CI runs formatting, vet, race tests, the container
integration test and multiarchitecture image builds.
