# IPvlan IPsec failover acceptance — 2026-11-17

## Scope

Controlled public-network tests with a dedicated test Floating IP, two gateway
Pods on separate Hetzner Cloud nodes and a separate strongSwan peer. Production
VPN endpoints, credentials and Floating IPs were not used. Environment-specific
addresses, resource IDs and private evidence remain outside this repository.

Stack: Talos 1.14.5, Linux 6.18.58, Kubernetes 1.36.3, Flannel, Multus 4.3.2-thick
and CNI reference plugins 1.9.1. strongSwan 6.1.0 image:

```text
ghcr.io/brick4u/strongswan-ikev1@sha256:c38543f1a0818d27453d263674dc2bf7ef24fd1aaf7495c2ca31d29d22760f4d
```

The gateway public `/32` exists only on an IPvlan L2 interface in each Pod.
Explicit source policy routing preserves the normal Flannel default. The native
peer uses a host network namespace with exact benchmark `/32` selectors; an
independent, pre-qualified recovery process scopes cleanup to the test daemon,
address and XFRM state. No host firewall/default-route/sysctl rewrites or global
XFRM flush were used.

## Results

Three complete test runs passed: native ESP twice, explicitly forced ESP-in-UDP
once. Every run passed:

- cold peer initiation and cold gateway initiation;
- competing gateway initiation, with only the Floating-IP owner data-ready;
- hard Floating-IP move while the old gateway Pod/daemon remained running;
- autonomous reconstruction of IKE/CHILD SAs without controller initiation or
  peer reset during the hard-move window;
- hard return to the original owner;
- explicitly triggered CHILD rekey and IKEv1 reauthentication, with new SPIs and
  successful protected traffic;
- active gateway Pod recreation and subsequent protected traffic;
- Floating-IP restoration and verified scoped host/namespace cleanup.

IKEv1 used AES-256-CBC, SHA-256 and ECP384. Kernel state and protected ICMP
receive/transmit counter progress were checked at both ends. Native mode had no
UDP encapsulation. UDP mode positively required UDP4500 and `espinudp` kernel
state; this was forced encapsulation, not a test of an intervening NAT device.

### Hard-move observations

| Run | Owner A → B | Owner B → A |
|---|---:|---:|
| Native ESP, first run | 6.97 s | 6.69 s |
| Native ESP, repeat | 5.13 s | 7.28 s |
| ESP-in-UDP | 6.88 s | 9.94 s |

Values are the interval from the last successful bidirectional protected probe
on the old owner to the first on the new owner. Sequential API/ICMP/counter
sampling has variable granularity. These are not packet-level outage bounds or
production SLAs. Test-only IKEv1 DPD used delay 2 s / timeout 8 s, with short
retransmission settings. The peer used authenticated duplicate-ID replacement.

The old owner's local SA could remain installed after protected traffic failed.
Readiness must therefore check recent protected bidirectional traffic and receive
progress; `ESTABLISHED` alone is insufficient. The test Pods' Kubernetes
readiness only represented daemon startup, not production active-owner selection.

### Packet-size observations

Both directions were tested:

| ICMP payload | Native ESP | Forced ESP-in-UDP |
|---|---|---|
| 1200 bytes, DF | Pass | Pass |
| 1400 / 1410 bytes, DF | Pass | Local `Message too long` |
| 16000 bytes, fragmentation permitted | Pass | Pass |

The exact PMTU boundary was not searched. Required small DF traffic and large
fragmented traffic passed. Full forwarding, TCP MSS and any additional WireGuard
path still require separate end-to-end acceptance.

## Reproduction and safety

Use [ipvlan_acceptance.py](../tests/ipvlan_acceptance.py) for ordinary Flannel and
IPvlan UDP/TCP first, then [ipvlan_ipsec_acceptance.py](../tests/ipvlan_ipsec_acceptance.py).
Both default to no mutation without explicit execution. The IPsec controller also
requires a caller-owned private approval file, exact resource identity and
node/provider-ID checks. All infrastructure values are supplied by CLI.

The host peer is guarded by initial empty-XFRM, socket and address checks. Its
watchdog process identity/signalling is qualified against a harmless same-Pod
process before the benchmark address or SAs are installed. Normal cleanup and
restoration were verified in each run; abrupt controller/node death was not a
separate runtime test.

All **65 offline tests** passed after the final implementation, including the
new IPvlan/IPsec safety tests. No SA replication, lossless HA, carrier-specific
interoperability, forwarded APN/broker path or private WireGuard standby gating
is claimed by this acceptance.

Private result SHA-256:

- Native first: `0b82b07d43660e96a8144ede27d16960fa1b1369c1d1e0d0d02a187516b906c0`
- Native repeat: `f179e35611b67fb2997e28ff295e38d3a51e72a9114ffa2667587735ac6f4c81`
- UDP: `333398bd88a284234e028078aa266e17ea9c44803b999250b085d5be42f46497`
