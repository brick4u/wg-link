#!/usr/bin/env python3
"""Review-first, bounded IPvlan/IKEv1 ESP acceptance controller.

No I/O without --execute. Execution additionally requires --allow-test-fip-moves
and --allow-native-host-peer. Review all CLI values and this source first.
Only a dedicated test Floating IP may be supplied. Never use production VPN credentials.
The controller needs kubectl and an HCLOUD_TOKEN environment variable, never a
command-line token. All images and infrastructure identifiers are caller inputs.

Both --encapsulation native (default) and udp use the same hostNetwork peer. Its independent recovery Pod outlives the
peer's activeDeadlineSeconds and cleans only the test reqid, exact /32 selectors,
benchmark loopback address. It first stops only a UUID/executable/PodUID-cgroup
verified charon using hostPID, SYS_PTRACE and KILL capabilities. It never flushes
XFRM or changes routes, firewall, NAT or sysctls on the host. Node failure can delay recovery;
keep the recovery namespace until its completion is verified. Deadline expiry
alone does NOT clean host XFRM. A failed recovery is fatal, not a passing test.

Baseline: cold peer/customer initiation; all replicas initiating concurrently;
hard Floating IP move with old Pod alive; move back. Optional --extended adds
protected MTU probes, CHILD rekey, IKEv1 reauthentication and active owner Pod
restart after baseline. MTU requires DF payload 1200 both ways, observes DF
1400/1410, and requires fragmented payload 16000 where ping -M dont is supported.
Readiness means bidirectional VIP ICMP plus increasing IPsec counters, never just
ESTABLISHED. Test timers are NOT carrier/production recommendations. Mode udp
forces ESP-in-UDP (encap=yes), checks UDP4500 and kernel espinudp. It does not
simulate a translating NAT or claim NAT traversal interoperability. Neither mode
claims APN forwarding or carrier interoperability; selectors remain test VIP /32s.

The normal Flannel eth0 remains; only net1 has the test public /32. Standard
native CNI ipvlan/static/sbr configuration is reused from ipvlan_acceptance.py.
PSK exists only in memory and fresh Kubernetes Secrets (not evidence/configmaps).
Evidence contains infrastructure addresses; use a private output directory.

--approval-file is separately reviewed caller-owned mode-0600 JSON. Exact keys:
floating_ip_id (integer), floating_ip, floating_ip_name, owner_server_id (integer),
standby_server_id (integer), owner_node, standby_node, peer_node, peer_public_ip.
Values must exactly match CLI arguments. HCLOUD_TOKEN is read from environment.
The watchdog has no cloud token: controller SIGKILL/host loss can leave the FIP
on the standby. The parent must independently supervise cloud restoration then;
SIGINT/SIGTERM and ordinary exceptions run bounded restoration in finally.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from ipvlan_acceptance import nad, check_routes, prepare_evidence


# The recovery Pod shares the host PID namespace ONLY to stop this run's daemon.
# Every signal revalidates UUID, role, executable and Pod UID/cgroup membership.
STOP_OWNED_CHARON = r'''
owned_charon() {
  pid="$1"
  test "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "${EXPECTED_EXE:-/usr/libexec/ipsec/charon}" || return 1
  env=$(tr '\000' '\n' < "/proc/$pid/environ" 2>/dev/null) || return 1
  printf '%s\n' "$env" | /bin/grep -Fxq "ACCEPTANCE_RUN=$RUN_UUID" || return 1
  printf '%s\n' "$env" | /bin/grep -Fxq 'ACCEPTANCE_ROLE=peer' || return 1
  uid=$(printf '%s\n' "$env" | sed -n 's/^ACCEPTANCE_POD_UID=//p')
  test -n "$uid" || return 1
  printf '%s' "$uid" | /bin/grep -Eq '^[0-9a-f-]{36}$' || return 1
  cg=$(tr '-' '_' < "/proc/$pid/cgroup") || return 1
  normalized=$(printf '%s' "$uid" | tr '-' '_')
  printf '%s\n' "$cg" | /bin/grep -Fq "$normalized" || return 1
}
stop_owned() {
  for entry in /proc/[0-9]*; do
    pid=${entry##*/}
    if owned_charon "$pid"; then
      # Recheck immediately before the signal; never signal a remembered PID.
      if owned_charon "$pid"; then kill -TERM "$pid"; fi
    fi
  done
  sleep 2
  for entry in /proc/[0-9]*; do
    pid=${entry##*/}
    if owned_charon "$pid"; then
      if owned_charon "$pid"; then kill -KILL "$pid"; fi
    fi
  done
  sleep 1
  for entry in /proc/[0-9]*; do
    pid=${entry##*/}
    if owned_charon "$pid"; then echo 'Owned charon survived watchdog' >&2; return 1; fi
  done
  # An unreadable/unidentified live daemon must never be mistaken for stopped.
  if ss -H -u -a -n | awk '$4 ~ /:(500|4500)$/ { found=1 } END { exit !found }'; then
    echo 'IKE sockets remain; refusing XFRM cleanup' >&2
    return 1
  fi
}
stop_owned
'''

# ip prints multiline records. Match both the unique reqid AND exact endpoints;
# policies additionally require exact /32 selectors. Delete by recorded index,
# not a global flush or a wildcard selector. ip output contains no secret keys.
CLEANUP = r'''
set -eu
cleanup() {
  ip xfrm state list nokeys | awk -v req="$REQID" -v a="$PUBLIC_LOCAL" -v b="$PUBLIC_REMOTE" '
    function emit() { if (owned && ((src==a && dst==b)||(src==b && dst==a)) && spi!="") print src,dst,spi }
    /^src / { emit(); src=$2; dst=$4; owned=0; spi="" }
    /proto esp/ { for(i=1;i<=NF;i++) if($i=="spi") spi=$(i+1) }
    /reqid / { for(i=1;i<=NF;i++) if($i=="reqid" && $(i+1)==req) owned=1 }
    END { emit() }' | while read -r src dst spi; do
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi"
    done
  ip xfrm policy list | awk -v req="$REQID" -v a="$VIP_LOCAL/32" -v b="$VIP_REMOTE/32" '
    function emit() { if (owned && ((src==a && dst==b)||(src==b && dst==a)) && idx!="" && dir!="") print idx,dir }
    /^src / { emit(); src=$2; dst=$4; owned=0; idx=""; dir="" }
    /dir / { for(i=1;i<=NF;i++) { if($i=="dir") dir=$(i+1); if($i=="index") idx=$(i+1) } }
    /reqid / { for(i=1;i<=NF;i++) if($i=="reqid" && $(i+1)==req) owned=1 }
    END { emit() }' | while read -r idx dir; do
      ip xfrm policy delete index "$idx" dir "$dir"
    done
  # Presence checks make repeated cleanup safe without hiding delete failures.
  if ip -o addr show dev lo | /bin/grep -Fq "inet $VIP_LOCAL/32 "; then
    ip addr del "$VIP_LOCAL/32" dev lo
  fi
}
cleanup
states=$(ip xfrm state list nokeys)
policies=$(ip xfrm policy list)
if test -n "$states$policies"; then
  echo 'Host XFRM remains after scoped recovery; refusing foreign deletion' >&2
  exit 1
fi
addresses=$(ip -o addr show dev lo)
if printf '%s\\n' "$addresses" | /bin/grep -Fq "inet $VIP_LOCAL/32 "; then
  echo 'Owned VIP remains after recovery' >&2
  exit 1
fi
'''


def qualification_script(identity_probe):
    # Resolve the applet symlink in the exact peer image; /proc exposes real exe.
    return 'set -eu\nEXPECTED_EXE=$(readlink -f /usr/bin/tail)\n'+identity_probe+STOP_OWNED_CHARON


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ('execute', 'allow-test-fip-moves', 'allow-native-host-peer', 'extended'):
        p.add_argument('--'+flag, action='store_true')
    for flag in ('kubeconfig', 'peer-kubeconfig', 'owner-node', 'standby-node',
                 'peer-node', 'floating-ip', 'floating-ip-name', 'peer-public-ip',
                 'gateway', 'parent-interface', 'customer-vip', 'peer-vip',
                 'strongswan-image', 'tools-image', 'evidence-dir', 'approval-file'):
        p.add_argument('--'+flag, required=True)
    for flag in ('floating-ip-id', 'owner-server-id', 'standby-server-id'):
        p.add_argument('--'+flag, required=True, type=int)
    p.add_argument('--timeout', type=int, default=300, help='Total work deadline: 180..300 seconds; cleanup has 110s budget')
    p.add_argument('--failover-timeout', type=int, default=90, help='10..90 seconds')
    p.add_argument('--cold-timeout', type=int, default=40, help='10..40 seconds')
    p.add_argument('--encapsulation', choices=['native', 'udp'], default='native',
                   help='Native ESP or forced ESP-in-UDP over the same host peer topology')
    p.add_argument('--cni-version', choices=['1.1.0'], default='1.1.0')
    return p


def validate(a):
    for key in ('floating_ip', 'peer_public_ip', 'gateway', 'customer_vip', 'peer_vip'):
        v = ipaddress.ip_address(getattr(a, key))
        require(v.version == 4 and not (v.is_unspecified or v.is_multicast or v.is_loopback), 'Invalid '+key)
    benchmark = ipaddress.ip_network('198.18.0.0/15')
    require(all(ipaddress.ip_address(v) in benchmark for v in (a.customer_vip, a.peer_vip)), 'VIPs must be benchmark addresses in 198.18.0.0/15')
    require(a.customer_vip != a.peer_vip, 'VIPs must differ')
    require(len({a.floating_ip, a.peer_public_ip, a.gateway, a.customer_vip, a.peer_vip}) == 5, 'Addresses must differ')
    require(a.owner_node != a.standby_node, 'Customer nodes must differ')
    require(a.owner_server_id != a.standby_server_id, 'Server IDs must differ')
    require(all(x > 0 for x in (a.floating_ip_id, a.owner_server_id, a.standby_server_id)), 'IDs must be positive')
    require(re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', a.parent_interface), 'Invalid interface')
    for image in (a.strongswan_image, a.tools_image):
        require(re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', image), 'Images require immutable digests')
    require(180 <= a.timeout <= 300 and 10 <= a.failover_timeout <= 90 and 10 <= a.cold_timeout <= 40, 'Invalid deadline')
    if a.execute:
        require(a.allow_test_fip_moves and a.allow_native_host_peer, 'Both explicit mutation acknowledgements required')
        require(bool(os.environ.get('HCLOUD_TOKEN')), 'HCLOUD_TOKEN required')
        approval = Path(a.approval_file)
        require(not approval.is_symlink() and approval.is_file(), 'Approval must be a regular private file')
        require(approval.stat().st_mode & 0o077 == 0 and approval.stat().st_uid == os.getuid(), 'Approval must be caller-owned mode 0600')
        approved = json.loads(approval.read_text())
        for key in ('floating_ip_id', 'floating_ip', 'floating_ip_name', 'owner_server_id',
                    'standby_server_id', 'owner_node', 'standby_node', 'peer_node', 'peer_public_ip'):
            require(approved.get(key) == getattr(a, key), 'Private approval mismatch: '+key)


def swan_config(a, peer, psk, reqid, auto=False):
    local, remote = (a.peer_public_ip, a.floating_ip) if peer else (a.floating_ip, a.peer_public_ip)
    lv, rv = (a.peer_vip, a.customer_vip) if peer else (a.customer_vip, a.peer_vip)
    lid, rid = ('peer.acceptance.invalid', 'customer.acceptance.invalid') if peer else ('customer.acceptance.invalid', 'peer.acceptance.invalid')
    return f'''connections {{
  acceptance {{
    version = 1
    local_addrs = {local}
    remote_addrs = {remote}
    proposals = aes256-sha256-ecp384
    encap = {'yes' if a.encapsulation == 'udp' else 'no'}
    unique = replace
    keyingtries = 0
    dpd_delay = 2s
    dpd_timeout = 8s
    rekey_time = 0
    reauth_time = 0
    local {{ auth = psk
      id = {lid}
    }}
    remote {{ auth = psk
      id = {rid}
    }}
    children {{
      protected {{
        local_ts = {lv}/32
        remote_ts = {rv}/32
        esp_proposals = aes256-sha256-ecp384
        reqid = {reqid}
        start_action = {'start' if auto and not peer else 'none'}
        dpd_action = {'restart' if auto else 'clear'}
        close_action = {'start' if auto else 'none'}
        rekey_time = 45s
        life_time = 75s
        rand_time = 0s
      }}
    }}
  }}
}}
secrets {{
  ike-acceptance {{
    id-customer = customer.acceptance.invalid
    id-peer = peer.acceptance.invalid
    secret = {psk}
  }}
}}
'''


CHARON_CONFIG = '''charon {
  load_modular = yes
  delete_rekeyed = yes
  install_routes = no
  install_virtual_ip = no
  retransmit_timeout = 1
  retransmit_base = 1.5
  retransmit_tries = 3
  plugins {
    include /etc/strongswan.d/charon/*.conf
    kernel-netlink {
      install_routes = no
      install_virtual_ip = no
    }
  }
  start-scripts {
    load-all = /usr/sbin/swanctl --load-all --noprompt
  }
  filelog {
    stderr {
      default = 0
    }
  }
}
'''


def security(caps=()):
    return {'runAsUser': 0, 'allowPrivilegeEscalation': False,
            'capabilities': {'drop': ['ALL'], 'add': list(caps)},
            'seccompProfile': {'type': 'RuntimeDefault'}}


def peer_env(a, reqid, run_uuid):
    return [{'name': k, 'value': str(v)} for k, v in {
        'REQID': reqid, 'PUBLIC_LOCAL': a.peer_public_ip, 'PUBLIC_REMOTE': a.floating_ip,
        'VIP_LOCAL': a.peer_vip, 'VIP_REMOTE': a.customer_vip, 'RUN_UUID': run_uuid}.items()]


def recovery_pod(a, ns, reqid, run_uuid):
    # No API credentials or host mounts; hostPID permits verified daemon stop.
    # Controller death cannot rely on kubelet deadlines to remove kernel state.
    script = f'''set -eu
sleep {a.timeout+30}
if test -f /tmp/armed; then
{STOP_OWNED_CHARON}
{CLEANUP}
fi
touch /tmp/recovered
sleep 90
'''
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'recovery', 'namespace': ns},
            'spec': {'hostNetwork': True, 'hostPID': True, 'nodeName': a.peer_node, 'restartPolicy': 'Never',
                     'activeDeadlineSeconds': a.timeout+150, 'terminationGracePeriodSeconds': 2,
                     'automountServiceAccountToken': False, 'dnsPolicy': 'ClusterFirstWithHostNet',
                     'containers': [{'name': 'recovery', 'image': a.strongswan_image,
                                     'command': ['/bin/sh', '-ec', script], 'env': peer_env(a, reqid, run_uuid),
                                     'securityContext': security(['NET_ADMIN', 'SYS_PTRACE', 'KILL']),
                                     'readinessProbe': {'exec': {'command': ['/bin/sh', '-ec', 'test ! -f /tmp/recovered']}, 'periodSeconds': 2}}]}}


def endpoint_pod(a, ns, name, node, peer=False, run_uuid=None):
    lv = a.peer_vip if peer else a.customer_vip
    startup = 'set -eu\n'
    if peer:
        # Benign same-Pod process qualifies /proc identity and signals before any
        # host address, socket or XFRM mutation. Controller releases this gate.
        startup += '''/usr/bin/tail -f /dev/null &
touch /run/probe-ready
while ! test -f /run/allow-peer; do sleep 1; done
'''
    startup += f'ip addr add {lv}/32 dev lo\n'
    if not peer:
        startup += f'ip rule add pref 101 from {lv}/32 lookup 100\n'
    # Native ESP relies on the existing default route plus exact XFRM selectors.
    startup += '''/usr/libexec/ipsec/charon &
pid=$!
trap 'kill "$pid"; wait "$pid"' TERM INT
while ! test -S /run/charon.vici; do kill -0 "$pid"; sleep 1; done
/usr/sbin/swanctl --load-all --noprompt >/dev/null
touch /tmp/ready
wait "$pid"
'''
    spec = {'nodeName': node, 'restartPolicy': 'Never', 'activeDeadlineSeconds': a.timeout,
            'terminationGracePeriodSeconds': 5, 'automountServiceAccountToken': False,
            'volumes': [{'name': 'secret', 'secret': {'secretName': 'swan-peer' if peer else 'swan-customer', 'defaultMode': 256}},
                        {'name': 'run', 'emptyDir': {}}],
            'containers': [{'name': 'swan', 'image': a.strongswan_image,
                            'command': ['/bin/sh', '-ec', startup],
                            'securityContext': security(['NET_ADMIN', 'NET_RAW', 'NET_BIND_SERVICE']),
                            'volumeMounts': [{'name': 'secret', 'mountPath': '/etc/swanctl/swanctl.conf', 'subPath': 'swanctl.conf', 'readOnly': True},
                                             {'name': 'secret', 'mountPath': '/etc/strongswan.conf', 'subPath': 'strongswan.conf', 'readOnly': True},
                                             {'name': 'secret', 'mountPath': '/etc/swanctl/auto.conf', 'subPath': 'auto.conf', 'readOnly': True},
                                             {'name': 'run', 'mountPath': '/run'}],
                            'readinessProbe': {'exec': {'command': ['/bin/sh', '-ec', 'test -f /tmp/ready']}, 'periodSeconds': 1, 'timeoutSeconds': 2}}]}
    metadata = {'name': name, 'namespace': ns}
    if peer:
        require(bool(run_uuid), 'Peer requires a watchdog run UUID')
        spec['containers'][0]['env'] = [
            {'name': 'ACCEPTANCE_RUN', 'value': run_uuid},
            {'name': 'ACCEPTANCE_ROLE', 'value': 'peer'},
            {'name': 'ACCEPTANCE_POD_UID', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.uid'}}}]
        spec.update(hostNetwork=True, dnsPolicy='ClusterFirstWithHostNet')
    else:
        metadata['annotations'] = {'k8s.v1.cni.cncf.io/networks': json.dumps([{'name': 'acceptance-ipvlan', 'interface': 'net1'}])}
        # Tools image permits independent iproute observation on the same Pod NS.
        spec['containers'].append({'name': 'tools', 'image': a.tools_image,
                                   'command': ['/bin/sh', '-ec', 'sleep '+str(a.timeout)],
                                   'securityContext': security()})
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata, 'spec': spec}


def counters(raw):
    return tuple(sum(int(n) for n in re.findall(r'\b'+key+r'=(\d+)', raw))
                 for key in ('bytes-in', 'bytes-out', 'packets-in', 'packets-out'))


def spis(raw):
    return set(re.findall(r'\bspi-in=([0-9a-fA-F]+)', raw))


def sas_empty(raw):
    # CONNECTING/REKEYING are not a cold epoch either. Empty VICI replies have
    # no list-sa event at all; state= additionally handles abbreviated evidence.
    return not re.search(r'\blist-sa\s+event\b|\bstate=', raw)


def negotiated(raw, kernel, encapsulation='native'):
    for pattern in (r'version=1\b', r'state=ESTABLISHED', r'state=INSTALLED',
                    r'encr-alg=AES_CBC', r'encr-keysize=256',
                    r'integ-alg=HMAC_SHA2_256_128', r'dh-group=ECP_384'):
        require(re.search(pattern, raw), 'Missing negotiated '+pattern)
    require(encapsulation in ('native', 'udp'), 'Unknown encapsulation mode')
    if encapsulation == 'udp':
        for pattern in (r'\bencap=yes\b', r'\blocal-port=4500\b', r'\bremote-port=4500\b'):
            require(re.search(pattern, raw), 'Forced UDP epoch missing '+pattern)
        require('encap type espinudp' in kernel, 'Forced UDP epoch missing kernel ESP-in-UDP')
    else:
        require('encap=yes' not in raw and 'encap type espinudp' not in kernel, 'Native epoch unexpectedly negotiated NAT-T')
    require('proto esp' in kernel, 'No kernel ESP state')


class Run:
    def __init__(self, a):
        self.a = a
        self.start = time.monotonic()
        self.end = self.start+a.timeout
        self.reqid = secrets.randbelow(1_000_000_000)+1_000_000
        self.psk = secrets.token_hex(32)
        self.run_uuid = uuid.uuid4().hex
        self.ns = 'ipvlan-ipsec-'+self.run_uuid[:12]
        self.namespaces = []
        self.peer_created = False
        self.recovery_created = False
        self.host_touched = False
        self.initial_verified = False
        self.expected_owner = a.owner_server_id
        self.assignment_attempted = False
        self.lock = threading.Lock()
        self.last_success = {}
        self.evidence = {'success': False, 'encapsulation': a.encapsulation, 'reqid': self.reqid, 'events': [], 'samples': []}

    def remaining(self):
        value = self.end-time.monotonic()
        require(value > 0, 'Global deadline exceeded')
        return value

    def event(self, kind, **data):
        with self.lock:
            self.evidence['events'].append({'t': round(time.monotonic()-self.start, 3), 'kind': kind, **data})

    def kubectl(self, peer, args, obj=None, timeout=15, check=True):
        budget = min(timeout, self.remaining())
        cmd = ['kubectl', '--kubeconfig', self.a.peer_kubeconfig if peer else self.a.kubeconfig,
               '--request-timeout='+str(max(1, int(budget)))+'s']+args
        result = subprocess.run(cmd, input=json.dumps(obj) if obj is not None else None,
                                text=True, capture_output=True, timeout=budget)
        if check and result.returncode:
            # Never include submitted objects or Secret bodies in exceptions.
            raise RuntimeError('kubectl '+args[0]+' failed: '+result.stderr.replace(self.psk, '[REDACTED]')[:2000])
        return result

    def create(self, peer, obj):
        if obj['kind'] == 'Pod' and obj['metadata']['name'] != 'recovery':
            obj['spec']['activeDeadlineSeconds'] = max(1, int(self.remaining()))
        return json.loads(self.kubectl(peer, ['create', '-f', '-', '-o', 'json'], obj).stdout)

    def exec(self, name, command, peer=False, timeout=10, check=True, container='swan'):
        return self.kubectl(peer, ['-n', self.ns, 'exec', name, '-c', container, '--']+command, timeout=timeout, check=check)

    def swan(self, name, *args, peer=False, check=True):
        return self.exec(name, ['/usr/sbin/swanctl']+list(args), peer=peer, timeout=8, check=check).stdout

    def sas(self, name, peer=False):
        return self.swan(name, '--list-sas', '--raw', peer=peer)

    def ready(self, name, peer=False):
        self.kubectl(peer, ['-n', self.ns, 'wait', '--for=condition=Ready', 'pod/'+name, '--timeout=60s'], timeout=65)

    def cloud(self, method, path, body=None):
        require(path.startswith('/floating_ips/'+str(self.a.floating_ip_id)) or re.fullmatch(r'/actions/\d+', path), 'Unexpected cloud API path')
        request = urllib.request.Request('https://api.hetzner.cloud/v1'+path,
                    data=None if body is None else json.dumps(body).encode(), method=method,
                    headers={'Authorization': 'Bearer '+os.environ['HCLOUD_TOKEN'], 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=min(10, self.remaining())) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            raise RuntimeError('Cloud HTTP '+str(e.code)) from None

    def verify_fip(self, owner):
        fip = self.cloud('GET', '/floating_ips/'+str(self.a.floating_ip_id))['floating_ip']
        require(fip['id'] == self.a.floating_ip_id and fip['ip'] == self.a.floating_ip and
                fip['name'] == self.a.floating_ip_name and fip['server'] == owner,
                'Floating IP id/address/name/owner guard failed; refusing mutation')
        return fip

    def settle_actions(self, quiet_reads=1):
        stable = 0
        limit = time.monotonic()+min(40, self.remaining())
        while time.monotonic() < limit:
            actions = self.cloud('GET', '/floating_ips/'+str(self.a.floating_ip_id)+'/actions?status=running&per_page=50')['actions']
            stable = stable+1 if not actions else 0
            if stable >= quiet_reads:
                return
            time.sleep(1)
        raise RuntimeError('Floating IP actions failed to settle')

    def move(self, destination, force=False):
        require(destination in (self.a.owner_server_id, self.a.standby_server_id), 'Destination outside allowlist')
        self.settle_actions()
        self.verify_fip(self.expected_owner)
        if destination == self.expected_owner and not force:
            return
        self.event('move-request', old=self.expected_owner, new=destination)
        self.assignment_attempted = True  # BEFORE an ambiguous POST/timeout
        result = self.cloud('POST', '/floating_ips/'+str(self.a.floating_ip_id)+'/actions/assign', {'server': destination})
        # POST may succeed and lose its response. Cleanup re-reads owner and
        # restores only if identity and the two-member owner allowlist still match.
        self.expected_owner = destination
        action = result['action']['id']
        limit = time.monotonic()+min(40, self.remaining())
        while time.monotonic() < limit:
            state = self.cloud('GET', '/actions/'+str(action))['action']
            require(state['status'] != 'error', 'Cloud assignment action failed')
            if state['status'] == 'success':
                self.verify_fip(destination)
                self.event('move-complete', owner=destination)
                return
            time.sleep(.5)
        raise RuntimeError('Cloud assignment action timeout')

    def setup(self):
        for node, server in ((self.a.owner_node, self.a.owner_server_id), (self.a.standby_node, self.a.standby_server_id)):
            obj = json.loads(self.kubectl(False, ['get', 'node', node, '-o', 'json']).stdout)
            require(obj['spec'].get('providerID') == 'hcloud://'+str(server), 'Node/providerID mismatch: '+node)
        self.settle_actions()
        self.verify_fip(self.a.owner_server_id)
        self.initial_verified = True
        for peer in (False, True):
            obj = self.create(peer, {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
                'name': self.ns, 'labels': {
                    'acceptance-run': self.run_uuid,
                    'pod-security.kubernetes.io/enforce': 'privileged',
                    'pod-security.kubernetes.io/audit': 'privileged',
                    'pod-security.kubernetes.io/warn': 'privileged'}}})
            self.namespaces.append((peer, obj['metadata']['uid']))
            conf = swan_config(self.a, peer, self.psk, self.reqid)
            self.create(peer, {'apiVersion': 'v1', 'kind': 'Secret',
                              'metadata': {'name': 'swan-peer' if peer else 'swan-customer', 'namespace': self.ns},
                              'type': 'Opaque', 'data': {k: base64.b64encode(v.encode()).decode() for k, v in
                                                       {'swanctl.conf': conf, 'auto.conf': swan_config(self.a, peer, self.psk, self.reqid, auto=True), 'strongswan.conf': CHARON_CONFIG}.items()}})
        self.create(False, nad(self.a, self.ns))
        self.create(True, recovery_pod(self.a, self.ns, self.reqid, self.run_uuid))
        self.recovery_created = True
        self.ready('recovery', True)
        self.host_guard()
        # Arm autonomous recovery before any host mutation or peer launch.
        self.exec('recovery', ['/bin/sh', '-ec', 'touch /tmp/armed'], True, container='recovery')
        self.host_touched = True
        # Existing default route is sufficient for protected VIP traffic. No host
        # route, source rule, sysctl, firewall or virtual-IP install is performed.
        self.peer_created = True  # create may succeed even if its response is lost
        self.create(True, endpoint_pod(self.a, self.ns, 'peer', self.a.peer_node, True, self.run_uuid))
        limit = time.monotonic()+45
        while time.monotonic() < limit:
            if self.exec('peer', ['/bin/sh', '-ec', 'test -f /run/probe-ready'], True, check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Peer pre-mutation qualification gate timeout')
        identity_probe = STOP_OWNED_CHARON.rsplit('\nstop_owned\n', 1)[0]+'''
count=0
exe_candidates=0
readable_env=0
readable_cgroup=0
for entry in /proc/[0-9]*; do
  if test "$(readlink "$entry/exe" 2>/dev/null)" = "${EXPECTED_EXE:-/usr/libexec/ipsec/charon}"; then
    exe_candidates=$((exe_candidates+1))
    if test -r "$entry/environ"; then readable_env=$((readable_env+1)); fi
    if test -r "$entry/cgroup"; then readable_cgroup=$((readable_cgroup+1)); fi
  fi
  if owned_charon "${entry##*/}"; then count=$((count+1)); fi
done
if test "$count" != 1; then
  printf 'Process qualification failed: expected_exe=%s exe_candidates=%s readable_env=%s readable_cgroup=%s identity_matches=%s\\n' \\
    "${EXPECTED_EXE:-/usr/libexec/ipsec/charon}" "$exe_candidates" "$readable_env" "$readable_cgroup" "$count" >&2
  exit 1
fi
'''
        # /proc/PID/exe exposes the resolved binary, not the applet symlink.
        # Resolve inside the same immutable image that runs the peer process.
        qualification = qualification_script(identity_probe)
        self.exec('recovery', ['/bin/sh', '-ec', qualification], True, container='recovery', timeout=15)
        self.event('watchdog-signal-qualified-before-host-mutation')
        self.exec('peer', ['/bin/sh', '-ec', 'touch /run/allow-peer'], True)
        self.ready('peer', True)
        self.exec('recovery', ['/bin/sh', '-ec', identity_probe], True, container='recovery')
        self.event('watchdog-process-identity-verified')
        for name, node in (('owner', self.a.owner_node), ('standby', self.a.standby_node)):
            self.create(False, endpoint_pod(self.a, self.ns, name, node))
            self.ready(name)
            self.validate_customer_routes(name)
        self.event('setup-complete')

    def host_guard(self):
        def ip(*args):
            return self.exec('recovery', ['ip']+list(args), True, container='recovery').stdout
        require(not ip('xfrm', 'state', 'list', 'nokeys').strip(), 'Host already has XFRM states')
        require(not ip('xfrm', 'policy', 'list').strip(), 'Host already has XFRM policies')
        sockets = self.exec('recovery', ['ss', '-H', '-u', '-a', '-n'], True, container='recovery').stdout
        for line in sockets.splitlines():
            fields = line.split()
            require(len(fields) >= 5, 'Unexpected ss output')
            require(not re.search(r':(?:500|4500)$', fields[3]), 'Host UDP500/4500 already in use')
        addresses = json.loads(ip('-j', 'addr', 'show'))
        present = {x['local'] for interface in addresses for x in interface.get('addr_info', [])}
        require(self.a.peer_public_ip in present, 'Peer public IP not assigned to host')
        require(self.a.peer_vip not in present and self.a.customer_vip not in present, 'Benchmark VIP already assigned')
        routes = json.loads(ip('-j', 'route', 'show', 'table', 'all'))
        require(not any(r.get('dst') in (self.a.customer_vip, self.a.customer_vip+'/32', self.a.peer_vip, self.a.peer_vip+'/32') for r in routes), 'Benchmark route exists')
        self.event('host-guard-passed')

    def validate_customer_routes(self, name):
        def ip(*args):
            return json.loads(self.exec(name, ['ip', '-j']+list(args)).stdout)
        check_routes(ip('route', 'show', 'table', '100'), ip('rule'), self.a.floating_ip,
                     self.a.gateway, ip('route', 'show', 'table', 'main'))
        interfaces = ip('addr')
        addresses = {x['ifname']: [v['local'] for v in x.get('addr_info', [])] for x in interfaces}
        require(self.a.floating_ip in addresses.get('net1', []) and self.a.floating_ip not in addresses.get('eth0', []), 'Floating IP not exclusive to net1')
        self.event('customer-routes', pod=name, addresses=addresses)

    def initiate(self, name, peer=False):
        # This is asynchronous on the daemon; retry cadence is controller-bounded.
        self.swan(name, '--initiate', '--child', 'protected', '--timeout', '1', peer=peer, check=False)

    def cold(self):
        for name, peer in (('owner', False), ('standby', False), ('peer', True)):
            self.swan(name, '--terminate', '--ike', 'acceptance', '--timeout', '2', peer=peer, check=False)
        limit = time.monotonic()+10
        while time.monotonic() < limit:
            snapshots = [self.sas(n, p) for n, p in (('owner', False), ('standby', False), ('peer', True))]
            if all(sas_empty(raw) for raw in snapshots):
                self.event('cold-sas-empty')
                return
            time.sleep(.5)
        raise RuntimeError('Cold initiation precondition failed: old SAs remain')

    def health(self, name):
        before = [self.sas(name), self.sas('peer', True)]
        if not all('state=INSTALLED' in s for s in before):
            return False
        probe_times = []
        for n, local, remote, peer in ((name, self.a.customer_vip, self.a.peer_vip, False),
                                      ('peer', self.a.peer_vip, self.a.customer_vip, True)):
            started = time.monotonic()-self.start
            result = self.exec(n, ['ping', '-n', '-I', local, '-c', '1', '-W', '1', remote], peer, timeout=3, check=False)
            finished = time.monotonic()-self.start
            probe_times.append({'from': n, 'started': started, 'completed': finished, 'success': result.returncode == 0})
            if result.returncode:
                self.event('protected-probe-failure', probes=probe_times)
                return False
        after = [self.sas(name), self.sas('peer', True)]
        for old, new in zip(before, after):
            if not all(y > x for x, y in zip(counters(old), counters(new))):
                return False
        kernel = self.exec(name, ['ip', 'xfrm', 'state', 'list', 'nokeys']).stdout
        peer_kernel = self.exec('peer', ['ip', 'xfrm', 'state', 'list', 'nokeys'], True).stdout
        negotiated(after[0], kernel, self.a.encapsulation)
        negotiated(after[1], peer_kernel, self.a.encapsulation)
        self.last_success[name] = probe_times[-1]['completed']
        self.event('protected-data', pod=name, probes=probe_times, before=[counters(s) for s in before],
                   after=[counters(s) for s in after], customer_sas=after[0], peer_sas=after[1],
                   customer_xfrm_nokeys=kernel, peer_xfrm_nokeys=peer_kernel)
        return True

    def sample(self):
        row = {'t': round(time.monotonic()-self.start, 3)}
        for name in ('owner', 'standby'):
            row[name] = self.health(name)
            row[name+'_success_t'] = self.last_success.get(name) if row[name] else None
            raw = self.sas(name)
            row[name+'_installed'] = 'state=INSTALLED' in raw
            row[name+'_spis'] = sorted(spis(raw))
        row['active_count'] = sum(row[n] for n in ('owner', 'standby'))
        row['peer_sas'] = self.sas('peer', True)
        row['sequential_overlap_observation'] = row['active_count'] > 1
        # Probes are sequential and may straddle a cloud handover. Retain both
        # results with their timestamps; this does not prove concurrent readiness.
        # Settled acceptance still requires consecutive exclusive-owner samples.
        with self.lock:
            self.evidence['samples'].append(row)
        return row

    def wait_health(self, name, seconds, initiate=None):
        # Bound commands inside the last iteration too, not just loop starts.
        original_end = self.end
        self.end = min(self.end, time.monotonic()+seconds)
        consecutive = 0
        try:
            # One deliberate initiation per cold control, never per health poll.
            # Auto epochs call without this argument and rely only on charon.
            if initiate:
                for n, peer in initiate:
                    self.initiate(n, peer)
            while time.monotonic() < self.end:
                row = self.sample()
                consecutive = consecutive+1 if row[name] and row['active_count'] == 1 else 0
                if consecutive >= 2:
                    return row
                time.sleep(min(.5, max(0, self.end-time.monotonic())))
            raise RuntimeError('Data readiness timeout: '+name)
        finally:
            self.end = original_end

    def mtu(self, name):
        """Bounded protected-VIP ICMP payload/fragmentation checks, no forwarding."""
        for endpoint, local, remote, peer in (
                (name, self.a.customer_vip, self.a.peer_vip, False),
                ('peer', self.a.peer_vip, self.a.customer_vip, True)):
            for payload, pmtud, required in ((1200, 'do', True), (1400, 'do', False),
                                              (1410, 'do', False), (16000, 'dont', True)):
                command = ['ping', '-n', '-I', local, '-c', '1', '-W', '2', '-w', '4',
                           '-M', pmtud, '-s', str(payload), remote]
                started = time.monotonic()-self.start
                try:
                    result = self.exec(endpoint, command, peer, timeout=5, check=False)
                    code, stdout, stderr = result.returncode, result.stdout, result.stderr
                except subprocess.TimeoutExpired:
                    code, stdout, stderr = 124, '', 'Controller probe timeout (maximum 5s)'
                unsupported = (payload == 16000 and code != 0 and bool(re.search(
                    r'invalid option|unrecognized option|unknown option|bad value|invalid argument',
                    stdout+' '+stderr, re.IGNORECASE)))
                self.event('protected-mtu-probe', encapsulation=self.a.encapsulation,
                           endpoint=endpoint, source=local, destination=remote, payload=payload,
                           pmtud=pmtud, required=required, unsupported=unsupported,
                           started=started, completed=time.monotonic()-self.start,
                           returncode=code, stdout=stdout[:4000], stderr=stderr[:2000])
                require(not required or unsupported or code == 0,
                        'Required protected MTU probe failed: '+endpoint+' payload='+str(payload)+' mode='+pmtud)
        self.wait_health(name, 15)
        self.event('protected-mtu-complete', encapsulation=self.a.encapsulation,
                   scope='Benchmark VIP ICMP only; not APN forwarding or carrier interoperability')

    def lifecycle(self, name, ike=False):
        old = self.sas(name)
        pattern = r'initiator-spi=([0-9a-fA-F]+)' if ike else r'\bspi-in=([0-9a-fA-F]+)'
        old_spis = set(re.findall(pattern, old))
        require(bool(old_spis), 'No lifecycle SPI baseline')
        args = ['--rekey', '--ike', 'acceptance', '--reauth'] if ike else ['--rekey', '--child', 'protected']
        self.swan(name, *args)
        limit = time.monotonic()+40
        while time.monotonic() < limit:
            current = set(re.findall(pattern, self.sas(name)))
            if current-old_spis and not current & old_spis:
                self.wait_health(name, 15)
                self.event('ike-reauth' if ike else 'child-rekey', old=sorted(old_spis), new=sorted(current))
                return
            time.sleep(1)
        raise RuntimeError('Lifecycle SPI replacement timeout')

    def hard_move(self):
        # Keep old owner daemon and Pod running throughout the cloud move. A
        # probe worker samples while cloud requests block; errors are fatal.
        samples_start = len(self.evidence['samples'])
        require(self.sample()['owner'], 'No last-success baseline before move')
        peer_before = set(re.findall(r'initiator-spi=([0-9a-fA-F]+)', self.sas('peer', True)))
        require(bool(peer_before), 'Missing peer IKE SPI baseline')
        stop = threading.Event()
        failures = []
        def monitor():
            while not stop.is_set():
                try:
                    self.sample()
                except Exception as e:
                    failures.append(str(e))
                    break
                stop.wait(.5)
        worker = threading.Thread(target=monitor, name='data-health', daemon=True)
        worker.start()
        try:
            self.move(self.a.standby_server_id)
        finally:
            stop.set()
            worker.join(timeout=max(1, self.end-time.monotonic())+15)
        require(not worker.is_alive(), 'Health monitor failed to stop')
        require(not failures, 'Health monitor failed: '+str(failures))
        self.wait_health('standby', self.a.failover_timeout)
        peer_after = set(re.findall(r'initiator-spi=([0-9a-fA-F]+)', self.sas('peer', True)))
        require(bool(peer_after-peer_before), 'Peer IKE SPI did not change across hard move')
        self.event('hard-move-peer-spi', old=sorted(peer_before), new=sorted(peer_after))
        rows = self.evidence['samples'][samples_start:]
        old = [r['owner_success_t'] for r in rows if r['owner']]
        new = [r['standby_success_t'] for r in rows if r['standby']]
        require(bool(old) and bool(new), 'Failover lacks pre/post traffic observations')
        obj = json.loads(self.kubectl(False, ['-n', self.ns, 'get', 'pod', 'owner', '-o', 'json']).stdout)
        require(obj['status']['phase'] == 'Running', 'Old owner did not remain running')
        self.event('hard-move-data-gap', last_old_success=max(old), first_new_success=min(new),
                   observed_gap_seconds=min(new)-max(old), sampling_note='Intervals between successful bidirectional probe completions; sequential kubectl/ICMP/counter sampling has variable granularity. Not a bound on packet-level downtime.')

    def matrix(self):
        for label, initiators in (('peer-initiates', [('peer', True)]),
                                  ('customer-initiates', [('owner', False)]),
                                  ('all-replicas-initiate', [('owner', False), ('standby', False)])):
            self.cold()
            self.wait_health('owner', self.a.cold_timeout, initiators)
            self.event(label)
        # Planned epoch boundary: retire passive CHILD configs before loading
        # restart actions. Established CHILDs retain their original config.
        self.cold()
        self.swan('peer', '--load-conns', '--file', '/etc/swanctl/auto.conf', peer=True)
        for name in ('owner', 'standby'):
            self.swan(name, '--load-conns', '--file', '/etc/swanctl/auto.conf')
        self.event('autonomous-start-profiles-loaded')
        self.wait_health('owner', self.a.cold_timeout)
        self.event('autonomous-owner-steady-before-move')
        self.hard_move()
        self.move(self.a.owner_server_id)
        self.wait_health('owner', self.a.failover_timeout)
        self.event('return-move-data-ready')
        if self.a.extended:
            self.mtu('owner')
            self.lifecycle('owner')
            self.lifecycle('owner', True)
            self.kubectl(False, ['-n', self.ns, 'delete', 'pod', 'owner', '--wait=true', '--timeout=15s'], timeout=20)
            self.create(False, endpoint_pod(self.a, self.ns, 'owner', self.a.owner_node))
            self.ready('owner')
            self.swan('owner', '--load-conns', '--file', '/etc/swanctl/auto.conf')
            self.wait_health('owner', self.a.failover_timeout)
            self.event('owner-pod-restart')

    def cleanup(self):
        # Separate bounded teardown budget; restoration precedes deleting Pods.
        cleanup_end = time.monotonic()+110
        self.end = time.monotonic()+60  # reserve host recovery time
        errors = []
        if self.initial_verified:
            try:
                self.settle_actions(quiet_reads=3 if self.assignment_attempted else 1)
                fip = self.cloud('GET', '/floating_ips/'+str(self.a.floating_ip_id))['floating_ip']
                require(fip['id'] == self.a.floating_ip_id and fip['ip'] == self.a.floating_ip and
                        fip['name'] == self.a.floating_ip_name and
                        fip['server'] in (self.a.owner_server_id, self.a.standby_server_id), 'Restore identity/owner guard failed')
                self.expected_owner = fip['server']
                # An ambiguous prior POST must never turn an old-owner GET into
                # a no-op: issue an ordered assignment after running actions settle.
                self.move(self.a.owner_server_id, force=self.assignment_attempted)
                self.settle_actions(quiet_reads=3)
                for _ in range(3):
                    self.verify_fip(self.a.owner_server_id)
                    time.sleep(.5)
                self.event('restore-stable-owner-and-no-running-actions')
            except Exception as e:
                errors.append('RESTORE FAILED: '+str(e))
        self.end = cleanup_end
        # Do not delete recovery until peer termination AND scoped cleanup verified.
        peer_stopped = not self.peer_created
        if self.peer_created:
            try:
                self.kubectl(True, ['-n', self.ns, 'delete', 'pod', 'peer', '--ignore-not-found', '--wait=true', '--timeout=20s'], timeout=25)
                peer_stopped = True
            except Exception as e:
                errors.append('peer stop: '+str(e))
        recovered = not self.host_touched
        if self.host_touched:
            try:
                self.exec('recovery', ['/bin/sh', '-ec', 'set -eu\n'+STOP_OWNED_CHARON+'\n'+CLEANUP], True, timeout=20, container='recovery')
                state = self.exec('recovery', ['ip', 'xfrm', 'state', 'list', 'nokeys'], True, container='recovery').stdout
                policies = self.exec('recovery', ['ip', 'xfrm', 'policy', 'list'], True, container='recovery').stdout
                require(not state.strip() and not policies.strip(), 'Host XFRM nonempty after cleanup; no foreign state deletion attempted')
                addresses = self.exec('recovery', ['ip', '-o', 'addr', 'show', 'dev', 'lo'], True, container='recovery').stdout
                require('inet '+self.a.peer_vip+'/32 ' not in addresses, 'Owned VIP remains')
                self.event('host-cleanup-verified', states_nokeys=state, policies=policies)
                recovered = True
            except Exception as e:
                errors.append('HOST RECOVERY FAILED: '+str(e))
        for peer, uid in reversed(self.namespaces):
            if peer and (not recovered or not peer_stopped):
                errors.append('Recovery namespace retained: '+self.ns+'; verify host cleanup manually')
                continue
            try:
                self.kubectl(peer, ['delete', '--raw', '/api/v1/namespaces/'+self.ns, '-f', '-'],
                             {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}, 'propagationPolicy': 'Background'})
                self.kubectl(peer, ['wait', '--for=delete', 'namespace/'+self.ns, '--timeout=20s'], timeout=25)
            except Exception as e:
                errors.append('namespace cleanup: '+str(e))
        self.evidence['cleanup_errors'] = errors
        return errors


def execute(a):
    output = prepare_evidence(a.evidence_dir)
    r = Run(a)
    previous = {}
    def interrupted(signum, frame):
        raise RuntimeError('Interrupted by signal '+str(signum))
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, interrupted)
    try:
        r.setup()
        r.matrix()
        r.evidence['success'] = True
    except Exception as e:
        r.evidence['error'] = str(e).replace(r.psk, '[REDACTED]')
    finally:
        # Ignore repeated signals during the finite restoration/recovery window.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        errors = r.cleanup()
        r.evidence['success'] = r.evidence['success'] and not errors
        text = json.dumps(r.evidence, indent=2).replace(r.psk, '[REDACTED]')
        path = output/'result.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text+'\n')
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps({'success': r.evidence['success'], 'evidence': str(path), 'cleanup_errors': errors}))
    return 0 if r.evidence['success'] else 1


def main(argv=None):
    a = parser().parse_args(argv)
    try:
        validate(a)
        if not a.execute:
            print('REVIEW ONLY: no cluster/cloud calls. Native host peer + independent recovery; exact test FIP restoration; see module documentation and source before --execute.')
            return 0
        return execute(a)
    except Exception as e:
        print(type(e).__name__+': '+str(e), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
