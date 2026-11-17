#!/usr/bin/env python3
"""Review-first PUBLIC IPvlan/IPsec + Lease/WireGuard six-client acceptance.

Composes the existing IPsec controller and HA service builders without editing
or executing either standalone entrypoint. No API/subprocess without --execute;
all original approval-file, cloud identity, watchdog and host-absence guards
remain mandatory. Review this module's exact-selector cleanup extension before
execution. Only owner/standby nodes host customer workloads. The external peer
uses the existing guarded host namespace and an unprivileged Python sidecar.

Root XFRM selectors are peer VIP /32 versus exactly health VIP, two benchmark DNS
VIPs, broker test VIP and support-client VIP, each /32. IKEv1 uses FIVE separate
CHILDs, one exact selector pair each, with five unique reqids (base+0..4). Customer
start_action=trap|start prevents cleartext fallthrough during SA recovery. Rekey
is disabled for this service-only counter epoch, life_time=3600s; lifecycle was
tested separately. Pod/work deadline remains at most 300s. No default selector,
host route, firewall or sysctl changes. Recovery stops the verified owned daemon
then removes only approved-reqid+outer-tuple states and approved-reqid+outer-tuple+
exact-selector policies. The cloud
move is the original guarded test-IP-only assignment; restoration runs in finally.
No real carrier interoperability, tenant forwarding or translating NAT is claimed.

The same six clients (2 DNS, 3 HAProxy, support) must select the Lease-holder Pod
UID, with real IPsec benchmark-ping readiness independent of WG. Actual DNS UDP/
TCP, three authenticated MQTT/PROXYv2 paths and bidirectional support echo run
before and after the hard owner->standby->owner roundtrip. Existing customer and
peer Pods remain running, with UID/container identity checked after each move.
MQTT sockets may reconnect after handover; continuity is not claimed.

Each epoch records first observed Kubelet Swan Ready (after the configured ping
successes), Lease+WG readiness, all-six endpoint observations and completion of a
real DNS1 UDP probe. These are sequential controller/API observations, not packet
outage timestamps or guaranteed maxima. The extra observed interval includes
polling, exec and five-CHILD verification overhead; failed DNS attempts are kept.
Provider assignment-action acknowledgement and all-related-task settlement have
separate events: an implicit unassign can outlive the returned assignment task.
The existing bounded action/global deadlines remain strict; no cloud latency SLA
is inferred. On failure, a separate shared 15s read-only diagnostic budget saves
own Pod status, safe SA/XFRM metadata, routes/rules, logs and exact test-FIP action
history BEFORE ordinary restoration/host teardown. No Secret/spec/key dump occurs.
"""
import argparse
import base64
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import ipvlan_ipsec_acceptance as native

DNS_VIPS = ('198.18.51.2', '198.18.51.3')
BROKER_VIP = '192.0.2.80'
SUPPORT_VIP = '198.18.40.2'
GATEWAYS = ('owner', 'standby')
CHILDREN = ('protected', 'protected-dns-1', 'protected-dns-2', 'protected-broker', 'protected-support')


def load_services():
    # A private module instance: adapting benchmark constants cannot affect the
    # standalone acceptance module or another controller in this interpreter.
    spec = importlib.util.spec_from_file_location('public_ipvlan_ha_services',
              Path(__file__).with_name('ha_service_acceptance.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.GATEWAYS = GATEWAYS
    module.GATEWAY_INTERFACES = {'wg-dns', 'wg-broker', 'wg-transit'}
    module.base.DNS = list(DNS_VIPS)
    return module


services = load_services()


def selectors(a):
    values = (a.customer_vip, *DNS_VIPS, BROKER_VIP, SUPPORT_VIP)
    native.require(len(set(values)) == len(values) and a.peer_vip not in values,
                   'Protected test selectors must be distinct')
    return tuple(str(ipaddress.IPv4Address(value))+'/32' for value in values)


def expanded_cleanup(a):
    """Exact reqid set + /32 policy ownership/outer tuple; retain stop guards."""
    protected = selectors(a)
    old = '((src==a && dst==b)||(src==b && dst==a)) && idx!="" && dir!=""'
    dst = '('+' || '.join('dst=="'+value+'"' for value in protected)+')'
    src = '('+' || '.join('src=="'+value+'"' for value in protected)+')'
    new = '((src==a && '+dst+')||(dst==a && '+src+')) && idx!="" && dir!=""'
    native.require(native.CLEANUP.count(old) == 1, 'Upstream cleanup changed; review required')
    expanded = native.CLEANUP.replace(old, new)
    marker = 'ip xfrm policy list | awk -v req="$REQID" -v a="$VIP_LOCAL/32" -v b="$VIP_REMOTE/32"'
    native.require(expanded.count(marker) == 1, 'Upstream policy parser changed; review required')
    expanded = expanded.replace(marker, marker+' -v outer_a="$PUBLIC_LOCAL" -v outer_b="$PUBLIC_REMOTE"')
    prefix, policy = expanded.split('ip xfrm policy list', 1)
    reset = 'owned=0; idx=""; dir=""'
    reqid = '/reqid / { for(i=1;i<=NF;i++) if($i=="reqid" && $(i+1)==req) owned=1 }'
    native.require(policy.count(reset) == 1 and policy.count(reqid) == 1,
                   'Upstream policy ownership parser changed; review required')
    policy = policy.replace(reset, reset+'; tmpl_src=""; tmpl_dst=""')
    policy = policy.replace(reqid,
        '/tmpl src / { tmpl_src=$3; tmpl_dst=$5 }\n'
        '    /reqid / { for(i=1;i<=NF;i++) if($i=="reqid" && $(i+1)==req && '
        '((tmpl_src==outer_a && tmpl_dst==outer_b)||(tmpl_src==outer_b && tmpl_dst==outer_a))) owned=1 }')
    expanded = prefix+'ip xfrm policy list'+policy
    # Five IKEv1 CHILDs use five distinct reqids. Treat these as exact numeric
    # membership, never regex/substrings, on both state and policy records.
    native.require(expanded.count('-v req="$REQID"') == 2,
                   'Upstream XFRM parsers changed; review required')
    expanded = expanded.replace('-v req="$REQID"', '-v req="$REQID" -v reqids="$REQIDS"')
    initializer = '    BEGIN { n=split(reqids, ids, " "); for(i=1;i<=n;i++) approved_reqids[ids[i]]=1 }\n'
    native.require(expanded.count('    function emit()') == 2,
                   'Upstream XFRM record parser changed; review required')
    expanded = expanded.replace('    function emit()', initializer+'    function emit()')
    native.require(expanded.count('$(i+1)==req') == 2, 'Upstream reqid filter changed; review required')
    return expanded.replace('$(i+1)==req', 'approved_reqids[$(i+1)]')


def expand_profile(a, text, peer):
    # IKEv1 does not negotiate a comma-separated selector set without extensions.
    # Generate one native strongSwan CHILD stanza for each exact selector pair.
    matches = list(re.finditer(r'(?ms)^      protected \{\n.*?^      \}', text))
    native.require(len(matches) == 1, 'Upstream CHILD profile changed; review required')
    original = matches[0].group()
    reqids = re.findall(r'(?m)^        reqid = (\d+)$', original)
    native.require(len(reqids) == 1, 'Upstream CHILD reqid changed; review required')
    base_reqid = int(reqids[0])
    field = 'remote_ts' if peer else 'local_ts'
    old = field+' = '+a.customer_vip+'/32'
    native.require(original.count(old) == 1, 'Upstream selector profile changed; review required')
    children = []
    for index, (name, selector) in enumerate(zip(CHILDREN, selectors(a))):
        child = original.replace('protected {', name+' {', 1).replace(old, field+' = '+selector)
        child = child.replace('reqid = '+str(base_reqid), 'reqid = '+str(base_reqid+index))
        # Lifecycle was proven separately. Keep counter windows stable during
        # this service-only phase; Pod/global work deadline remains 300s.
        child = child.replace('rekey_time = 45s', 'rekey_time = 0').replace('life_time = 75s', 'life_time = 3600s')
        if not peer:
            child = child.replace('start_action = start', 'start_action = trap|start')
        children.append(child)
    return text[:matches[0].start()]+'\n'.join(children)+text[matches[0].end():]


def installed_children(raw, reqids):
    found = {}
    for block in re.findall(r'\{([^{}]*)\}', raw):
        name = re.search(r'\bname=([^\s{}]+)', block)
        reqid = re.search(r'\breqid=(\d+)\b', block)
        if not name or name.group(1) not in CHILDREN or 'state=INSTALLED' not in block:
            continue
        name = name.group(1)
        native.require(name not in found, 'Duplicate installed service CHILD: '+name)
        native.require(reqid and int(reqid.group(1)) == reqids[CHILDREN.index(name)],
                       'Unexpected service CHILD reqid: '+name)
        found[name] = {'reqid': int(reqid.group(1)), 'counters': native.counters(block),
                       'spis': sorted(native.spis(block))}
    native.require(set(found) == set(CHILDREN), 'All five exact-selector CHILDs must be installed')
    return found


def parser():
    p = native.parser()
    p.description = __doc__
    for name in ('wg-image', 'probe-image', 'unbound-image', 'haproxy-image', 'broker-image'):
        p.add_argument('--'+name, required=True)
    return p


def validate(a):
    native.validate(a)
    selectors(a)
    native.require(not a.extended, 'This service roundtrip does not repeat standalone lifecycle/MTU tests')
    for name in ('wg_image', 'probe_image', 'unbound_image', 'haproxy_image', 'broker_image'):
        native.require(re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', getattr(a, name)), 'Immutable image required: '+name)
    expanded_cleanup(a)  # fail closed on upstream changes, before any execution


class ServiceHarness(services.Harness):
    def __init__(self, controller):
        # Do not call the standalone constructor (it mutates args and creates an
        # output directory). NativeRun exclusively owns output/deadline/cleanup.
        self.controller = controller
        self.a = copy.copy(controller.a)
        self.a.fault_tests = False  # fault injection belongs to standalone internal harness
        self.a.nodes = [self.a.owner_node, self.a.standby_node, self.a.owner_node]
        self.ns, self.token = controller.ns, controller.run_uuid
        self.sensitive = []
        self.result = {'scope': {'public_ipsec': True, 'synthetic_remote_lan': False},
                       'trace': [], 'dataplane': []}
        self.gateway_templates = {}
        self.remote_ip = self.a.gateway  # discarded synthetic init-container input
        self.fresh_client_template = None
        self.cleaning = False
        self.namespace_uid = None
        self.created = False
        # The loaded service module is private to this composed controller.
        services.base.APN = self.a.peer_vip

    def run(self, argv, data=None, timeout=45, allow=False):
        native.require(self.a.execute, '--execute required')
        result = subprocess.run(argv, input=data, text=True, capture_output=True,
                                timeout=min(timeout, self.controller.remaining()))
        if result.returncode and not allow:
            raise RuntimeError('Service subprocess failed: '+self.redact(result.stderr[-2000:]))
        return result.stdout+('\n[stderr]\n'+result.stderr if allow and result.stderr else '')+(
            '\n[exit code: '+str(result.returncode)+']\n' if allow and result.returncode else '')

    def k(self, *args, data=None, timeout=20, allow=False):
        args = list(args)
        peer = bool(args and args[0] == 'exec' and 'provider' in args)
        if peer:
            args[args.index('provider')] = 'peer'
        result = self.controller.kubectl(peer, args, json.loads(data) if data else None,
                                         timeout=timeout, check=not allow)
        return result.stdout+('\n[exit code: '+str(result.returncode)+']\n' if allow and result.returncode else '')

    def wait(self, fn, message):
        limit = min(self.controller.end, time.monotonic()+self.a.failover_timeout)
        last = None
        while time.monotonic() < limit:
            try:
                value = fn()
                if value:
                    return value
            except (RuntimeError, AssertionError, KeyError, json.JSONDecodeError) as error:
                last = type(error).__name__+': '+str(error)[:200]
            time.sleep(.5)
        raise RuntimeError('Service readiness timeout: '+message+'; '+str(last))

    def apply(self, objects):
        for original in objects:
            obj = copy.deepcopy(original)
            name = obj['metadata']['name']
            if name == 'provider':
                native.require(obj['kind'] in ('ConfigMap', 'Secret', 'Service'), 'Synthetic provider Pod unexpectedly generated')
                continue
            if obj['kind'] == 'Secret' and name == 'gateway':
                obj.get('data', {}).pop('gl', None)
            if obj['kind'] == 'Service' and name == 'gateway':
                obj['spec']['ports'] = [port for port in obj['spec']['ports'] if port['port'] != 51824]
            if obj['kind'] == 'ConfigMap' and name == 'gateway':
                config = json.loads(obj['data']['config.yaml'])
                config['interfaces'] = [iface for iface in config['interfaces'] if iface['name'] != 'wg-lan']
                native.require({iface['name'] for iface in config['interfaces']} == services.GATEWAY_INTERFACES,
                               'Public gateway must have exactly three service WG interfaces')
                config['activation']['kubernetesLease']['requireReadyContainers'] = ['swan']
                forwarding = config['forwarding']
                forwarding['externalInterfaces'] = ['net1']
                for rule in forwarding['rules']+forwarding['dnat']:
                    for field in ('from', 'to'):
                        if rule.get(field) in ('eth0', 'wg-lan'):
                            rule[field] = 'net1'
                obj['data']['config.yaml'] = json.dumps(config)
            if obj['kind'] == 'Pod' and obj['metadata']['name'] in GATEWAYS:
                self.gateway_templates[obj['metadata']['name']] = obj
                continue
            self.controller.create(False, obj)
            if obj['kind'] in ('Secret', 'ConfigMap') and obj['metadata']['name'] in ('probe', 'mqtt-auth'):
                self.controller.create(True, copy.deepcopy(obj))

    def provider_resources(self, objects, config):
        # The external peer is NativeRun's guarded IPsec host peer, not a seventh
        # WG consumer or synthetic LAN Pod. Builder-generated provider CM/key/
        # Service objects are also discarded by apply().
        native.require([iface['name'] for iface in config['interfaces']] == ['wg-lan'],
                       'Synthetic provider builder changed; review required')

    def bootstrap(self):
        role = self.resource('Role', 'discovery', rules=[
            {'apiGroups': [''], 'resources': ['pods', 'services'], 'verbs': ['get', 'list', 'watch']},
            {'apiGroups': ['discovery.k8s.io'], 'resources': ['endpointslices'], 'verbs': ['get', 'list', 'watch']},
            {'apiGroups': ['coordination.k8s.io'], 'resources': ['leases'],
             'verbs': ['get', 'list', 'watch', 'create', 'update', 'patch']}])
        role['apiVersion'] = 'rbac.authorization.k8s.io/v1'
        binding = self.resource('RoleBinding', 'discovery', subjects=[
            {'kind': 'ServiceAccount', 'name': 'wg-link', 'namespace': self.ns}],
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'discovery'})
        binding['apiVersion'] = 'rbac.authorization.k8s.io/v1'
        probe = services.base.PROBE.replace("('0.0.0.0',18082)", '('+repr(self.a.peer_vip)+',18082)')
        # Peer-only listeners are benchmark-bound, never wildcard host listeners.
        peer_probe = probe.replace("s.bind(('0.0.0.0',port))", 's.bind(('+repr(self.a.peer_vip)+',port))')
        mqtt = services.base.MQTT_PROBE.replace("source='198.18.10.2'", 'source='+repr(self.a.peer_vip))
        unbound = services.UNBOUND.replace('198.18.10.2/32', self.a.peer_vip+'/32')
        objects = [self.resource('ServiceAccount', 'wg-link'), role, binding,
            self.resource('ConfigMap', 'probe', data={'probe.py': services.base.PROBE,
                'peer.py': peer_probe, 'dns.py': services.DNS_PROBE, 'mqtt.py': mqtt}),
            self.resource('ConfigMap', 'unbound', data={'unbound.conf': unbound})]
        self.broker_resources(objects)
        self.apply(objects)
        # Reuse native WG keygen, configs, real DNS/HAProxy/VerneMQ builders.
        self.topology()
        native.require(set(self.gateway_templates) == set(GATEWAYS), 'Service gateway builder changed')

    def snapshot(self):
        lease = self.obj('lease', services.LEASE)
        holder = lease['spec'].get('holderIdentity')
        pods = [self.obj('pod', name) for name in GATEWAYS]
        def ready(pod, container):
            return any(c.get('name') == container and c.get('ready')
                       for c in pod.get('status', {}).get('containerStatuses', []))
        healthy = [p['metadata']['name'] for p in pods if ready(p, 'swan')]
        active = [p for p in pods if p['metadata']['uid'] == holder and ready(p, 'swan') and ready(p, 'wg-link')]
        value = {'time': time.monotonic(), 'healthy': healthy,
                 'active': active[0]['metadata']['name'] if active else None, 'holder_uid': holder,
                 'staleReady': [p['metadata']['name'] for p in pods if ready(p, 'wg-link') and p not in active]}
        self.result['trace'].append(value)
        return value

    def settled(self, expected):
        value = self.snapshot()
        return value if value['active'] == expected and value['healthy'] == [expected] else False

    def sessions(self, flows):
        # Explicit source expectation belongs to this composed phase, not the
        # separately imported standalone BrokerAcceptance module's APN constant.
        rows = {name: self.session_rows(int(name.rsplit('-', 1)[1])) for name, _ in services.BROKER_PATHS}
        evidence = {}
        for flow in flows:
            name, port = services.BROKER_PATHS[int(flow['client_id'].rsplit('-', 1)[1]) % 3]
            matching = [row for row in rows[name] if row['client_id'] == flow['client_id']]
            native.require(len(matching) == 1, 'Expected actual VerneMQ session: '+flow['client_id'])
            row = matching[0]
            native.require(row['peer_host'] == self.a.peer_vip, 'VerneMQ PROXYv2 source IP mismatch')
            native.require(row['is_online'] in (True, 'true'), 'VerneMQ session not online')
            evidence[flow['client_id']] = {'broker': name, 'destination_port': port,
                **{key: row[key] for key in ('peer_host', 'session_pid', 'session_started_at')}}
        return evidence

    def dataplane(self, active, frozen=None):
        # No provider routes: real decrypted /32 traffic enters net1 and traverses WG.
        self.gates(active)
        endpoints = self.endpoints(active)
        for source, pod in ((self.a.peer_vip, 'provider'), (SUPPORT_VIP, 'support-client')):
            for server in DNS_VIPS:
                for transport in ('udp', 'tcp'):
                    self.exec(pod, 'probe', 'python', '/probe/dns.py', source, server,
                              transport, 'allowed.example', '192.0.2.123', '1')
        self.echo('support-client', self.a.peer_vip, source=SUPPORT_VIP)
        self.echo('provider', SUPPORT_VIP, source=self.a.peer_vip)
        opened = None
        try:
            opened = self.mqtt('open', prefix='public-'+self.token[:8], count=3, interval=0)
            native.require(opened['established'] == 3 and not opened['errors'], 'MQTT connections failed')
            flows = self.held_check(opened['flows'])
            sessions = self.sessions(flows)
        finally:
            self.mqtt('close')
        record = {'active': active, 'endpoints': endpoints, 'dns_udp_tcp': True,
                  'support_bidirectional': True, 'mqtt': flows, 'broker_sessions': sessions}
        self.result['dataplane'].append(record)
        return record


class Run(native.Run):
    def __init__(self, a):
        super().__init__(a)
        self.reqids = tuple(self.reqid+index for index in range(len(CHILDREN)))
        self.cleanup_script = expanded_cleanup(a)
        self.services = ServiceHarness(self)
        self.bootstrapped = False
        self.evidence['scope'] = 'Public IPsec with six Lease-selected service clients'
        self.evidence['reqids'] = self.reqids
        self.evidence['protected_selectors'] = {'peer': a.peer_vip+'/32', 'customer': selectors(a)}

    def kubectl(self, peer, args, obj=None, timeout=15, check=True):
        native.require(self.a.execute, '--execute required for Kubernetes I/O')
        return super().kubectl(peer, args, obj, timeout, check)

    def create(self, peer, obj):
        obj = copy.deepcopy(obj)
        kind, name = obj['kind'], obj['metadata']['name']
        if kind == 'Secret' and name in ('swan-peer', 'swan-customer'):
            # Start AUTO immediately; no directional/lifecycle controls in this phase.
            original = base64.b64decode(obj['data']['auto.conf']).decode()
            expanded = expand_profile(self.a, original, peer)
            encoded = base64.b64encode(expanded.encode()).decode()
            obj['data']['swanctl.conf'] = obj['data']['auto.conf'] = encoded
        if kind == 'NetworkAttachmentDefinition' and not self.bootstrapped:
            self.bootstrapped = True
            self.services.bootstrap()
        if kind == 'Pod' and name == 'recovery':
            obj['spec']['containers'][0]['env'].append({'name': 'REQIDS', 'value': ' '.join(map(str, self.reqids))})
            command = obj['spec']['containers'][0]['command']
            native.require(command[-1].count(native.CLEANUP) == 1, 'Recovery builder changed')
            command[-1] = command[-1].replace(native.CLEANUP, self.cleanup_script)
            # Service/key setup precedes helper creation. Preserve the ORIGINAL
            # absolute global recovery deadline, rather than restarting 300s now.
            initial_sleep = 'sleep '+str(self.a.timeout+30)+'\n'
            native.require(command[-1].count(initial_sleep) == 1, 'Recovery deadline builder changed')
            remaining = max(1, int(self.remaining()))
            command[-1] = command[-1].replace(initial_sleep, 'sleep '+str(remaining+30)+'\n')
            obj['spec']['activeDeadlineSeconds'] = remaining+150
        if kind == 'Pod' and name == 'peer':
            spec = obj['spec']
            spec['volumes'] += [{'name': 'probe', 'configMap': {'name': 'probe'}},
                                {'name': 'mqtt-auth', 'secret': {'secretName': 'mqtt-auth'}}]
            boot = '''import os,runpy,socket,subprocess,time
end=time.monotonic()+int(os.environ['BUDGET'])
while time.monotonic()<end:
 try:
  s=socket.socket();s.bind((os.environ['SOURCE'],0));s.close();break
 except OSError:time.sleep(.2)
else:raise RuntimeError('Peer VIP did not become available')
subprocess.Popen(['python','/probe/mqtt.py'])
runpy.run_path('/probe/peer.py',run_name='__main__')
'''
            spec['containers'].append({'name': 'probe', 'image': self.a.probe_image,
                'command': ['python', '-u', '-c', boot], 'securityContext': native.security(),
                'env': [{'name': 'SOURCE', 'value': self.a.peer_vip}, {'name': 'BUDGET', 'value': str(min(45, self.a.timeout))}],
                'volumeMounts': [{'name': 'probe', 'mountPath': '/probe', 'readOnly': True},
                                 {'name': 'mqtt-auth', 'mountPath': '/mqtt-auth', 'readOnly': True}]})
        if kind == 'Pod' and name in GATEWAYS:
            template = self.services.gateway_templates[name]
            spec = obj['spec']
            spec['serviceAccountName'] = 'wg-link'
            spec['automountServiceAccountToken'] = True
            spec['containers'].append(copy.deepcopy(template['spec']['containers'][0]))
            spec['volumes'] += copy.deepcopy(template['spec']['volumes'])
            obj['metadata']['labels'] = dict(template['metadata']['labels'], app='gateway')
            swan = spec['containers'][0]
            swan['readinessProbe'] = {'exec': {'command': ['ping', '-n', '-I', self.a.customer_vip,
                '-c', '1', '-W', '1', self.a.peer_vip]}, 'periodSeconds': 1, 'timeoutSeconds': 2,
                'failureThreshold': 3, 'successThreshold': 2}
            # Returned service sources must take table100 toward the protected
            # destination. This is inside the customer Pod only, not a host rule.
            script = swan['command'][-1]
            marker = '/usr/libexec/ipsec/charon &'
            native.require(script.count(marker) == 1, 'Customer launcher changed')
            swan['command'][-1] = script.replace(marker,
                'ip rule add pref 102 to '+self.a.peer_vip+'/32 lookup 100\n'+marker)
        return super().create(peer, obj)

    def exec(self, name, command, peer=False, timeout=10, check=True, container='swan'):
        command = [part.replace(native.CLEANUP, self.cleanup_script) for part in command]
        return super().exec(name, command, peer, timeout, check, container)

    def ready(self, name, peer=False):
        if peer or name not in GATEWAYS:
            return super().ready(name, peer)
        # Standby WG is intentionally not Ready; neither WG nor data readiness
        # may prevent creating the second candidate. Only wait daemon startup.
        limit = min(self.end, time.monotonic()+45)
        while time.monotonic() < limit:
            result = self.exec(name, ['/bin/sh', '-ec', 'test -f /tmp/ready'], check=False)
            if result.returncode == 0:
                return
            time.sleep(.5)
        raise RuntimeError('Customer charon startup timeout: '+name)

    def host_guard(self):
        super().host_guard()
        raw = self.exec('recovery', ['ss', '-H', '-l', '-t', '-u', '-n'], True, container='recovery').stdout
        for line in raw.splitlines():
            fields = line.split()
            native.require(len(fields) >= 5, 'Unexpected listener output')
            native.require(not re.search(r':(?:18080|18081|18082|18083)$', fields[4] if fields[0] in ('tcp', 'udp') else fields[3]),
                           'Host benchmark probe port already in use')

    def move(self, destination, force=False):
        assigning = force or destination != self.expected_owner
        super().move(destination, force=force)
        if assigning:
            self.event('provider-assignment-acknowledged', owner=destination,
                       meaning='Returned assignment action succeeded and owner GET matched; implicit sibling tasks may still run')
        try:
            # One assignment may create an implicit unassign task as well. The
            # returned assignment action alone does not prove provider idleness.
            self.settle_actions(quiet_reads=3)
            self.verify_fip(destination)
        except Exception as error:
            self.event('provider-related-tasks-not-settled', owner=destination, error=str(error))
            raise RuntimeError('Provider assignment acknowledged but related Floating IP tasks did not settle: '+str(error)) from error
        self.event('provider-all-tasks-settled', owner=destination,
                   meaning='Three quiet reads of all running test-FIP actions plus verified owner; no provider latency maximum claimed')

    def diagnostic_cloud_get(self, path):
        native.require(self.a.execute, '--execute required for diagnostic cloud reads')
        root = '/floating_ips/'+str(self.a.floating_ip_id)
        native.require(path in (root, root+'/actions?per_page=10&sort=id:desc',
                                root+'/actions?status=running&per_page=50'),
                       'Diagnostic path outside exact approved Floating IP')
        request = native.urllib.request.Request('https://api.hetzner.cloud/v1'+path, method='GET',
                  headers={'Authorization': 'Bearer '+os.environ['HCLOUD_TOKEN']})
        try:
            with native.urllib.request.urlopen(request, timeout=min(2, self.remaining())) as response:
                body, status = json.load(response), response.status
        except native.urllib.error.HTTPError as error:
            result = {'http_status': error.code, 'error': str(error.reason)}
            error.close()
            return result
        if path == root:
            item = body['floating_ip']
            return {'http_status': status, 'floating_ip': {key: item.get(key) for key in ('id', 'ip', 'name', 'server')}}
        fields = ('id', 'command', 'status', 'started', 'finished', 'progress', 'error')
        return {'http_status': status, 'actions': [{key: item.get(key) for key in fields} for item in body['actions']]}

    def diagnostics(self):
        """Failure-only read-only snapshots, at most 15s total before teardown."""
        original_end = self.end
        started = time.monotonic()
        deadline = started+15
        report = {'started': started-self.start, 'budget_seconds': 15, 'snapshots': {},
                  'scope': 'Own test Pods/status only, safe SA metadata/XFRM nokeys, exact approved FIP GETs; no Secrets/spec/env/config/key dumps'}
        self.evidence['failure_diagnostics'] = report
        def text(value):
            return self.services.redact(str(value)).replace(self.psk, '[REDACTED]')
        def safe(value):
            return json.loads(text(json.dumps(value)))
        def capture(label, callback, cap=2):
            now = time.monotonic()
            if now >= deadline:
                report['snapshots'][label] = {'skipped': 'shared 15s diagnostic deadline exhausted'}
                return
            self.end = min(deadline, now+cap)
            try:
                report['snapshots'][label] = safe(callback())
            except Exception as error:
                report['snapshots'][label] = {'error_type': type(error).__name__, 'error': text(error)}
            finally:
                self.end = deadline
        def kube(peer, args):
            result = self.kubectl(peer, args, timeout=2, check=False)
            return {'returncode': result.returncode, 'stdout': text(result.stdout)[:65536],
                    'stderr': text(result.stderr)[:8192]}
        commands = [('sas', ['/usr/sbin/swanctl', '--list-sas', '--raw']),
                    ('xfrm_state_nokeys', ['ip', 'xfrm', 'state', 'list', 'nokeys']),
                    ('xfrm_policy', ['ip', 'xfrm', 'policy', 'list']),
                    ('rules', ['ip', '-j', 'rule', 'show']),
                    ('routes', ['ip', '-j', 'route', 'show', 'table', 'all'])]
        def network(name, peer):
            parts = commands+([('loopback', ['ip', '-j', 'addr', 'show', 'dev', 'lo'])] if peer else [])
            script = '\n'.join("printf '\\n-- %s --\\n' "+shlex.quote(label)+'; '+shlex.join(command)+
                               "; rc=$?; printf '\\n[exit code: %s]\\n' \"$rc\"" for label, command in parts)
            result = self.exec(name, ['/bin/sh', '-c', script], peer, timeout=2, check=False)
            return {'returncode': result.returncode, 'stdout': text(result.stdout)[:65536],
                    'stderr': text(result.stderr)[:8192]}
        try:
            for name, peer in (('owner', False), ('standby', False), ('peer', True)):
                capture(name+'_network', lambda name=name, peer=peer: network(name, peer))
            root = '/floating_ips/'+str(self.a.floating_ip_id)
            capture('floating_ip', lambda: self.diagnostic_cloud_get(root))
            capture('recent_actions', lambda: self.diagnostic_cloud_get(root+'/actions?per_page=10&sort=id:desc'))
            capture('running_actions', lambda: self.diagnostic_cloud_get(root+'/actions?status=running&per_page=50'))
            for name, peer in (('owner', False), ('standby', False), ('peer', True)):
                capture(name+'_status', lambda name=name, peer=peer: kube(peer,
                    ['-n', self.ns, 'get', 'pod', name, '-o', 'jsonpath={.status}']))
            capture('lease_spec', lambda: kube(False,
                    ['-n', self.ns, 'get', 'lease', services.LEASE, '-o', 'jsonpath={.spec}']))
            for name, peer in (('owner', False), ('standby', False), ('peer', True)):
                capture(name+'_swan_logs', lambda name=name, peer=peer: kube(peer,
                    ['-n', self.ns, 'logs', name, '-c', 'swan', '--tail=80', '--timestamps=true']))
        finally:
            report['completed'] = time.monotonic()-self.start
            report['elapsed_seconds'] = time.monotonic()-started
            self.end = original_end
        return report

    def identities(self):
        result = {}
        for name, peer in (('owner', False), ('standby', False), ('peer', True)):
            pod = json.loads(self.kubectl(peer, ['-n', self.ns, 'get', 'pod', name, '-o', 'json']).stdout)
            native.require(pod['status']['phase'] == 'Running', 'Old test Pod no longer running')
            result[name] = {'uid': pod['metadata']['uid'], 'containers': {
                c['name']: (c.get('containerID'), c.get('restartCount')) for c in pod['status']['containerStatuses']}}
        return result

    def observe_stages(self, expected, children):
        service = self.services
        stages = {'expected': expected, 'epoch_started': time.monotonic()-self.start,
                  'tXfrmReadyObservation': None, 'tSwanReadyObservation': None,
                  'tPodLeaseWGReady': None, 'tEndpointsObserved': None,
                  'tFirstDNSProbeCompleted': None, 'dns_attempts': [],
                  'measurement': 'Sequential controller/API observations, not packet outage or a guaranteed maximum. XfrmReady means Kubelet swan container Ready after configured ping successes; intervals include polling, exec and five-CHILD verification overhead.'}
        self.evidence.setdefault('observed_service_stages', []).append(stages)
        def settled():
            value = service.snapshot()
            observed = time.monotonic()-self.start
            if expected in value['healthy'] and stages['tSwanReadyObservation'] is None:
                stages['tSwanReadyObservation'] = stages['tXfrmReadyObservation'] = observed
            if value['active'] == expected and value['healthy'] == [expected]:
                stages['tPodLeaseWGReady'] = observed
                return value
            return False
        service.wait(settled, 'IPsec-ready Lease holder '+expected)
        endpoints = service.wait(lambda: service.endpoints(expected), 'all six endpoints for '+expected)
        native.require(set(endpoints) == set(services.CLIENTS), 'Expected all six service endpoint observations')
        stages['tEndpointsObserved'] = time.monotonic()-self.start
        stages['endpoints'] = endpoints
        counters_before = service.wait(children, 'five installed CHILDs for '+expected)
        def dns_probe():
            attempt = {'started': time.monotonic()-self.start}
            stages['dns_attempts'].append(attempt)
            try:
                raw = service.exec('provider', 'probe', 'python', '/probe/dns.py', self.a.peer_vip,
                                   DNS_VIPS[0], 'udp', 'allowed.example', '192.0.2.123', '1')
            except Exception:
                attempt.update(completed=time.monotonic()-self.start, success=False)
                raise
            attempt.update(completed=time.monotonic()-self.start, success=True)
            stages['tFirstDNSProbeCompleted'] = attempt['completed']
            stages['first_dns_result'] = raw
            return True
        service.wait(dns_probe, 'first actual DNS UDP probe for '+expected)
        stages['extra_observed_seconds'] = stages['tFirstDNSProbeCompleted']-stages['tSwanReadyObservation']
        self.event('observed-service-stages', **stages)
        return counters_before, stages

    def matrix(self):
        service = self.services
        for name in ('dns-1', 'dns-2', 'support', 'support-client', 'broker-1', 'broker-2', 'broker-3'):
            service.wait(lambda name=name: service.ready(name), name+' readiness')
        for name in ('proxy-1', 'proxy-2', 'proxy-3'):
            service.wait(lambda name=name: service.ready(service.client_pod(name)), name+' readiness')
        before = self.identities()
        for expected, destination in (('owner', None), ('standby', self.a.standby_server_id), ('owner', self.a.owner_server_id)):
            if destination is not None:
                self.move(destination)
            def children():
                return {'customer': installed_children(self.sas(expected), self.reqids),
                        'peer': installed_children(self.sas('peer', True), self.reqids)}
            counters_before, stages = self.observe_stages(expected, children)
            self.wait_health(expected, self.a.failover_timeout)
            record = service.dataplane(expected)
            counters_after = children()
            for side in ('customer', 'peer'):
                for child in CHILDREN:
                    old = counters_before[side][child]['counters']
                    new = counters_after[side][child]['counters']
                    native.require(all(y > x for x, y in zip(old, new)),
                                   'Service CHILD counters did not increase: '+side+' '+child)
            native.require(self.identities() == before, 'Hard roundtrip changed customer/peer identity')
            self.event('public-service-epoch', expected=expected, dataplane=record,
                       child_counters_before=counters_before, child_counters_after=counters_after,
                       observed_stages=stages)
        self.evidence['services'] = service.result


def execute(a):
    output = native.prepare_evidence(a.evidence_dir)
    run = Run(a)
    previous = {}
    def interrupted(signum, frame):
        raise RuntimeError('Interrupted by signal '+str(signum))
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, interrupted)
    try:
        run.setup()
        run.matrix()
        run.evidence['success'] = True
    except Exception as error:
        run.evidence['error'] = str(error)
        try:
            run.diagnostics()
        except Exception as diagnostic_error:
            # Diagnostics must never prevent guarded restoration/host recovery.
            run.evidence['diagnostic_error'] = str(diagnostic_error)
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        errors = run.cleanup()
        run.evidence['success'] = run.evidence['success'] and not errors
        run.evidence['services'] = run.services.result
        text = run.services.redact(json.dumps(run.evidence, indent=2)).replace(run.psk, '[REDACTED]')
        path = output/'result.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(text+'\n')
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps({'success': run.evidence['success'], 'evidence': str(path), 'cleanup_errors': errors}))
    return 0 if run.evidence['success'] else 1


def main(argv=None):
    a = parser().parse_args(argv)
    try:
        validate(a)
        if not a.execute:
            print('REVIEW ONLY: no API/subprocess. Public IPsec + six Lease-selected clients; exact-selector watchdog expansion requires independent review.')
            return 0
        return execute(a)
    except Exception as error:
        print(type(error).__name__+': '+str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
