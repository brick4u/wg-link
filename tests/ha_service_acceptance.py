#!/usr/bin/env python3
"""Opt-in INTERNAL-ONLY generic Lease/WireGuard acceptance (no IPsec/cloud).

No subprocess runs without --execute. Three ordinary gateway Pods share keys and
internal addresses; an independent Python application's /healthy file controls
eligibility. Two DNS, three HAProxy/WG and one support/WG client discover the
Lease holder through Service/EndpointSlice targetRef UID + Ready filtering.
A synthetic remote-LAN Pod owns 198.18.10.2/32 on loopback. A fourth gateway
WG-LAN interface carries it over normal CNI UDP routing; this seventh Lease
consumer models the remote path for INTERNAL-ONLY tests, NOT IPsec, a floating IP
or a cloud failover. Gateway UDP ports are 51820/51821/51822 plus test-LAN 51824.

Requires public immutable WG/Python/Unbound/HAProxy/VerneMQ image digests, three
explicit nodes, kubeconfig and private output directory. Never run before parent
review. No host networking, host mounts, production peers, external IPs or native
IPsec selectors. Optional --fault-tests adds scoped SIGSTOP/API-partition probes;
these require separate parent review and remain disabled by default.
"""
import argparse
import base64
import importlib.util
import json
import ipaddress
from pathlib import Path
import re
import time

_spec = importlib.util.spec_from_file_location('ha_system', Path(__file__).with_name('system_acceptance.py'))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
CLIENTS = ('dns-1', 'dns-2', 'proxy-1', 'proxy-2', 'proxy-3', 'support')
GATEWAYS = ('gateway-1', 'gateway-2', 'gateway-3')
PORTS = (51820, 51821, 51822, 51824)
GATEWAY_INTERFACES = {'wg-dns', 'wg-broker', 'wg-transit', 'wg-lan'}
LEASE = 'gateway-active'
CLEANUP_RESERVE = 40  # fault restoration plus namespace UID deletion/wait
# Explicit destination-port ownership; matches the reused MQTT driver's port order.
BROKER_PATHS = (('broker-1', 12101), ('broker-2', 12201), ('broker-3', 1883))
# The shared probe is A-only. Extend its question/RDATA handling for policy AAAA.
DNS_PROBE = base.DNS_PROBE.replace(
    'source,dst,proto,name,expected=sys.argv[1:]',
    'source,dst,proto,name,expected=sys.argv[1:6]\nqtype=int(sys.argv[6]) if len(sys.argv)>6 else 1'
).replace("struct.pack('!HH',1,1)", "struct.pack('!HH',qtype,1)").replace(
    "if typ==1 and cls==1 and n==4:answers.append(socket.inet_ntoa(b[o:o+4]))",
    "if typ==qtype and cls==1 and n==(16 if qtype==28 else 4):answers.append(socket.inet_ntop(socket.AF_INET6 if qtype==28 else socket.AF_INET,b[o:o+n]))")
APPLICATION = '''import http.server,pathlib
p=pathlib.Path('/healthy');p.touch()
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200 if p.exists() else 503);self.end_headers()
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',18080),Handler).serve_forever()
'''
UNBOUND = '''server:
 interface: 0.0.0.0
 interface-automatic: yes
 username: ""
 chroot: ""
 directory: "/"
 pidfile: ""
 use-syslog: no
 module-config: "iterator"
 access-control: 198.18.10.2/32 allow
 access-control: 198.18.40.2/32 allow
 access-control: 0.0.0.0/0 refuse
 local-zone: "allowed.example." static
 local-data: "allowed.example. 60 IN A 192.0.2.123"
 local-zone: "sinkhole.example." static
 local-data: "sinkhole.example. 60 IN A 127.0.0.1"
 local-data: "sinkhole.example. 60 IN AAAA ::1"
'''


class Harness(base.Harness):
    def __init__(self, args):
        args.strongswan_image = args.exporter_image = None
        super().__init__(args)
        self.ns = 'wg-ha-' + self.token[:12]
        self.deadline = time.monotonic() + args.timeout
        self.namespace_uid = None
        self.cleaning = False
        self.result.update(scope={'network': 'synthetic internal LAN only', 'ipsec': False,
                                 'cloud_actions': False, 'floating_ip': False,
                                 'remote_transport': 'synthetic WG-LAN (not IPsec)',
                                 'service_clients': 6, 'lease_consumers': 7}, trace=[])
        self.result['images'] = {k: getattr(args, k) for k in
                                ('wg_image', 'probe_image', 'unbound_image', 'haproxy_image', 'broker_image')}

    def run(self, argv, data=None, timeout=45, allow=False):
        remaining = self.deadline - time.monotonic() - (0 if self.cleaning else CLEANUP_RESERVE)
        if remaining <= 0:
            raise RuntimeError('total acceptance deadline exhausted')
        return super().run(argv, data, max(.1, min(timeout, remaining)), allow)

    def wait(self, fn, message):
        while time.monotonic() < self.deadline - CLEANUP_RESERVE:
            try:
                value = fn()
                if value:
                    return value
            except (RuntimeError, AssertionError, KeyError, json.JSONDecodeError):
                pass
            time.sleep(1)
        raise RuntimeError('deadline waiting for ' + message)

    def wg(self, config):
        env = [{'name': name, 'valueFrom': {'fieldRef': {'fieldPath': field}}}
               for name, field in [('POD_NAME', 'metadata.name'), ('POD_NAMESPACE', 'metadata.namespace'),
                                   ('POD_UID', 'metadata.uid')]]
        env += [{'name': 'WG_CONTAINER_NAME', 'value': 'wg-link'},
                {'name': 'OWNPOD_ID', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.uid'}}}]
        return self.container('wg-link', self.a.wg_image, ['NET_ADMIN', 'NET_RAW'],
            args=['-config', '/config/config.yaml', '-listen', ':9090'], env=env,
            readinessProbe={'httpGet': {'path': '/readyz', 'port': 9090},
                            'periodSeconds': 1, 'failureThreshold': 2, 'successThreshold': 1},
            volumeMounts=[{'name': 'config', 'mountPath': '/config', 'readOnly': True},
                          {'name': 'keys', 'mountPath': '/keys', 'readOnly': True}])

    def gateway_wg(self, config):
        container = self.wg(config)
        if self.a.fault_tests:
            # Namespace PID1 ignores unhandled SIGSTOP on Linux. Only this test
            # mode runs WG as a child; baseline and all clients keep entrypoints.
            container.pop('args')
            container['command'] = ['/bin/sh', '-ec',
                '/usr/local/bin/wg-link -config /config/config.yaml -listen :9090 & p=$!; '
                'set -- $(cat /proc/$p/stat); shift 21; '
                'printf "%s %s\\n" "$p" "$1" > /tmp/wg-test-pid; '
                'trap \'kill -TERM "$p" 2>/dev/null || :; wait "$p" 2>/dev/null || :\' TERM INT; '
                'wait "$p"']
        return container

    def config_objects(self, name, config, keys):
        return [self.resource('ConfigMap', name, data={'config.yaml': json.dumps(config)}),
                self.resource('Secret', name, type='Opaque',
                              data={k: base64.b64encode(v.encode()).decode() for k, v in keys.items()})]

    def volumes(self, name):
        return [{'name': 'config', 'configMap': {'name': name}},
                {'name': 'keys', 'secret': {'secretName': name, 'defaultMode': 256}},
                {'name': 'probe', 'configMap': {'name': 'probe'}}]

    def setup(self):
        self.created = True
        self.k('create', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'Namespace',
            'metadata': {'name': self.ns, 'labels': {base.OWNER: self.token,
                         'pod-security.kubernetes.io/enforce': 'privileged'}}}))
        self.namespace_uid = self.obj('namespace', self.ns)['metadata']['uid']
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
        objects = [self.resource('ServiceAccount', 'wg-link'), role, binding,
                   self.resource('ConfigMap', 'probe', data={'probe.py': base.PROBE,
                       'dns.py': DNS_PROBE, 'mqtt.py': base.MQTT_PROBE, 'application.py': APPLICATION}),
                   self.resource('ConfigMap', 'unbound', data={'unbound.conf': UNBOUND})]
        self.broker_resources(objects)
        self.apply(objects)
        self.topology()

    def provider_resources(self, objects, config):
        # The source VIP remains on loopback. This fourth WG tunnel transports
        # the synthetic remote LAN over ordinary CNI Pod-to-Pod UDP routing.
        remote = self.pod('provider', self.a.nodes[0], [self.wg(config), self.probe(base.APN),
            self.container('mqtt', self.a.probe_image, command=['python', '/probe/mqtt.py'],
                volumeMounts=[{'name': 'probe', 'mountPath': '/probe', 'readOnly': True},
                              {'name': 'mqtt-auth', 'mountPath': '/mqtt-auth', 'readOnly': True}])],
            self.volumes('provider')+[{'name': 'mqtt-auth', 'secret': {'secretName': 'mqtt-auth'}}],
            [self.container('source-vip', self.a.wg_image, ['NET_ADMIN'],
                            command=['ip', 'address', 'add', base.APN+'/32', 'dev', 'lo'])])
        remote['metadata']['labels']['app'] = 'provider'
        objects.append(remote)

    def topology(self):
        keys = {}
        for name in ('gd', 'gb', 'gt', 'gl', 'provider', *CLIENTS, 'sa', 'client'):
            private = self.run(['docker', 'run', '--rm', '--network=none', '--entrypoint',
                                'wg', self.a.wg_image, 'genkey']).strip()
            public = self.run(['docker', 'run', '--rm', '-i', '--network=none', '--entrypoint',
                               'wg', self.a.wg_image, 'pubkey'], private+'\n').strip()
            self.sensitive += [private, public]
            keys[name] = private, public

        def interface(name, key, address, routes, port):
            return dict(name=name, addresses=[address+'/32'], routes=[x+'/32' for x in routes],
                        listenPort=port, privateKeyFile='/keys/'+key, peers=[])

        def peer(key, allowed, service, port, lease=False):
            ref = {'namespace': self.ns, 'name': service, 'port': 'p'+str(port)}
            if lease:
                ref['leaseName'] = LEASE
            return {'publicKey': keys[key][1], 'allowedIPs': [x+'/32' for x in allowed],
                    'persistentKeepalive': 1, 'service': ref}

        dns = interface('wg-dns', 'gd', '198.18.51.1', base.DNS, PORTS[0])
        broker = interface('wg-broker', 'gb', '198.18.61.1', base.BROKER_VIPS, PORTS[1])
        transit = interface('wg-transit', 'gt', '198.18.52.1', [base.CLIENT], PORTS[2])
        lan = interface('wg-lan', 'gl', '198.18.11.1', [base.APN], PORTS[3])
        lan['peers'] = [peer('provider', [base.APN, '198.18.11.2'], 'provider', PORTS[3])]
        remote = interface('wg-lan', 'provider', '198.18.11.2',
                           [*base.DNS, base.BROKER_IP, base.CLIENT], PORTS[3])
        remote['peers'] = [peer('gl', [*base.DNS, base.BROKER_IP, base.CLIENT, '198.18.11.1'],
                                'gateway', PORTS[3], True)]
        configs = {'provider': {'interfaces': [remote]}}
        for name, vip, gateway_key, group, port in [
            *[(f'dns-{i}', vip, 'gd', dns, PORTS[0]) for i, vip in enumerate(base.DNS, 1)],
            *[(f'proxy-{i}', vip, 'gb', broker, PORTS[1]) for i, vip in enumerate(base.BROKER_VIPS, 1)]]:
            group['peers'].append(peer(name, [vip], name, port))
            n = interface(group['name'], name, vip, [base.APN, base.CLIENT], port)
            n['peers'] = [peer(gateway_key, [base.APN, base.CLIENT], 'gateway', port, True)]
            configs[name] = {'interfaces': [n]}
        transit['peers'] = [peer('support', [base.CLIENT], 'support', PORTS[2])]
        support = interface('wg-transit', 'support', '198.18.52.2', [base.APN, *base.DNS], PORTS[2])
        support['peers'] = [peer('gt', [base.APN, *base.DNS], 'gateway', PORTS[2], True)]
        client = interface('wg-support', 'sa', '198.18.40.1', [base.CLIENT], 51823)
        client['peers'] = [peer('client', [base.CLIENT], 'support-client', 51823)]
        end = interface('wg-support', 'client', base.CLIENT, [base.APN, *base.DNS], 51823)
        end['peers'] = [peer('sa', [base.APN, *base.DNS], 'support', 51823)]
        def rule(frm, to, src, dst, protocols, ports=None):
            r = dict(source=src+'/32', destination=dst+'/32', protocols=protocols)
            r.update({'from': frm, 'to': to})
            if ports:
                r['ports'] = ports
            return r
        rules = []
        for vip, iface, ports in [*[(v, 'wg-dns', [53]) for v in base.DNS],
                                  *[(v, 'wg-broker', [1883]) for v in base.BROKER_VIPS],
                                  (base.CLIENT, 'wg-transit', [18080])]:
            rules.append(rule('wg-lan', iface, base.APN, vip, ['tcp', 'udp'], ports))
        rules.append(rule('wg-transit', 'wg-lan', base.CLIENT, base.APN, ['tcp'], [18080]))
        for vip in base.DNS:
            rules += [rule('wg-transit', 'wg-dns', base.CLIENT, vip, ['tcp', 'udp'], [53])]
        # Explicit response rules as well as the forwarding engine's established/related rule.
        for r in list(rules):
            rules.append(dict(r, **{'from': r['to'], 'to': r['from'],
                                    'source': r['destination'], 'destination': r['source']}))
        gateway = {'activation': {'kubernetesLease': {'namespace': self.ns, 'name': LEASE,
            'requireReadyContainers': ['application'], 'leaseDuration': '15s',
            'renewDeadline': '10s', 'retryPeriod': '1s'}, 'fenceTimeout': '3s'},
            'interfaces': [dns, broker, transit, lan], 'forwarding': {'enabled': True,
            'rules': rules, 'dnat': [
                {'from': 'wg-lan', 'source': base.APN+'/32', 'destination': base.BROKER_IP+'/32',
                 'protocol': 'tcp', 'port': p, 'targetIPAddress': vip, 'targetPort': 1883}
                for (_, p), vip in zip(BROKER_PATHS, base.BROKER_VIPS)]}}
        configs['support'] = {'interfaces': [support, client], 'forwarding': {'enabled': True,
            'rules': [rule(f, t, s, d, ['tcp', 'udp'], [53, 18080])
                      for s, d, f, t in [(base.CLIENT, v, 'wg-support', 'wg-transit')
                                        for v in [base.APN, *base.DNS]] +
                                       [(v, base.CLIENT, 'wg-transit', 'wg-support')
                                        for v in [base.APN, *base.DNS]]]}}
        configs['support-client'] = {'interfaces': [end]}
        objects = []
        for name, config in [('gateway', gateway), *configs.items()]:
            used = {i['privateKeyFile'].split('/')[-1] for i in config['interfaces']}
            objects += self.config_objects(name, config, {k: keys[k][0] for k in used})
            ports = [i['listenPort'] for i in config['interfaces']]
            objects.append(self.service(name, name, [('p'+str(p), p) for p in ports]))
        for i, name in enumerate(GATEWAYS):
            app = self.container('application', self.a.probe_image,
                command=['python', '/probe/application.py'],
                readinessProbe={'httpGet': {'path': '/', 'port': 18080}, 'periodSeconds': 1,
                                'failureThreshold': 3, 'successThreshold': 2},
                volumeMounts=[{'name': 'probe', 'mountPath': '/probe', 'readOnly': True}])
            pod = self.pod(name, self.a.nodes[i], [self.gateway_wg(gateway), app], self.volumes('gateway'))
            pod['metadata']['labels']['app'] = 'gateway'
            objects.append(pod)
        for index, name in enumerate(('dns-1', 'dns-2', 'support', 'support-client')):
            containers = [self.wg(configs[name])]
            volumes = self.volumes(name)
            if name.startswith('dns-'):
                volumes.append({'name': 'unbound', 'configMap': {'name': 'unbound'}})
                containers.append(self.container('unbound', self.a.unbound_image, ['NET_BIND_SERVICE'],
                    command=['/usr/sbin/unbound', '-d', '-c', '/unbound/unbound.conf'],
                    volumeMounts=[{'name': 'unbound', 'mountPath': '/unbound', 'readOnly': True}]))
            else:
                containers.append(self.probe(base.CLIENT if name == 'support-client' else '198.18.40.1'))
            pod = self.pod(name, self.a.nodes[index % 3], containers, volumes)
            pod['metadata']['labels']['app'] = name
            if name == 'dns-1':
                self.fresh_client_template = pod
            objects.append(pod)
        self.provider_resources(objects, configs['provider'])
        self.proxy_resources(objects, configs)
        # Existing proxy resources get the same mandatory Downward identity.
        for obj in objects:
            if obj['kind'] == 'Deployment':
                obj['spec']['template']['spec']['containers'][0] = self.wg({})
        self.apply(objects)

    def snapshot(self):
        pods = [self.obj('pod', n) for n in GATEWAYS]
        lease = self.obj('lease', LEASE)
        holder = lease['spec'].get('holderIdentity')
        ready = [p for p in pods if any(c.get('name') == 'wg-link' and c.get('ready')
                                      for c in p.get('status', {}).get('containerStatuses', []))]
        healthy = [p['metadata']['name'] for p in pods if any(
            c.get('name') == 'application' and c.get('ready')
            for c in p.get('status', {}).get('containerStatuses', []))]
        # Kubelet readiness is asynchronous: old Ready observations can coexist
        # with a successor. Only Lease UID + application-ready + WG-ready selects.
        active = [p for p in ready if p['metadata']['uid'] == holder
                  and p['metadata']['name'] in healthy]
        value = {'time': time.monotonic(), 'healthy': healthy,
                 'active': active[0]['metadata']['name'] if active else None,
                 'holder_uid': holder,
                 'staleReady': [p['metadata']['name'] for p in ready if p not in active]}
        self.result['trace'].append(value)
        return value

    def converged(self, healthy, previous=None):
        v = self.snapshot()
        if len(v['healthy']) != healthy or (healthy and not v['active']):
            return False
        if previous and v['active'] == previous:
            return False
        if not healthy and v['active']:
            return False
        return v

    def toggle(self, name, healthy):
        code = "import pathlib;p=pathlib.Path('/healthy');" + ('p.touch()' if healthy else 'p.unlink(missing_ok=True)')
        self.exec(name, 'application', 'python', '-c', code)

    def client_pod(self, name):
        return self.proxy_pod(name)['metadata']['name'] if name.startswith('proxy-') else name

    def endpoints(self, active):
        ip = self.obj('pod', active)['status']['podIP']
        evidence = {}
        for name in CLIENTS:
            iface = 'wg-dns' if name.startswith('dns-') else 'wg-broker' if name.startswith('proxy-') else 'wg-transit'
            raw = self.exec(self.client_pod(name), 'wg-link', 'wg', 'show', iface, 'endpoints')
            expected = ip+':'+str(PORTS[0] if name.startswith('dns-') else PORTS[1] if name.startswith('proxy-') else PORTS[2])
            assert len(raw.splitlines()) == 1 and raw.split()[1] == expected, (name, raw, expected)
            evidence[name] = expected
        return evidence

    @staticmethod
    def gate_open(table):
        for entry in table['nftables']:
            group = entry.get('set', {})
            if group.get('name') == 'active_ports':
                for value in group.get('elem', []):
                    element = value.get('elem', value) if isinstance(value, dict) else {}
                    if not isinstance(element, dict) or element.get('expires', 1) > 0:
                        return True
        return False

    def gates(self, active, frozen=None, foreign=None):
        evidence = {}
        for name in GATEWAYS:
            table = json.loads(self.exec(name, 'wg-link', 'nft', '-j', 'list', 'table', 'inet', 'wg_link_ha'))
            entries = table['nftables']
            assert any(e.get('table', {}).get('comment') == 'wg-link:ha:v1' for e in entries)
            rules = [e['rule'] for e in entries if 'rule' in e]
            for chain in ('input', 'output'):
                assert any(r['chain'] == chain and any('drop' in x for x in r['expr']) for r in rules)
            opened = self.gate_open(table)
            interfaces = self.exec(name, 'wg-link', 'wg', 'show', 'interfaces').split()
            evidence[name] = {'allowance_present': bool(opened), 'interfaces': interfaces}
        # Sequential API/exec observations are not a simultaneous safety proof.
        # Compare only after stable Lease convergence; retry transitional samples.
        assert sum(v['allowance_present'] for v in evidence.values()) <= 1, evidence
        for name, value in evidence.items():
            assert value['allowance_present'] == (name == active), (name, 'kernel gate does not match holder')
            if name == foreign:
                assert set(value['interfaces']) <= GATEWAY_INTERFACES
            else:
                assert set(value['interfaces']) == (GATEWAY_INTERFACES if name in (active, frozen) else set())
        assert self.snapshot()['active'] == active, 'Lease selection changed during sequential gate sample'
        self.result.setdefault('kernel_gates', []).append(evidence)
        return True

    def sessions(self, flows):
        # MQTT driver client suffix chooses its original destination port. Resolve
        # that port through this explicit named mapping, never API listing order.
        rows = {name: self.session_rows(int(name.rsplit('-', 1)[1])) for name, _ in BROKER_PATHS}
        evidence = {}
        for flow in flows:
            name, port = BROKER_PATHS[int(flow['client_id'].rsplit('-', 1)[1]) % 3]
            matching = [r for r in rows[name] if r['client_id'] == flow['client_id']]
            assert len(matching) == 1, ('missing actual broker session', name, flow['client_id'])
            row = matching[0]
            assert row['peer_host'] == base.APN, ('PROXYv2 source VIP lost', name, row)
            assert row['is_online'] in (True, 'true'), row
            evidence[flow['client_id']] = {'broker': name, 'destination_port': port,
                **{k: row[k] for k in ('peer_host', 'session_pid', 'session_started_at')}}
        return evidence

    def dataplane(self, active, frozen=None, foreign=None):
        self.gates(active, frozen, foreign)
        self.endpoints(active)
        ip = self.obj('pod', active)['status']['podIP']
        lan = self.exec('provider', 'wg-link', 'wg', 'show', 'wg-lan', 'endpoints')
        assert len(lan.splitlines()) == 1 and lan.split()[1] == ip+':'+str(PORTS[3]), lan
        for source, pod in [(base.APN, 'provider'), (base.CLIENT, 'support-client')]:
            for server in base.DNS:
                for proto in ('udp', 'tcp'):
                    for name, expected, qtype in [('allowed.example', '192.0.2.123', '1'),
                                                  ('sinkhole.example', '127.0.0.1', '1'),
                                                  ('sinkhole.example', '::1', '28')]:
                        self.exec(pod, 'probe', 'python', '/probe/dns.py', source, server,
                                  proto, name, expected, qtype)
        self.echo('support-client', base.APN, source=base.CLIENT)
        self.echo('provider', base.CLIENT, source=base.APN)
        try:
            opened = self.mqtt('open', prefix='ha-'+self.token[:8], count=3, interval=0)
            assert opened['established'] == 3 and not opened['errors'], opened
            flows = self.held_check(opened['flows'])
            sessions = self.sessions(flows)  # actual VerneMQ peer_host must be source VIP
        finally:
            self.mqtt('close')
        self.result.setdefault('dataplane', []).append({'active': active, 'mqtt': flows,
            'broker_sessions': sessions, 'dns_udp_tcp': True, 'support_bidirectional': True})
        return True

    def delete_uid(self, path, uid):
        self.k('delete', '--raw', path, '-f', '-', data=json.dumps({
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}))

    def fresh_client(self, active):
        old = self.obj('pod', 'dns-1')['metadata']['uid']
        self.delete_uid('/api/v1/namespaces/'+self.ns+'/pods/dns-1', old)
        self.k('wait', '--for=delete', 'pod/dns-1', '-n', self.ns, '--timeout=15s', timeout=17)
        self.apply([self.fresh_client_template])
        self.wait(lambda: self.ready('dns-1'), 'fresh DNS/WG client readiness')
        new = self.obj('pod', 'dns-1')['metadata']['uid']
        assert new != old, 'fresh client must have a new Pod UID'
        selected = self.wait(lambda: self.endpoints(active), 'fresh client discovers successor')
        self.result['fresh_client'] = {'name': 'dns-1', 'previous_uid': old, 'uid': new,
                                       'selected_endpoint': selected['dns-1'], 'active': active}
        return True

    def restore(self, fn):
        # Restoration gets independently bounded exec calls from the reserved
        # cleanup budget, even when the normal test deadline was exhausted.
        previous = self.cleaning
        self.cleaning = True
        try:
            return fn()
        finally:
            self.cleaning = previous

    def signal_wg(self, pod, signal):
        assert pod in GATEWAYS and signal in ('STOP', 'CONT')
        gone = 'exit 0' if signal == 'CONT' else 'exit 1'
        script = ('[ -f /tmp/wg-test-pid ] || { '+gone+'; }; '
                  'read -r p birth < /tmp/wg-test-pid; '
                  'case "$p:$birth" in *[!0-9:]*|:*|*:) exit 1;; esac; '
                  '[ "$p" -gt 1 ] || { echo "namespace PID1 cannot be frozen" >&2; exit 1; }; '
                  '[ -d /proc/$p ] || { '+gone+'; }; '
                  '[ "$(cat /proc/$p/comm)" = wg-link ] || { '+gone+'; }; '
                  'set -- $(cat /proc/$p/stat); shift 21; '
                  '[ "$1" = "$birth" ] || { '+gone+'; }; '
                  'kill -'+signal+' "$p"; printf "%s\\n" "$p"')
        # PID start ticks prevent signaling a reused PID; an exited original is
        # harmless during CONT restoration. Every signal validates identity anew.
        return self.k('exec', '-n', self.ns, pod, '-c', 'wg-link', '--',
                      '/bin/sh', '-ec', script, timeout=5)

    def closed_while_application_alive(self, pod, started, limit):
        table = json.loads(self.exec(pod, 'wg-link', 'nft', '-j', 'list', 'table', 'inet', 'wg_link_ha'))
        if self.gate_open(table):
            if time.monotonic()-started >= limit:
                raise TimeoutError('kernel allowance did not expire inside fault budget')
            return False
        elapsed = time.monotonic()-started
        if elapsed > limit:
            raise TimeoutError('gate closure observation exceeded fault budget')
        self.exec(pod, 'application', 'python', '-c',
            "import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:18080/',timeout=2).status==200")
        # Observe the old gate closed before accepting a successor Lease. This
        # is ordered evidence, not a simultaneous multi-Pod snapshot claim.
        lease = self.obj('lease', LEASE)
        assert lease['spec'].get('holderIdentity') == self.obj('pod', pod)['metadata']['uid'], \
            'handoff was observed before old gate closure could be established'
        return {'closed_after_seconds': elapsed, 'application_http_alive': True,
                'closed_before_observed_handoff': True}

    def frozen_process(self):
        selected = self.wait(lambda: self.converged(3), 'healthy fault-test baseline')
        old = selected['active']
        record = {'kind': 'SIGSTOP', 'old': old, 'kernel_timeout_seconds': 3,
                  'observation_budget_seconds': 6}
        self.result.setdefault('faults', []).append(record)
        try:
            pid = self.signal_wg(old, 'STOP').strip()
            started = time.monotonic()
            assert pid.isdecimal() and int(pid) > 1, 'fault target must be the WG child, not namespace PID1'
            status = self.exec(old, 'wg-link', 'cat', '/proc/'+pid+'/status')
            assert any(line.startswith('State:') and line.split()[1] in ('T', 't')
                       for line in status.splitlines()), 'WG child process did not stop'
            record.update(wg_pid=int(pid), child_stopped=True)
            record.update(self.wait(lambda: self.closed_while_application_alive(old, started, 6),
                                    'frozen process kernel gate expiry'))
            new = self.wait(lambda: self.converged(3, old), 'Lease expiry and successor while frozen')
            record['successor'] = new['active']
            self.wait(lambda: self.dataplane(new['active'], frozen=old), 'traffic while former WG process frozen')
        finally:
            # The new exec process is independent of the stopped child. Even an
            # ambiguous STOP response must attempt CONT before namespace cleanup.
            self.restore(lambda: self.signal_wg(old, 'CONT'))
        self.wait(lambda: self.gates(new['active']), 'resumed former holder remains fenced')
        record['resumed'] = True

    def api_table(self, pod):
        return json.loads(self.exec(pod, 'wg-link', 'nft', '-j', 'list', 'tables'))['nftables']

    def remove_api_partition(self, pod):
        assert pod in GATEWAYS, 'fault cleanup is restricted to test gateways'
        # Inspect only this disposable Pod namespace; never flush any ruleset.
        raw = self.k('exec', '-n', self.ns, pod, '-c', 'wg-link', '--',
                     'nft', '-j', 'list', 'ruleset', timeout=5)
        tables = [e['table'] for e in json.loads(raw)['nftables'] if 'table' in e]
        matches = [t for t in tables if t.get('family') == 'inet' and t.get('name') == 'wg_ha_test_api']
        if not matches:
            return
        assert len(matches) == 1 and matches[0].get('comment') == self.token, 'foreign API fault table'
        self.k('exec', '-n', self.ns, pod, '-c', 'wg-link', '--',
               'nft', 'delete', 'table', 'inet', 'wg_ha_test_api', timeout=5)

    def partition_api(self):
        selected = self.wait(lambda: self.converged(3), 'healthy API-fault baseline')
        old = selected['active']
        assert not any(e.get('table', {}).get('name') == 'wg_ha_test_api' for e in self.api_table(old)), \
            'API fault table already exists'
        host, port = json.loads(self.exec(old, 'application', 'python', '-c',
            "import os,json;print(json.dumps([os.environ['KUBERNETES_SERVICE_HOST'],int(os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS','443'))]))"))
        address = ipaddress.IPv4Address(host)
        assert address.is_private and not address.is_unspecified and 1 <= port <= 65535
        rules = ('add table inet wg_ha_test_api { comment "'+self.token+'"; }\n'
                 'add chain inet wg_ha_test_api output { type filter hook output priority -320; policy accept; }\n'
                 'add rule inet wg_ha_test_api output ip daddr '+str(address)+' tcp dport '+str(port)+' drop\n')
        record = {'kind': 'Pod API OUTPUT partition', 'old': old, 'api_host': host,
                  'api_port': port, 'observation_budget_seconds': 10}
        self.result.setdefault('faults', []).append(record)
        try:
            self.k('exec', '-i', '-n', self.ns, old, '-c', 'wg-link', '--', 'nft', '-f', '-', data=rules)
            started = time.monotonic()
            record.update(self.wait(lambda: self.closed_while_application_alive(old, started, 10),
                                    'API-partitioned kernel gate expiry'))
            new = self.wait(lambda: self.converged(3, old), 'API-partitioned Lease expiry and successor')
            record['successor'] = new['active']
            self.wait(lambda: self.dataplane(new['active']), 'API-partition successor traffic')
        finally:
            self.restore(lambda: self.remove_api_partition(old))
        record['partition_removed'] = True

    def restore_alias(self, pod, original, marker):
        assert pod in GATEWAYS and original['ifname'] == 'wg-dns' and original['ifalias'] == 'wg-link:v1'
        assert marker == 'wg-ha-test-foreign-'+self.token
        links = json.loads(self.k('exec', '-n', self.ns, pod, '-c', 'wg-link', '--',
                                  'ip', '-j', 'link', 'show', timeout=5))
        matches = [link for link in links if link['ifname'] == 'wg-dns']
        if not matches:
            return 'link_already_removed'
        assert len(matches) == 1 and matches[0]['ifindex'] == original['ifindex'], 'interface identity changed'
        if matches[0].get('ifalias') == original['ifalias']:
            return 'original_alias_unchanged'
        assert matches[0].get('ifalias') == marker, 'refusing to change a foreign alias'
        self.k('exec', '-n', self.ns, pod, '-c', 'wg-link', '--', 'ip', 'link', 'set',
               'dev', 'wg-dns', 'alias', original['ifalias'], timeout=5)
        return 'original_alias_restored'

    def backend_failure(self):
        selected = self.wait(lambda: self.converged(3), 'healthy backend-fault baseline')
        old = selected['active']
        before = self.stable_identity(GATEWAYS)
        original, = json.loads(self.exec(old, 'wg-link', 'ip', '-j', 'link', 'show', 'dev', 'wg-dns'))
        assert original['ifname'] == 'wg-dns' and original.get('ifalias') == 'wg-link:v1'
        marker = 'wg-ha-test-foreign-'+self.token
        record = {'kind': 'backend foreign interface alias', 'old': old, 'interface': 'wg-dns',
                  'ifindex': original['ifindex'], 'application_healthy': True}
        self.result.setdefault('faults', []).append(record)

        def closed_and_not_ready():
            table = json.loads(self.exec(old, 'wg-link', 'nft', '-j', 'list', 'table', 'inet', 'wg_link_ha'))
            pod = self.obj('pod', old)
            statuses = {c['name']: c for c in pod['status']['containerStatuses']}
            return not self.gate_open(table) and not statuses['wg-link']['ready'] and statuses['application']['ready']

        try:
            self.exec(old, 'wg-link', 'ip', 'link', 'set', 'dev', 'wg-dns', 'alias', marker)
            started = time.monotonic()
            self.wait(closed_and_not_ready, 'backend failure closes gate while application remains healthy')
            record.update(closed_after_seconds=time.monotonic()-started, wg_ready_after_failure=False)
            self.exec(old, 'application', 'python', '-c',
                "import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:18080/',timeout=2).status==200")
            record['closed_before_successor_validation'] = True
            # Immediate release may precede API observations. Do not require a
            # stale Lease holder here: validate closure, then successor service.
            new = self.wait(lambda: self.converged(3, old), 'backend failure yields Lease to successor')
            record['successor'] = new['active']
            self.wait(lambda: self.dataplane(new['active'], foreign=old), 'backend-failure successor traffic')
            assert before == self.stable_identity(GATEWAYS), 'backend fault restarted Pod/container'
            record['pod_container_identities_unchanged'] = True
        finally:
            record['alias_cleanup'] = self.restore(lambda: self.restore_alias(old, original, marker))

    def tests(self):
        first = self.wait(lambda: self.converged(3), 'three healthy, single Lease holder')
        self.wait(lambda: self.dataplane(first['active']), 'initial six-client DNS/MQTT/support traffic')
        self.toggle(first['active'], False)
        second = self.wait(lambda: self.converged(2, first['active']), 'readiness-driven rotation')
        self.wait(lambda: self.endpoints(second['active']), 'rotated six-client endpoint selection')
        self.fresh_client(second['active'])
        self.wait(lambda: self.dataplane(second['active']), 'rotated endpoints and fresh-client traffic')
        for name in GATEWAYS:
            self.toggle(name, False)
        self.wait(lambda: self.converged(0), 'no healthy candidate')
        self.wait(lambda: self.gates(None), 'all kernel gates closed')
        before = self.endpoints(second['active'])
        for name in GATEWAYS:
            assert not self.exec(name, 'wg-link', 'wg', 'show', 'interfaces').strip(), 'standby interfaces remain'
        # Retaining the last authenticated endpoint is intentional. No gateways
        # have an interface or open gate; kubelet Ready observations may lag.
        self.result['zero_healthy'] = {'retained_endpoints': before, 'gateway_interfaces_absent': True}
        self.toggle(first['active'], True)
        third = self.wait(lambda: self.converged(1), 'recovery')
        self.wait(lambda: self.dataplane(third['active']), 'recovered six-client traffic')
        if self.a.fault_tests:
            for name in GATEWAYS:
                self.toggle(name, True)
            self.frozen_process()
            self.partition_api()
            self.backend_failure()

    def cleanup(self):
        self.cleaning = True
        if not self.created:
            return
        raw = self.k('get', 'namespace', self.ns, '--ignore-not-found', '-o', 'json')
        if not raw.strip():
            return
        meta = json.loads(raw)['metadata']
        assert meta.get('labels', {}).get(base.OWNER) == self.token, 'namespace owner mismatch'
        if self.namespace_uid is None:
            self.namespace_uid = meta['uid']  # ambiguous create response, UUID owner still mandatory
        assert meta['uid'] == self.namespace_uid, 'namespace UID mismatch'
        self.delete_uid('/api/v1/namespaces/'+self.ns, self.namespace_uid)
        self.k('wait', '--for=delete', 'namespace/'+self.ns, '--timeout=25s', timeout=27)
        assert not self.k('get', 'namespace', self.ns, '--ignore-not-found', '-o', 'name').strip()
        self.result['cleanup_verified'] = True

    def diagnostics(self):
        # A separate 15s diagnostic budget always leaves at least 30s for UID
        # namespace cleanup. Only status/events and selected container logs are
        # persisted: never Pod specs, Secrets, config/key dumps or XFRM state.
        records = self.result.setdefault('diagnostics', [])
        end = min(time.monotonic()+15, self.deadline-30)
        previous = self.cleaning
        self.cleaning = True

        def request(*args):
            remaining = end-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('diagnostic budget exhausted; preserving cleanup time')
            return self.k(*args, timeout=min(3, remaining))

        def save(name, value):
            path = self.out/name
            text = value if isinstance(value, str) else json.dumps(value, indent=2)
            path.write_text(self.redact(text))
            path.chmod(0o600)
            records.append({'file': name})

        try:
            if not self.created:
                return
            ns = json.loads(request('get', 'namespace', self.ns, '-o', 'json'))['metadata']
            assert ns.get('labels', {}).get(base.OWNER) == self.token, 'diagnostic namespace owner mismatch'
            assert self.namespace_uid is None or ns['uid'] == self.namespace_uid, 'diagnostic namespace UID mismatch'
            pods = json.loads(request('get', 'pods', '-n', self.ns, '-l',
                                      base.OWNER+'='+self.token, '-o', 'json'))['items']
            pods = [p for p in pods if p['metadata'].get('labels', {}).get(base.OWNER) == self.token]
            save('failure-pod-status.json', [{'name': p['metadata']['name'],
                'uid': p['metadata']['uid'], 'status': p.get('status', {})} for p in pods])
            try:
                events = json.loads(request('get', 'events', '-n', self.ns,
                    '--sort-by=.metadata.creationTimestamp', '-o', 'json'))
                save('failure-events.json', events.get('items', [])[-40:])
            except Exception as error:
                records.append({'events_error': type(error).__name__})
            for pod in pods:
                for container in pod['spec'].get('containers', []):
                    name = container['name']
                    if name not in ('wg-link', 'application', 'unbound', 'haproxy'):
                        continue
                    if time.monotonic() >= end:
                        records.append({'truncated': '15s budget or cleanup reserve'})
                        return
                    try:
                        text = request('logs', '-n', self.ns, pod['metadata']['name'], '-c', name, '--tail=40')
                        save('failure-'+pod['metadata']['name']+'-'+name+'.log', text)
                    except Exception as error:
                        records.append({'pod': pod['metadata']['name'], 'container': name,
                                        'error': type(error).__name__})
        except Exception as error:
            records.append({'collection_error': type(error).__name__})
        finally:
            self.cleaning = previous


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute', action='store_true')
    p.add_argument('--fault-tests', action='store_true',
                   help='test WG child suspend, Pod API partition and backend alias failure (requires ConfigurationFailed-capable WG image; separate review required)')
    p.add_argument('--kubeconfig', required=True)
    p.add_argument('--nodes', nargs=3, required=True)
    p.add_argument('--output', required=True, help='private evidence directory (0700)')
    p.add_argument('--timeout', type=int, default=300, help='total seconds including cleanup, 60..300')
    for name in ('wg', 'probe', 'unbound', 'haproxy', 'broker'):
        p.add_argument('--'+name+'-image', required=True)
    a = p.parse_args(argv)
    if len(set(a.nodes)) != 3:
        p.error('three distinct nodes required')
    if not 60 <= a.timeout <= 300:
        p.error('total timeout must be 60..300 seconds')
    for name in ('wg', 'probe', 'unbound', 'haproxy', 'broker'):
        if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', getattr(a, name+'_image')):
            p.error(name+' image requires an immutable sha256 digest')
    return a


if __name__ == '__main__':
    args = arguments()
    if args.execute:
        Harness(args).main()
    else:
        print('Arguments valid; no Docker/Kubernetes/cloud operations performed. Parent review required before --execute.')
