"""Offline tests for the overall test harness; no Docker or cluster access."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('system_acceptance', Path(__file__).with_name('system_acceptance.py'))
system = importlib.util.module_from_spec(spec)
spec.loader.exec_module(system)


class ProbeTests(unittest.TestCase):
    def test_cli_does_not_start_http_listener(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = server.getsockname()[1]
            errors = []

            def echo():
                try:
                    server.settimeout(5)
                    conn, address = server.accept()
                    with conn:
                        conn.settimeout(5)
                        payload = conn.recv(1024).decode().strip()
                        conn.sendall((json.dumps({'source': address[0], 'payload': payload}) + '\n').encode())
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=echo)
            worker.start()
            code = """import http.server,sys

def forbidden(*args,**kwargs):
    raise AssertionError('HTTP listener started in probe CLI')
http.server.ThreadingHTTPServer=forbidden
sys.argv=['probe.py','check','127.0.0.1',sys.argv[1],'tcp']
exec(%r)
""" % system.PROBE
            result = subprocess.run([sys.executable, '-c', code, str(port)],
                                    env={**os.environ, 'SOURCE': '127.0.0.1'},
                                    text=True, capture_output=True, timeout=8)
            worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['ok'])

    def test_embedded_programs_compile(self):
        compile(system.PROBE, 'probe.py', 'exec')
        compile(system.DNS_PROBE, 'dns.py', 'exec')


class TopologyTests(unittest.TestCase):
    def setUp(self):
        h = object.__new__(system.Harness)
        h.a = SimpleNamespace(wg_image='wg', strongswan_image='ipsec',
                              unbound_image='dns', exporter_image='metrics',
                              probe_image='probe', haproxy_image='haproxy', broker_image='vernemq',
                              nodes=['node-a', 'node-b', 'node-c'])
        h.ns, h.token, h.sink, h.sensitive = 'test', 'unit-token', '192.0.2.2', []
        # Inspect manifests offline; credential generation is irrelevant here.
        h.run = lambda *args, **kwargs: base64.b64encode(os.urandom(32)).decode()
        self.resources = []
        h.apply = self.resources.extend
        h.result = {}
        def obj(kind, name):
            self.assertEqual((kind, name), ('service', 'ipsec-gateway'))
            self.assertEqual([r['metadata']['name'] for r in self.resources],
                             ['ipsec-gateway', 'provider-peer'], 'bootstrap Services must precede workloads')
            return {'spec': {'clusterIP': '10.96.12.34'}}
        h.obj = obj
        h.topology()
        self.harness = h

    def resource(self, kind, name):
        return next(r for r in self.resources if r['kind'] == kind and r['metadata']['name'] == name)

    def test_datapath_readiness_preserves_ike_bootstrap(self):
        gateway = self.resource('Pod', 'gateway')
        swan = next(c for c in gateway['spec']['containers'] if c['name'] == 'strongswan')
        self.assertEqual(swan['livenessProbe']['exec']['command'], ['swanctl', '--stats'])
        self.assertEqual(swan['readinessProbe']['exec']['command'],
                         ['ping', '-n', '-I', '198.18.51.1', '-c', '1', '-W', '1', system.APN])
        services = [r for r in self.resources if r['kind'] == 'Service']
        published_unready = [r['metadata']['name'] for r in services if r['spec'].get('publishNotReadyAddresses')]
        self.assertEqual(published_unready, ['ipsec-gateway'])
        secret = self.resource('Secret', 'gateway-ipsec')
        self.assertEqual(set(secret['stringData']), {'swanctl.conf'})

    def test_outer_ike_bootstrap_uses_preallocated_literal_ip(self):
        provider = self.resource('Secret', 'provider-ipsec')['stringData']['swanctl.conf']
        gateway = self.resource('Secret', 'gateway-ipsec')['stringData']['swanctl.conf']
        self.assertIn('remote_addrs = 10.96.12.34\n', provider)
        self.assertNotIn('.svc.cluster.local', provider)
        self.assertIn('remote_addrs = %any\n', gateway)
        for config in (provider, gateway):
            self.assertIn('local_port = 500\n', config)
            self.assertIn('remote_port = 500\n', config)
            self.assertIn('encap = yes', config)
            self.assertIn('dpd_action = restart', config)
        self.assertEqual(self.harness.result['ike_bootstrap']['gateway_service_ip'], '10.96.12.34')
        self.assertEqual(len([r for r in self.resources if r['kind'] == 'Service' and
                              r['metadata']['name'] == 'ipsec-gateway']), 1)

    def test_nat_scope_and_unbound_identity(self):
        cfg = json.loads(self.resource('ConfigMap', 'gateway')['data']['config.yaml'])
        self.assertEqual(cfg['forwarding']['externalInterfaces'], ['eth0'])
        self.assertEqual(cfg['forwarding']['masquerade'],
                         [{'from': 'eth0', 'to': 'eth0', 'source': '198.18.10.0/24',
                           'destination': '192.0.2.2/32'}])
        dns = self.resource('Pod', 'dns-1')
        resolver = next(c for c in dns['spec']['containers'] if c['name'] == 'unbound')
        self.assertEqual(resolver['command'][0], '/usr/sbin/unbound')
        self.assertEqual(resolver['securityContext']['runAsUser'], 101)
        self.assertEqual(resolver['securityContext']['runAsGroup'], 102)

    def config(self, name):
        return json.loads(self.resource('ConfigMap', name)['data']['config.yaml'])

    def test_independent_dns_identities_and_exact_routes(self):
        gateway = self.config('gateway')['interfaces'][0]
        self.assertEqual(gateway['routes'], [x+'/32' for x in system.DNS])
        self.assertEqual(len(gateway['peers']), 2)
        self.assertEqual(len({p['publicKey'] for p in gateway['peers']}), 2)
        for i, alias in enumerate(system.DNS, 1):
            interface = self.config('dns-'+str(i))['interfaces'][0]
            self.assertEqual(interface['addresses'], [alias+'/32'])
            self.assertEqual(interface['routes'], ['198.18.10.0/24'])
            self.assertEqual(gateway['peers'][i-1]['allowedIPs'], [alias+'/32'])

    def test_broker_dnat_acl_and_distinct_wireguard_peers(self):
        config = self.config('gateway')
        broker = next(i for i in config['interfaces'] if i['name'] == 'wg-broker')
        self.assertEqual(broker['routes'], [v+'/32' for v in system.BROKER_VIPS])
        self.assertEqual(len({p['publicKey'] for p in broker['peers']}), 3)
        for i, (port, vip) in enumerate(zip(system.BROKER_PORTS, system.BROKER_VIPS)):
            self.assertEqual(broker['peers'][i]['allowedIPs'], [vip+'/32'])
            self.assertEqual(config['forwarding']['dnat'][i], {
                'from': 'eth0', 'source': '198.18.10.0/24', 'destination': '192.0.2.80/32',
                'protocol': 'tcp', 'port': port, 'targetIPAddress': vip, 'targetPort': 1883})
            acl = [r for r in config['forwarding']['rules'] if r['destination'] == vip+'/32']
            self.assertEqual(acl, [{'from': 'eth0', 'to': 'wg-broker', 'source': '198.18.10.0/24',
                                   'destination': vip+'/32', 'protocols': ['tcp'], 'ports': [1883]}])
            self.assertEqual(self.config('proxy-'+str(i+1))['interfaces'][0]['addresses'], [vip+'/32'])
        self.assertEqual(len(config['forwarding']['masquerade']), 1)

    def test_proxy_standard_master_worker_and_recreate_projection(self):
        for i in range(1, 4):
            deployment = self.resource('Deployment', 'proxy-'+str(i))
            self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
            self.assertEqual(deployment['spec']['replicas'], 1)
            pod = deployment['spec']['template']['spec']
            proxy = next(c for c in pod['containers'] if c['name'] == 'haproxy')
            self.assertEqual(proxy['command'], ['/usr/local/sbin/haproxy', '-W', '-db', '-f', '/config/haproxy.cfg'])
            self.assertEqual(proxy['securityContext']['capabilities'], {'drop': ['ALL'], 'add': []})
            self.assertEqual(proxy['volumeMounts'], [{'name': 'haproxy', 'mountPath': '/config', 'readOnly': True}])
            config = self.resource('ConfigMap', 'proxy-'+str(i)+'-haproxy')['data']['haproxy.cfg']
            self.assertIn('send-proxy-v2 check-send-proxy', config)
            self.assertIn('broker-'+str(i)+'.test.svc.cluster.local:1883', config)
            self.assertIn('parse-resolv-conf', config)
            self.assertIn('timeout client 2h', config)

    def test_vernemq_auth_storage_and_security(self):
        auth = self.resource('Secret', 'mqtt-auth')['stringData']
        credentials = json.loads(auth['credentials.json'])
        self.assertEqual(credentials['password'], auth['password'])
        self.assertGreaterEqual(len(auth['password']), 32)
        # VerneMQ uses `topic FILTER` for read + write, not Mosquitto's readwrite token.
        self.assertEqual(self.resource('ConfigMap', 'mqtt-acl')['data']['vmq.acl'],
                         'user wgtest\ntopic isolated/#\n')
        for i in range(1, 4):
            pod = self.resource('Pod', 'broker-'+str(i))['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(pod['securityContext']['fsGroup'], 10000)
            self.assertTrue(all('persistentVolumeClaim' not in v for v in pod['volumes']))
            container = pod['containers'][0]
            self.assertEqual(container['securityContext']['runAsUser'], 10000)
            env = {e['name']: e for e in container['env']}
            self.assertEqual(env['DOCKER_VERNEMQ_ALLOW_ANONYMOUS']['value'], 'off')
            self.assertEqual(env['DOCKER_VERNEMQ_LISTENER__TCP__DEFAULT__PROXY_PROTOCOL']['value'], 'on')
            self.assertNotIn('DOCKER_VERNEMQ_ACCEPT_EULA', env)
            self.assertIn('valueFrom', env['DOCKER_VERNEMQ_USER_WGTEST'])
            self.assertNotIn('/vernemq/etc', [m['mountPath'] for m in container['volumeMounts']])
        for resource in self.resources:
            if resource['kind'] not in ('Pod', 'Deployment'): continue
            spec = resource['spec'] if resource['kind'] == 'Pod' else resource['spec']['template']['spec']
            self.assertFalse(spec.get('hostNetwork', False))
            self.assertNotIn('sysctls', spec['securityContext'])
            for container in spec['containers'] + spec.get('initContainers', []):
                self.assertFalse(container['securityContext'].get('privileged', False))


class BrokerEvidenceTests(unittest.TestCase):
    def test_actual_session_rows_and_source_are_required(self):
        harness = object.__new__(system.Harness)
        rows = [{'client_id': 'held-0', 'peer_host': system.APN, 'is_online': True,
                 'session_pid': '<0.123.0>', 'session_started_at': '2026-11-03T12:00:00Z'}]
        harness.exec = lambda *args: json.dumps([{'type': 'table', 'table': rows}])
        self.assertEqual(harness.session_rows(1), rows)
        harness.session_rows = lambda index: rows if index == 1 else []
        self.assertEqual(harness.sessions([{'client_id': 'held-0'}])['held-0']['peer_host'], system.APN)
        rows[0]['peer_host'] = '10.0.0.10'
        with self.assertRaises(AssertionError): harness.sessions([{'client_id': 'held-0'}])
        rows.clear()
        with self.assertRaises(AssertionError): harness.sessions([{'client_id': 'held-0'}])

    def test_held_socket_and_sequence_cannot_be_replaced(self):
        harness = object.__new__(system.Harness)
        before = [{'client_id': 'held-0', 'socket': [['198.18.10.2', 1234], ['192.0.2.80', 12101]], 'sequence': 1}]
        after = [{**before[0], 'sequence': 2, 'puback': True, 'subscribed_echo': True}]
        harness.mqtt = lambda *args, **kwargs: after
        self.assertEqual(harness.held_check(before), after)
        after[0]['socket'] = [['198.18.10.2', 4321], ['192.0.2.80', 12101]]
        with self.assertRaises(AssertionError): harness.held_check(before)
        after[0] = {**before[0], 'puback': True, 'subscribed_echo': True}
        with self.assertRaises(AssertionError): harness.held_check(before)

    def test_sa_evidence_excludes_elapsed_state_and_requires_spis(self):
        harness = object.__new__(system.Harness)
        harness.exec = lambda *args: ('apn { uniqueid=3 initiator-spi=abc responder-spi=def '
                                      'child-sas { uniqueid=5 spi-in=123 spi-out=456 } }')
        self.assertEqual(harness.sa_identity(), ['123', '3', '456', '5', 'abc', 'def'])
        harness.exec = lambda *args: 'apn { uniqueid=3 state=ESTABLISHED }'
        with self.assertRaises(AssertionError): harness.sa_identity()


class MQTTProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('mqtt_probe_test', Path(__file__).with_name('system_mqtt_probe.py'))
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_real_connect_subscribe_qos1_sequences_on_same_socket(self):
        module = self.module
        errors, received = [], []
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            def broker():
                try:
                    connection, _ = server.accept()
                    with connection:
                        peer = object.__new__(module.Client)
                        peer.socket = connection
                        connection.settimeout(3)
                        kind, payload = peer.receive()
                        self.assertEqual(kind, 0x10)
                        self.assertIn(module.text('username')+module.text('private-password'), payload)
                        connection.sendall(module.packet(0x20, b'\x00\x00'))
                        kind, payload = peer.receive()
                        self.assertEqual(kind, 0x82)
                        connection.sendall(module.packet(0x90, b'\x00\x01\x01'))
                        for sequence in (1, 2, 3):
                            kind, payload = peer.receive()
                            self.assertEqual(kind, 0x32)
                            received.append(payload)
                            length = int.from_bytes(payload[:2], 'big')
                            packet_id = payload[2+length:4+length]
                            self.assertTrue(payload.endswith(('client:'+str(sequence)).encode()))
                            # Alternate PUBACK order relative to subscribed echo.
                            publish = module.packet(0x32, payload)
                            ack = module.packet(0x40, packet_id)
                            connection.sendall(publish+ack if sequence % 2 else ack+publish)
                            self.assertEqual(peer.receive(), (0x40, packet_id))
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=broker)
            worker.start()
            client = module.Client('client', server.getsockname()[1],
                                   {'username': 'username', 'password': 'private-password'},
                                   source='127.0.0.1', host='127.0.0.1')
            try:
                identity = client.identity
                self.assertEqual(client.roundtrip()['sequence'], 2)
                self.assertEqual(client.roundtrip()['sequence'], 3)
                self.assertEqual(client.identity, identity)
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors, errors)
                self.assertEqual(len(received), 3)
                with self.assertRaises(ConnectionError):
                    client.roundtrip()
            finally:
                client.close()

    def test_bad_and_oversized_packets_fail_closed(self):
        for payload in (b'\x30\xff\xff\xff\xff', b'\x30\xff\xff\x7f'):
            with self.subTest(payload=payload):
                left, right = socket.socketpair()
                try:
                    client = object.__new__(self.module.Client)
                    client.socket = left
                    left.settimeout(1)
                    right.sendall(payload)
                    with self.assertRaises(ValueError): client.receive()
                finally:
                    left.close()
                    right.close()


class ArgumentTests(unittest.TestCase):
    def arguments(self):
        digest = 'image@sha256:'+'a'*64
        return ['--kubeconfig', '/not-used', '--nodes', 'one', 'two', 'three'] + [
            item for name in ('wg', 'strongswan', 'unbound', 'exporter', 'probe', 'haproxy', 'broker')
            for item in ('--'+name+'-image', digest)]

    def test_images_and_bounded_count(self):
        args = system.arguments(self.arguments())
        self.assertEqual(args.connection_count, 300)
        self.assertFalse(args.execute)
        for option, value in [('--connection-count', '1001'), ('--connection-count', '0'),
                              ('--connection-interval', '-1'), ('--connection-interval', 'nan'),
                              ('--haproxy-image', 'haproxy:latest'), ('--broker-image', 'broker:latest')]:
            with self.subTest(option=option, value=value), self.assertRaises(SystemExit):
                system.arguments(self.arguments()+[option, value])


if __name__ == '__main__':
    unittest.main()
