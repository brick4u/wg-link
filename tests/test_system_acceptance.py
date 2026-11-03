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
                              probe_image='probe', nodes=['node-a', 'node-b', 'node-c'])
        h.ns, h.token, h.sink, h.sensitive = 'test', 'unit-token', '192.0.2.2', []
        # Inspect manifests offline; credential generation is irrelevant here.
        h.run = lambda *args, **kwargs: base64.b64encode(os.urandom(32)).decode()
        self.resources = []
        h.apply = self.resources.extend
        h.topology()

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

    def test_nat_scope_and_unbound_identity(self):
        cfg = json.loads(self.resource('ConfigMap', 'gateway')['data']['config.yaml'])
        self.assertEqual(cfg['forwarding']['externalInterfaces'], ['eth0'])
        self.assertEqual(cfg['forwarding']['masquerade'],
                         [{'from': 'eth0', 'to': 'eth0', 'source': '198.18.10.0/24',
                           'destination': '192.0.2.2/32'}])
        dns = self.resource('Pod', 'dns')
        resolver = next(c for c in dns['spec']['containers'] if c['name'] == 'unbound')
        self.assertEqual(resolver['command'][0], '/usr/sbin/unbound')
        self.assertEqual(resolver['securityContext']['runAsUser'], 101)
        self.assertEqual(resolver['securityContext']['runAsGroup'], 102)


if __name__ == '__main__':
    unittest.main()
