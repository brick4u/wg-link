"""Offline contract tests: no Docker, Kubernetes, network or cloud I/O."""
import importlib.util
import contextlib
import io
import socket
import struct
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ha_acceptance', Path(__file__).with_name('ha_service_acceptance.py'))
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)
IMAGE = 'public.example/wg@sha256:' + 'a'*64


def argv(output):
    return ['--kubeconfig', '/explicit/config', '--nodes', 'one', 'two', 'three',
            '--output', output, *[x for name in ('wg', 'probe', 'unbound', 'haproxy', 'broker')
                                  for x in ('--'+name+'-image', IMAGE)]]


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = ha.Harness(ha.arguments(argv(self.tmp.name)))

    def topology(self):
        objects = []
        with patch.object(self.h, 'run', return_value='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'), \
             patch.object(self.h, 'apply', side_effect=objects.extend):
            self.h.topology()
        return objects

    def test_opt_in_blocks_every_subprocess(self):
        with patch.object(ha.base.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, '--execute'):
                self.h.k('get', 'pods')
            run.assert_not_called()

    def test_cli_pins_and_deadline(self):
        for old, new in [(IMAGE, 'public.example/wg:latest'), ('three', 'two')]:
            args = [new if value == old else value for value in argv(self.tmp.name)]
            with self.assertRaises(SystemExit):
                ha.arguments(args)
        with self.assertRaises(SystemExit):
            ha.arguments(argv(self.tmp.name)+['--timeout', '301'])

    def test_private_output(self):
        self.assertEqual(self.h.out.stat().st_mode & 0o777, 0o700)
        self.assertFalse(self.h.result['scope']['cloud_actions'])
        self.assertFalse(self.h.result['scope']['ipsec'])

    def test_three_gateways_independent_application_and_identity(self):
        objects = self.topology()
        gateways = [o for o in objects if o['kind'] == 'Pod' and o['metadata']['name'] in ha.GATEWAYS]
        self.assertEqual(len(gateways), 3)
        for pod in gateways:
            wg, app = pod['spec']['containers']
            self.assertEqual(app['name'], 'application')
            self.assertEqual(app['readinessProbe']['periodSeconds'], 1)
            self.assertEqual(app['readinessProbe']['failureThreshold'], 3)
            env = {e['name']: e for e in wg['env']}
            self.assertEqual(env['POD_UID']['valueFrom']['fieldRef']['fieldPath'], 'metadata.uid')
            self.assertEqual(env['OWNPOD_ID']['valueFrom']['fieldRef']['fieldPath'], 'metadata.uid')
            self.assertEqual(env['WG_CONTAINER_NAME']['value'], 'wg-link')
            self.assertNotIn('hostNetwork', pod['spec'])
        cfg = json.loads(next(o for o in objects if o['kind'] == 'ConfigMap' and
                              o['metadata']['name'] == 'gateway')['data']['config.yaml'])
        self.assertEqual(cfg['activation']['kubernetesLease']['requireReadyContainers'], ['application'])
        self.assertEqual({i['listenPort'] for i in cfg['interfaces']}, set(ha.PORTS))
        self.assertEqual(len(cfg['forwarding']['dnat']), 3)

    def test_six_clients_filter_same_namespace_lease(self):
        objects = self.topology()
        for name in ha.CLIENTS:
            cfg = json.loads(next(o for o in objects if o['kind'] == 'ConfigMap' and
                                  o['metadata']['name'] == name)['data']['config.yaml'])
            refs = [p['service'] for i in cfg['interfaces'] for p in i['peers']
                    if p['service']['name'] == 'gateway']
            self.assertEqual(len(refs), 1, name)
            self.assertEqual(refs[0]['leaseName'], ha.LEASE)
            self.assertEqual(refs[0]['namespace'], self.h.ns)
        support = json.loads(next(o for o in objects if o['kind'] == 'ConfigMap' and
                                  o['metadata']['name'] == 'support')['data']['config.yaml'])
        routes = {r for i in support['interfaces'] for r in i['routes']}
        self.assertTrue({x+'/32' for x in ha.base.DNS}.issubset(routes))
        self.assertTrue(all(o['metadata']['labels'][ha.base.OWNER] == self.h.token for o in objects))

    def test_synthetic_remote_lan_is_seventh_lease_consumer_without_onlink_routes(self):
        objects = self.topology()
        configs = {o['metadata']['name']: json.loads(o['data']['config.yaml']) for o in objects
                   if o['kind'] == 'ConfigMap' and 'config.yaml' in o['data']}
        gateway = configs['gateway']
        self.assertEqual({i['name'] for i in gateway['interfaces']}, ha.GATEWAY_INTERFACES)
        lan = next(i for i in gateway['interfaces'] if i['name'] == 'wg-lan')
        self.assertEqual(lan['listenPort'], 51824)
        self.assertEqual(lan['routes'], [ha.base.APN+'/32'])
        remote = configs['provider']['interfaces'][0]
        self.assertEqual(remote['addresses'], ['198.18.11.2/32'])
        self.assertEqual(remote['peers'][0]['service']['leaseName'], ha.LEASE)
        self.assertEqual(set(remote['routes']), {x+'/32' for x in [*ha.base.DNS, ha.base.BROKER_IP, ha.base.CLIENT]})
        consumers = [name for name, c in configs.items() if any(
            p.get('service', {}).get('leaseName') == ha.LEASE for i in c['interfaces'] for p in i['peers'])]
        self.assertEqual(set(consumers), set(ha.CLIENTS)|{'provider'})
        self.assertTrue(all(d['from'] == 'wg-lan' for d in gateway['forwarding']['dnat']))
        self.assertTrue(all('eth0' not in (r['from'], r['to']) for r in gateway['forwarding']['rules']))
        provider = next(o for o in objects if o['kind'] == 'Pod' and o['metadata']['name'] == 'provider')
        self.assertEqual([c['name'] for c in provider['spec']['containers']], ['wg-link', 'probe', 'mqtt'])
        self.assertEqual(provider['spec']['initContainers'][0]['command'],
                         ['ip', 'address', 'add', ha.base.APN+'/32', 'dev', 'lo'])
        self.assertNotIn('onlink', json.dumps(objects))
        self.assertNotIn('remote-return', json.dumps(objects))

    def test_reuses_three_proxy_deployments_no_host_privileges(self):
        objects = self.topology()
        deployments = [o for o in objects if o['kind'] == 'Deployment']
        self.assertEqual(len(deployments), 3)
        for obj in objects:
            if obj['kind'] not in ('Pod', 'Deployment'):
                continue
            spec = obj['spec'] if obj['kind'] == 'Pod' else obj['spec']['template']['spec']
            self.assertFalse(spec.get('hostNetwork', False))
            self.assertFalse(spec.get('hostPID', False))
            self.assertTrue(all('hostPath' not in v for v in spec['volumes']))
            for container in spec['containers']+spec.get('initContainers', []):
                self.assertFalse(container['securityContext'].get('privileged', False))
                self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])

    def test_cleanup_checks_namespace_uid(self):
        self.h.created = True
        self.h.namespace_uid = 'expected'
        obj = {'metadata': {'uid': 'replacement', 'labels': {ha.base.OWNER: self.h.token}}}
        with patch.object(self.h, 'k', return_value=json.dumps(obj)) as k:
            with self.assertRaisesRegex(AssertionError, 'UID mismatch'):
                self.h.cleanup()
            self.assertEqual(k.call_count, 1)

    def test_cleanup_checks_owner(self):
        self.h.created = True
        with patch.object(self.h, 'k', return_value=json.dumps({'metadata': {'uid': 'x', 'labels': {}}})) as k:
            with self.assertRaisesRegex(AssertionError, 'owner mismatch'):
                self.h.cleanup()
            self.assertEqual(k.call_count, 1)

    def test_zero_healthy_and_nondeterministic_successor(self):
        with patch.object(self.h, 'snapshot', return_value={'healthy': [], 'active': None}):
            self.assertTrue(self.h.converged(0))
        for successor in ('gateway-2', 'gateway-3'):
            with patch.object(self.h, 'snapshot', return_value={'healthy': ['x', 'y'], 'active': successor}):
                self.assertTrue(self.h.converged(2, 'gateway-1'))
        with patch.object(self.h, 'snapshot', return_value={'healthy': ['x', 'y'], 'active': 'gateway-1'}):
            self.assertFalse(self.h.converged(2, 'gateway-1'))

    def test_stale_ready_selects_only_lease_uid(self):
        pods = {name: {'metadata': {'name': name, 'uid': name+'-uid'}, 'status': {
            'containerStatuses': [{'name': 'wg-link', 'ready': True},
                                  {'name': 'application', 'ready': True}]}} for name in ha.GATEWAYS}
        def obj(kind, name):
            return {'spec': {'holderIdentity': 'gateway-2-uid'}} if kind == 'lease' else pods[name]
        with patch.object(self.h, 'obj', side_effect=obj):
            result = self.h.snapshot()
        self.assertEqual(result['active'], 'gateway-2')
        self.assertEqual(result['staleReady'], ['gateway-1', 'gateway-3'])
        for p in pods.values():
            p['status']['containerStatuses'][1]['ready'] = False
        with patch.object(self.h, 'obj', side_effect=obj):
            self.assertIsNone(self.h.snapshot()['active'])

    def test_uid_delete_uses_api_precondition(self):
        with patch.object(self.h, 'k', return_value='') as k:
            self.h.delete_uid('/api/v1/namespaces/owned', 'owned-uid')
        self.assertEqual(k.call_args.args, ('delete', '--raw', '/api/v1/namespaces/owned', '-f', '-'))
        self.assertEqual(json.loads(k.call_args.kwargs['data'])['preconditions'], {'uid': 'owned-uid'})

    def test_explicit_named_broker_mapping(self):
        self.assertEqual(ha.BROKER_PATHS, (('broker-1', 12101), ('broker-2', 12201), ('broker-3', 1883)))
        flows = [{'client_id': 'group-'+str(i)} for i in range(3)]
        def rows(index):
            return [{'client_id': 'group-'+str(index-1), 'peer_host': ha.base.APN,
                     'is_online': True, 'session_pid': 'pid', 'session_started_at': 'now'}]
        with patch.object(self.h, 'session_rows', side_effect=rows):
            sessions = self.h.sessions(flows)
        for i, (broker, port) in enumerate(ha.BROKER_PATHS):
            self.assertEqual(sessions['group-'+str(i)]['broker'], broker)
            self.assertEqual(sessions['group-'+str(i)]['destination_port'], port)

    def test_fresh_client_recreated_and_endpoint_selected(self):
        self.h.fresh_client_template = {'kind': 'Pod', 'metadata': {'name': 'dns-1'}}
        with patch.object(self.h, 'obj', side_effect=[{'metadata': {'uid': 'old'}}, {'metadata': {'uid': 'new'}}]), \
             patch.object(self.h, 'delete_uid') as delete, patch.object(self.h, 'k'), \
             patch.object(self.h, 'apply') as apply, \
             patch.object(self.h, 'wait', side_effect=[True, {'dns-1': '10.0.0.2:51820'}]):
            self.assertTrue(self.h.fresh_client('gateway-2'))
        delete.assert_called_once_with('/api/v1/namespaces/'+self.h.ns+'/pods/dns-1', 'old')
        apply.assert_called_once_with([self.h.fresh_client_template])
        self.assertEqual(self.h.result['fresh_client']['uid'], 'new')

    def test_unbound_static_config_requires_no_writable_runtime_directory(self):
        self.assertIn(' directory: "/"\n', ha.UNBOUND)
        self.assertIn(' pidfile: ""\n', ha.UNBOUND)
        self.assertIn(' chroot: ""\n', ha.UNBOUND)
        self.assertIn(' username: ""\n', ha.UNBOUND)
        self.assertNotIn('/tmp', ha.UNBOUND)

    def test_dns_sinkhole_a_and_aaaa_probe_without_network(self):
        self.assertIn('IN A 127.0.0.1', ha.UNBOUND)
        self.assertIn('IN AAAA ::1', ha.UNBOUND)
        for proto in ('udp', 'tcp'):
            for qtype, answer, family in [(1, '127.0.0.1', socket.AF_INET), (28, '::1', socket.AF_INET6)]:
                question = b'\x08sinkhole\x07example\0'+struct.pack('!HH', qtype, 1)
                data = socket.inet_pton(family, answer)
                packet = struct.pack('!HHHHHH', 7, 0x8180, 1, 1, 0, 0)+question
                packet += b'\xc0\x0c'+struct.pack('!HHIH', qtype, 1, 60, len(data))+data
                class FakeSocket:
                    def __init__(self):
                        self.incoming = (struct.pack('!H', len(packet)) if proto == 'tcp' else b'')+packet
                    def settimeout(self, value): pass
                    def bind(self, value): pass
                    def connect(self, value): pass
                    def send(self, value):
                        self.question = value
                    sendall = send
                    def recv(self, length):
                        value, self.incoming = self.incoming[:length], self.incoming[length:]
                        return value
                sock = FakeSocket()
                args = ['dns.py', ha.base.APN, ha.base.DNS[0], proto, 'sinkhole.example', answer, str(qtype)]
                with patch('socket.socket', return_value=sock), patch('sys.argv', args), \
                     patch('random.randrange', return_value=7), contextlib.redirect_stdout(io.StringIO()) as out:
                    exec(ha.DNS_PROBE, {})
                self.assertIn(answer, json.loads(out.getvalue())['answers'])
                self.assertEqual(sock.question[-4:], struct.pack('!HH', qtype, 1))

    def test_faults_disabled_by_default(self):
        self.assertFalse(self.h.a.fault_tests)
        self.assertTrue(ha.arguments(argv(self.tmp.name)+['--fault-tests']).fault_tests)

    def test_sigstop_always_resumes_after_wait_failure(self):
        with patch.object(self.h, 'wait', side_effect=[{'active': 'gateway-1'}, RuntimeError('fault failed')]), \
             patch.object(self.h, 'exec', return_value='State:\tT (stopped)\n'), \
             patch.object(self.h, 'signal_wg', return_value='23\n') as signal:
            with self.assertRaisesRegex(RuntimeError, 'fault failed'):
                self.h.frozen_process()
        self.assertEqual(signal.call_args_list[0].args, ('gateway-1', 'STOP'))
        self.assertEqual(signal.call_args_list[1].args, ('gateway-1', 'CONT'))
        self.assertFalse(self.h.cleaning)

    def test_ambiguous_stop_response_still_resumes(self):
        with patch.object(self.h, 'wait', return_value={'active': 'gateway-1'}), \
             patch.object(self.h, 'exec', return_value='wg-link\n'), \
             patch.object(self.h, 'signal_wg', side_effect=[RuntimeError('exec timeout'), None]) as signal:
            with self.assertRaisesRegex(RuntimeError, 'exec timeout'):
                self.h.frozen_process()
        self.assertEqual(signal.call_args_list[-1].args, ('gateway-1', 'CONT'))

    def test_signal_validates_child_pid_name_and_birth_before_bounded_exec(self):
        for action in ('STOP', 'CONT'):
            with patch.object(self.h, 'k', return_value='') as k:
                self.h.signal_wg('gateway-2', action)
            self.assertEqual(k.call_args.args[:9], ('exec', '-n', self.h.ns, 'gateway-2', '-c',
                'wg-link', '--', '/bin/sh', '-ec'))
            script = k.call_args.args[-1]
            self.assertIn('read -r p birth < /tmp/wg-test-pid', script)
            self.assertIn('[ "$p" -gt 1 ]', script)
            self.assertIn('[ "$(cat /proc/$p/comm)" = wg-link ]', script)
            self.assertIn('[ "$1" = "$birth" ]', script)
            self.assertIn('kill -'+action+' "$p"', script)
            self.assertNotIn('kill -'+action+' 1', script)
            self.assertEqual(k.call_args.kwargs['timeout'], 5)
        with self.assertRaises(AssertionError):
            self.h.signal_wg('host', 'STOP')

    def test_only_fault_gateway_containers_get_child_wrapper(self):
        baseline = self.topology()
        self.h.a.fault_tests = True
        fault = self.topology()
        for objects, wrapped in ((baseline, False), (fault, True)):
            for obj in objects:
                if obj['kind'] != 'Pod':
                    continue
                gateway = obj['metadata']['name'] in ha.GATEWAYS
                for c in obj['spec']['containers']:
                    if c['name'] != 'wg-link':
                        continue
                    self.assertEqual('command' in c, wrapped and gateway)
                    if wrapped and gateway:
                        self.assertIn('/usr/local/bin/wg-link', c['command'][-1])
                        self.assertIn('/tmp/wg-test-pid', c['command'][-1])
                        self.assertIn('shift 21', c['command'][-1])
                        self.assertIn('trap ', c['command'][-1])
                        self.assertNotIn('args', c)
                    else:
                        self.assertEqual(c['args'], ['-config', '/config/config.yaml', '-listen', ':9090'])

    def test_fault_refuses_namespace_pid1_and_still_restores(self):
        with patch.object(self.h, 'wait', return_value={'active': 'gateway-1'}), \
             patch.object(self.h, 'signal_wg', return_value='1\n') as signal:
            with self.assertRaisesRegex(AssertionError, 'not namespace PID1'):
                self.h.frozen_process()
        self.assertEqual(signal.call_args_list[-1].args, ('gateway-1', 'CONT'))

    def test_partition_scoped_and_restored_after_wait_failure(self):
        with patch.object(self.h, 'wait', side_effect=[{'active': 'gateway-1'}, RuntimeError('fault failed')]), \
             patch.object(self.h, 'api_table', return_value=[]), \
             patch.object(self.h, 'exec', return_value='["10.47.0.1",443]'), \
             patch.object(self.h, 'k') as k, patch.object(self.h, 'remove_api_partition') as remove:
            with self.assertRaisesRegex(RuntimeError, 'fault failed'):
                self.h.partition_api()
        args = k.call_args.args
        self.assertEqual(args[:7], ('exec', '-i', '-n', self.h.ns, 'gateway-1', '-c', 'wg-link'))
        rules = k.call_args.kwargs['data']
        self.assertIn('ip daddr 10.47.0.1 tcp dport 443 drop', rules)
        self.assertIn('hook output', rules)
        self.assertIn(self.h.token, rules)
        self.assertNotIn('flush', rules)
        self.assertNotIn('input', rules)
        remove.assert_called_once_with('gateway-1')
        self.assertFalse(self.h.cleaning)

    def test_ambiguous_partition_install_still_attempts_cleanup(self):
        with patch.object(self.h, 'wait', return_value={'active': 'gateway-1'}), \
             patch.object(self.h, 'api_table', return_value=[]), \
             patch.object(self.h, 'exec', return_value='["10.47.0.1",443]'), \
             patch.object(self.h, 'k', side_effect=RuntimeError('ambiguous install')), \
             patch.object(self.h, 'remove_api_partition') as remove:
            with self.assertRaisesRegex(RuntimeError, 'ambiguous install'):
                self.h.partition_api()
        remove.assert_called_once_with('gateway-1')

    def test_restore_can_use_reserved_deadline_budget(self):
        self.h.a.execute = True
        completed = ha.base.subprocess.CompletedProcess([], 0, stdout='', stderr='')
        with patch.object(ha.time, 'monotonic', return_value=self.h.deadline-35), \
             patch.object(ha.base.subprocess, 'run', return_value=completed) as run:
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                self.h.signal_wg('gateway-1', 'CONT')
            self.h.restore(lambda: self.h.signal_wg('gateway-1', 'CONT'))
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['timeout'], 5)
        self.assertFalse(self.h.cleaning)

    def test_api_partition_refuses_existing_table(self):
        with patch.object(self.h, 'wait', return_value={'active': 'gateway-1'}), \
             patch.object(self.h, 'api_table', return_value=[{'table': {'name': 'wg_ha_test_api'}}]), \
             patch.object(self.h, 'k') as k:
            with self.assertRaisesRegex(AssertionError, 'already exists'):
                self.h.partition_api()
            k.assert_not_called()

    def test_partition_cleanup_validates_owner_and_deletes_only_table(self):
        for owner in ('foreign', self.h.token):
            raw = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'wg_ha_test_api', 'comment': owner}}]})
            with patch.object(self.h, 'k', return_value=raw) as k:
                if owner == 'foreign':
                    with self.assertRaisesRegex(AssertionError, 'foreign'):
                        self.h.remove_api_partition('gateway-1')
                    self.assertEqual(k.call_count, 1)
                else:
                    self.h.remove_api_partition('gateway-1')
                    self.assertEqual(k.call_args.args[-5:], ('nft', 'delete', 'table', 'inet', 'wg_ha_test_api'))

    def test_expired_kernel_allowance_not_open(self):
        def table(expires):
            return {'nftables': [{'set': {'name': 'active_ports', 'elem': [{'elem': {'val': 51820, 'expires': expires}}]}}]}
        self.assertFalse(self.h.gate_open(table(0)))
        self.assertTrue(self.h.gate_open(table(1500)))
        self.assertFalse(self.h.gate_open({'nftables': []}))

    def test_gate_closes_before_handoff_with_live_application(self):
        with patch.object(self.h, 'exec', side_effect=['{"nftables":[]}', '']) as execute, \
             patch.object(self.h, 'obj', side_effect=[{'spec': {'holderIdentity': 'old'}}, {'metadata': {'uid': 'old'}}]), \
             patch.object(ha.time, 'monotonic', return_value=100):
            value = self.h.closed_while_application_alive('gateway-1', 97, 6)
        self.assertEqual(value['closed_after_seconds'], 3)
        self.assertTrue(value['application_http_alive'])
        self.assertEqual(execute.call_args.args[1], 'application')

    def test_diagnostics_persists_only_status_events_selected_redacted_logs(self):
        self.h.created = True
        self.h.namespace_uid = 'ns-uid'
        self.h.sensitive.append('private-token')
        ns = {'metadata': {'uid': 'ns-uid', 'labels': {ha.base.OWNER: self.h.token}}}
        pods = {'items': [{'metadata': {'name': 'gateway-1', 'uid': 'pod-uid',
                           'labels': {ha.base.OWNER: self.h.token}},
                          'status': {'phase': 'Running'},
                          'spec': {'secret': 'must-not-persist', 'containers': [
                              {'name': 'wg-link'}, {'name': 'application'}, {'name': 'mqtt'}]}}]}
        answers = [json.dumps(ns), json.dumps(pods), json.dumps({'items': [{'message': 'event'}]}),
                   'log private-token', 'application log']
        with patch.object(self.h, 'k', side_effect=answers) as k:
            self.h.diagnostics()
        summary = (self.h.out/'failure-pod-status.json').read_text()
        self.assertNotIn('spec', summary)
        self.assertNotIn('must-not-persist', summary)
        self.assertIn('Running', summary)
        self.assertEqual((self.h.out/'failure-gateway-1-wg-link.log').read_text(), 'log [REDACTED]')
        for record in self.h.result['diagnostics']:
            if 'file' in record:
                self.assertEqual((self.h.out/record['file']).stat().st_mode & 0o777, 0o600)
        logs = [call for call in k.call_args_list if call.args[0] == 'logs']
        self.assertEqual(len(logs), 2)
        self.assertTrue(all(call.args[-1] == '--tail=40' and call.kwargs['timeout'] <= 3 for call in logs))
        self.assertFalse(self.h.cleaning)

    def test_diagnostics_preserves_namespace_cleanup_time(self):
        self.h.created = True
        with patch.object(ha.time, 'monotonic', return_value=self.h.deadline-29), \
             patch.object(self.h, 'k') as k:
            self.h.diagnostics()
        k.assert_not_called()
        self.assertEqual(self.h.result['diagnostics'][-1]['collection_error'], 'TimeoutError')
        self.assertFalse(self.h.cleaning)

    def test_diagnostics_refuses_unowned_namespace(self):
        self.h.created = True
        with patch.object(self.h, 'k', return_value=json.dumps({'metadata': {'labels': {}}})) as k:
            self.h.diagnostics()
        self.assertEqual(k.call_count, 1)
        self.assertEqual(self.h.result['diagnostics'][-1]['collection_error'], 'AssertionError')

    def test_backend_fault_always_restores_exact_interface_after_wait_failure(self):
        original = {'ifname': 'wg-dns', 'ifindex': 7, 'ifalias': 'wg-link:v1'}
        with patch.object(self.h, 'wait', side_effect=[{'active': 'gateway-1'}, RuntimeError('backend failed')]), \
             patch.object(self.h, 'stable_identity', return_value={}), \
             patch.object(self.h, 'exec', side_effect=[json.dumps([original]), '']) as execute, \
             patch.object(self.h, 'restore_alias', return_value='restored') as restore:
            with self.assertRaisesRegex(RuntimeError, 'backend failed'):
                self.h.backend_failure()
        self.assertEqual(execute.call_args.args, ('gateway-1', 'wg-link', 'ip', 'link', 'set',
            'dev', 'wg-dns', 'alias', 'wg-ha-test-foreign-'+self.h.token))
        restore.assert_called_once_with('gateway-1', original, 'wg-ha-test-foreign-'+self.h.token)
        self.assertFalse(self.h.cleaning)

    def test_alias_restoration_checks_ifindex_and_marker_before_mutating(self):
        original = {'ifname': 'wg-dns', 'ifindex': 7, 'ifalias': 'wg-link:v1'}
        marker = 'wg-ha-test-foreign-'+self.h.token
        for index, alias, expected in [(7, marker, 'original_alias_restored'),
                                       (7, 'wg-link:v1', 'original_alias_unchanged'),
                                       (8, marker, None), (7, 'unrelated', None)]:
            link = dict(original, ifindex=index, ifalias=alias)
            with patch.object(self.h, 'k', return_value=json.dumps([link])) as k:
                if expected:
                    self.assertEqual(self.h.restore_alias('gateway-1', original, marker), expected)
                    self.assertEqual(k.call_count, 2 if alias == marker else 1)
                    if alias == marker:
                        self.assertEqual(k.call_args.args[-7:],
                            ('ip', 'link', 'set', 'dev', 'wg-dns', 'alias', 'wg-link:v1'))
                else:
                    with self.assertRaises(AssertionError):
                        self.h.restore_alias('gateway-1', original, marker)
                    self.assertEqual(k.call_count, 1)

    def test_alias_cleanup_tolerates_interface_already_removed(self):
        original = {'ifname': 'wg-dns', 'ifindex': 7, 'ifalias': 'wg-link:v1'}
        with patch.object(self.h, 'k', return_value='[]') as k:
            self.assertEqual(self.h.restore_alias('gateway-1', original,
                'wg-ha-test-foreign-'+self.h.token), 'link_already_removed')
        self.assertEqual(k.call_count, 1)

    def test_backend_fault_records_successor_and_unchanged_container_identity(self):
        original = {'ifname': 'wg-dns', 'ifindex': 7, 'ifalias': 'wg-link:v1'}
        with patch.object(self.h, 'wait', side_effect=[{'active': 'gateway-1'}, True, {'active': 'gateway-3'}, True]), \
             patch.object(self.h, 'stable_identity', return_value={'uid': 'same'}), \
             patch.object(self.h, 'exec', side_effect=[json.dumps([original]), '', '']), \
             patch.object(self.h, 'restore_alias', return_value='original_alias_restored'):
            self.h.backend_failure()
        record = self.h.result['faults'][-1]
        self.assertEqual(record['successor'], 'gateway-3')
        self.assertTrue(record['pod_container_identities_unchanged'])
        self.assertTrue(record['closed_before_successor_validation'])

    def test_cleanup_time_reserved(self):
        with patch.object(ha.time, 'monotonic', return_value=self.h.deadline-29), \
             patch.object(ha.base.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                self.h.run(['anything'])
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
