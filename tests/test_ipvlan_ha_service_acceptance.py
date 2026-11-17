#!/usr/bin/env python3
"""Offline only: exact selectors/cleanup, manifests, composition and I/O gates."""
import base64
import copy
import ipaddress
import io
import json
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ipvlan_ha_service_acceptance as h
from test_ipvlan_ipsec_acceptance import arguments as native_arguments


def arguments():
    extra = []
    for name in ('wg-image', 'probe-image', 'unbound-image', 'haproxy-image', 'broker-image'):
        extra += ['--'+name, 'example.invalid/'+name+'@sha256:'+'c'*64]
    return native_arguments()+extra


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.a = h.parser().parse_args(arguments())

    def test_review_only_no_subprocess_or_network_or_output(self):
        with patch.object(h, 'execute', side_effect=AssertionError('executed')), \
             patch.object(h.subprocess, 'run', side_effect=AssertionError('process')), \
             patch.object(h.native.urllib.request, 'urlopen', side_effect=AssertionError('network')):
            self.assertEqual(h.main(arguments()), 0)

    def test_constructor_is_offline_and_keeps_original_args(self):
        before = vars(self.a).copy()
        with patch.object(h.subprocess, 'run', side_effect=AssertionError('process')):
            run = h.Run(self.a)
        self.assertEqual(vars(self.a), before)
        self.assertEqual(run.ns, run.services.ns)
        self.assertEqual(run.services.a.nodes, [self.a.owner_node, self.a.standby_node, self.a.owner_node])

    def test_direct_kubernetes_calls_require_execute(self):
        run = h.Run(self.a)
        with patch.object(h.subprocess, 'run', side_effect=AssertionError('process')):
            with self.assertRaisesRegex(RuntimeError, '--execute'):
                run.kubectl(False, ['get', 'pods'])

    def test_images_and_phase_validation(self):
        h.validate(self.a)
        self.a.wg_image = 'mutable:latest'
        with self.assertRaises(RuntimeError):
            h.validate(self.a)
        self.a = h.parser().parse_args(arguments()+['--extended'])
        with self.assertRaises(RuntimeError):
            h.validate(self.a)

    def test_exact_protected_selector_list(self):
        values = h.selectors(self.a)
        self.assertEqual(len(values), 5)
        self.assertEqual(set(values), {self.a.customer_vip+'/32', '198.18.51.2/32',
            '198.18.51.3/32', '192.0.2.80/32', '198.18.40.2/32'})
        self.assertTrue(all(ipaddress.ip_network(v).prefixlen == 32 for v in values))
        self.a.customer_vip = h.DNS_VIPS[0]
        with self.assertRaises(RuntimeError):
            h.selectors(self.a)

    def test_profiles_exact_inverse_no_default_selector(self):
        for peer in (False, True):
            original = h.native.swan_config(self.a, peer, 'unit-psk', 123, auto=True)
            profile = h.expand_profile(self.a, original, peer)
            protected = 'remote_ts' if peer else 'local_ts'
            single = 'local_ts' if peer else 'remote_ts'
            self.assertEqual(re.findall(single+r' = ([^\n]+)', profile), [self.a.peer_vip+'/32']*5)
            self.assertEqual(set(re.findall(protected+r' = ([^\n]+)', profile)), set(h.selectors(self.a)))
            self.assertEqual(re.findall(r'reqid = (\d+)', profile), ['123', '124', '125', '126', '127'])
            self.assertEqual(re.findall(r'^      ([a-z0-9-]+) \{', profile, re.MULTILINE), list(h.CHILDREN))
            self.assertNotIn('0.0.0.0/0', profile)
            self.assertNotIn('/24', profile)
            self.assertNotIn(',198.', profile)
            self.assertEqual(profile.count('start_action = '+('none' if peer else 'trap|start')), 5)
            self.assertEqual(profile.count('life_time = 3600s'), 5)

    def test_cleanup_changes_only_policy_predicate_bytes(self):
        original = h.native.CLEANUP
        expanded = h.expanded_cleanup(self.a)
        before = 'ip xfrm policy list'
        state_expected = original.split(before)[0].replace('-v req="$REQID"', '-v req="$REQID" -v reqids="$REQIDS"')
        state_expected = state_expected.replace('    function emit()',
            '    BEGIN { n=split(reqids, ids, " "); for(i=1;i<=n;i++) approved_reqids[ids[i]]=1 }\n    function emit()')
        state_expected = state_expected.replace('$(i+1)==req', 'approved_reqids[$(i+1)]')
        self.assertEqual(state_expected, expanded.split(before)[0])
        suffix = '\ncleanup\n'
        self.assertEqual(original.split(suffix)[1], expanded.split(suffix)[1])
        predicate = next(line for line in expanded.splitlines() if 'idx!=""' in line)
        self.assertIn('owned', predicate)
        self.assertIn('idx', predicate)
        for selector in h.selectors(self.a):
            self.assertIn(selector, predicate)
        self.assertIn('-v outer_a="$PUBLIC_LOCAL" -v outer_b="$PUBLIC_REMOTE"', expanded)
        self.assertIn('tmpl_src==outer_a && tmpl_dst==outer_b', expanded)
        self.assertIn('tmpl_src==outer_b && tmpl_dst==outer_a', expanded)
        self.assertIn('tmpl_src=""; tmpl_dst=""', expanded)
        for forbidden in ('flush', 'ip route', 'iptables', 'sysctl', '0.0.0.0/0'):
            self.assertNotIn(forbidden, expanded)

    def test_cleanup_rejects_upstream_predicate_drift(self):
        with patch.object(h.native, 'CLEANUP', 'unexpected upstream cleanup'):
            with self.assertRaisesRegex(RuntimeError, 'review required'):
                h.expanded_cleanup(self.a)

    def test_expanded_cleanup_filters_owned_service_and_foreign_policies(self):
        fake = r'''
REQID=12345
REQIDS='12345 12346 12347 12348 12349'
PUBLIC_LOCAL=203.0.113.20
PUBLIC_REMOTE=192.0.2.10
VIP_LOCAL=198.19.70.2
VIP_REMOTE=198.19.70.1
ip() {
 case "$*" in
 'xfrm state list nokeys')
  printf '%s\n' 'src 203.0.113.20 dst 192.0.2.10' ' proto esp spi 0x123 reqid 12345 mode tunnel' \
    'src 203.0.113.99 dst 192.0.2.10' ' proto esp spi 0x999 reqid 12345 mode tunnel';;
 'xfrm policy list')
  printf '%s\n' 'src 198.19.70.2/32 dst 198.18.51.2/32' ' dir out priority 1 index 41' \
    ' tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 12345 mode tunnel' \
    'src 198.18.40.2/32 dst 198.19.70.2/32' ' dir in priority 1 index 42' \
    ' tmpl src 192.0.2.10 dst 203.0.113.20 proto esp reqid 12345 mode tunnel' \
    'src 198.19.70.2/32 dst 198.18.51.3/32' ' dir out priority 1 index 43' \
    ' tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 99999 mode tunnel' \
    'src 198.19.70.2/32 dst 198.18.99.1/32' ' dir out priority 1 index 44' \
    ' tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 12345 mode tunnel' \
    'src 198.19.70.2/32 dst 198.18.51.2/32' ' dir out priority 1 index 45' \
    ' tmpl src 203.0.113.99 dst 192.0.2.10 proto esp reqid 12345 mode tunnel';;
 'xfrm state delete '*|'xfrm policy delete '*) printf 'DELETE %s\n' "$*";;
 '-o addr show dev lo') :;;
 *) echo "Unexpected mocked ip command: $*" >&2; return 77;;
 esac
}
'''
        selection = h.expanded_cleanup(self.a).split('\nstates=$(', 1)[0]
        result = subprocess.run(['/bin/sh', '-ec', fake+'\n'+selection], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            'DELETE xfrm state delete src 203.0.113.20 dst 192.0.2.10 proto esp spi 0x123',
            'DELETE xfrm policy delete index 41 dir out', 'DELETE xfrm policy delete index 42 dir in'])

    def test_recovery_manifest_reuses_stop_and_scoped_cleanup(self):
        run = h.Run(self.a)
        original = h.native.recovery_pod(self.a, run.ns, run.reqid, run.run_uuid)
        with patch.object(h.native.Run, 'create', side_effect=lambda peer, obj: obj):
            pod = run.create(True, original)
        script = pod['spec']['containers'][0]['command'][-1]
        self.assertIn(h.native.STOP_OWNED_CHARON, script)
        self.assertIn(run.cleanup_script, script)
        self.assertTrue(pod['spec']['hostPID'])
        env = {entry['name']: entry['value'] for entry in pod['spec']['containers'][0]['env']}
        self.assertEqual(env['REQIDS'].split(), list(map(str, run.reqids)))
        self.assertEqual(run.reqids, tuple(run.reqid+i for i in range(5)))
        self.assertNotIn('privileged', pod['spec']['containers'][0]['securityContext'])
        result = subprocess.run(['/bin/sh', '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_recovery_deadline_uses_remaining_global_budget(self):
        run = h.Run(self.a)
        original = h.native.recovery_pod(self.a, run.ns, run.reqid, run.run_uuid)
        with patch.object(run, 'remaining', return_value=60), \
             patch.object(h.native.Run, 'create', side_effect=lambda peer, obj: obj):
            pod = run.create(True, original)
        self.assertEqual(pod['spec']['activeDeadlineSeconds'], 210)
        self.assertEqual(pod['spec']['containers'][0]['command'][-1].splitlines()[1], 'sleep 90')

    def test_finally_cleanup_exec_also_uses_expanded_predicate(self):
        run = h.Run(self.a)
        command = ['/bin/sh', '-ec', h.native.STOP_OWNED_CHARON+h.native.CLEANUP]
        with patch.object(h.native.Run, 'exec', return_value=None) as execute:
            run.exec('recovery', command, True, container='recovery')
        actual = execute.call_args.args[1][-1]
        self.assertIn(run.cleanup_script, actual)
        self.assertIn(h.native.STOP_OWNED_CHARON, actual)

    def test_peer_probe_has_no_capabilities_and_preserves_watchdog_identity(self):
        run = h.Run(self.a)
        original = h.native.endpoint_pod(self.a, run.ns, 'peer', self.a.peer_node, True, run.run_uuid)
        with patch.object(h.native.Run, 'create', side_effect=lambda peer, obj: obj):
            pod = run.create(True, original)
        swan, probe = pod['spec']['containers']
        env = {x['name']: x for x in swan['env']}
        self.assertEqual(env['ACCEPTANCE_RUN']['value'], run.run_uuid)
        self.assertEqual(env['ACCEPTANCE_POD_UID']['valueFrom']['fieldRef']['fieldPath'], 'metadata.uid')
        self.assertEqual(probe['securityContext']['capabilities'], {'drop': ['ALL'], 'add': []})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertNotIn('hostPID', pod['spec'])
        boot = probe['command'][-1]
        compile(boot, 'peer-probe-boot', 'exec')
        self.assertLess(boot.index('s.bind((os.environ'), boot.index('subprocess.Popen'))
        self.assertLess(boot.index('s.bind((os.environ'), boot.index('runpy.run_path'))
        self.assertEqual(next(env['value'] for env in probe['env'] if env['name'] == 'BUDGET'), '45')

    def build_topology_offline(self):
        run = h.Run(self.a)
        objects = []
        with patch.object(run, 'create', side_effect=lambda peer, obj: objects.append((peer, copy.deepcopy(obj))) or obj), \
             patch.object(run.services, 'run', return_value='unit-key'):
            run.services.bootstrap()
        return run, objects

    def test_full_builder_removes_synthetic_lan_and_preserves_six_clients(self):
        run, objects = self.build_topology_offline()
        customer = [obj for peer, obj in objects if not peer]
        self.assertFalse(any(obj['metadata']['name'] == 'provider' for obj in customer))
        config = next(obj for obj in customer if obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'gateway')
        cfg = json.loads(config['data']['config.yaml'])
        self.assertEqual({iface['name'] for iface in cfg['interfaces']}, {'wg-dns', 'wg-broker', 'wg-transit'})
        self.assertEqual({iface['listenPort'] for iface in cfg['interfaces']}, {51820, 51821, 51822})
        self.assertNotIn('wg-lan', config['data']['config.yaml'])
        self.assertEqual(cfg['activation']['kubernetesLease']['requireReadyContainers'], ['swan'])
        self.assertEqual(cfg['forwarding']['externalInterfaces'], ['net1'])
        self.assertTrue(all(rule['from'] == 'net1' for rule in cfg['forwarding']['dnat']))
        key = next(obj for obj in customer if obj['kind'] == 'Secret' and obj['metadata']['name'] == 'gateway')
        self.assertEqual(set(key['data']), {'gd', 'gb', 'gt'})
        service = next(obj for obj in customer if obj['kind'] == 'Service' and obj['metadata']['name'] == 'gateway')
        self.assertEqual({port['port'] for port in service['spec']['ports']}, {51820, 51821, 51822})
        self.assertEqual(set(run.services.gateway_templates), {'owner', 'standby'})
        self.assertEqual(set(h.services.CLIENTS), {'dns-1', 'dns-2', 'proxy-1', 'proxy-2', 'proxy-3', 'support'})
        nodes = [obj['spec']['nodeName'] for obj in customer if obj['kind'] == 'Pod']
        nodes += [obj['spec']['template']['spec']['nodeName'] for obj in customer if obj['kind'] == 'Deployment']
        self.assertLessEqual(set(nodes), {self.a.owner_node, self.a.standby_node})

    def test_peer_probe_programs_compile_and_only_owned_listener_bindings(self):
        run, objects = self.build_topology_offline()
        peer_objects = [obj for peer, obj in objects if peer]
        self.assertEqual({(obj['kind'], obj['metadata']['name']) for obj in peer_objects},
                         {('ConfigMap', 'probe'), ('Secret', 'mqtt-auth')})
        probe = next(obj for obj in peer_objects if obj['kind'] == 'ConfigMap')
        for name, script in probe['data'].items():
            compile(script, name, 'exec')
        script = probe['data']['peer.py']
        self.assertNotIn("s.bind(('0.0.0.0',port))", script)
        self.assertNotIn("('0.0.0.0',18082)", script)
        self.assertIn(repr(self.a.peer_vip)+',port', script)
        self.assertIn('source='+repr(self.a.peer_vip), probe['data']['mqtt.py'])
        unbound = next(obj for peer, obj in objects if not peer and obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'unbound')
        self.assertIn('access-control: '+self.a.peer_vip+'/32 allow', unbound['data']['unbound.conf'])
        self.assertIn('pidfile: ""', unbound['data']['unbound.conf'])

    def test_gateway_merge_swan_readiness_independent_of_wg(self):
        run, objects = self.build_topology_offline()
        original = h.native.endpoint_pod(self.a, run.ns, 'owner', self.a.owner_node)
        with patch.object(h.native.Run, 'create', side_effect=lambda peer, obj: obj):
            pod = run.create(False, original)
        spec = pod['spec']
        self.assertFalse(spec.get('hostNetwork', False))
        self.assertFalse(spec.get('hostPID', False))
        self.assertEqual(spec['serviceAccountName'], 'wg-link')
        self.assertTrue(spec['automountServiceAccountToken'])
        self.assertEqual({container['name'] for container in spec['containers']}, {'swan', 'tools', 'wg-link'})
        swan = spec['containers'][0]
        self.assertEqual(swan['readinessProbe']['exec']['command'],
                         ['ping', '-n', '-I', self.a.customer_vip, '-c', '1', '-W', '1', self.a.peer_vip])
        self.assertEqual(swan['readinessProbe']['failureThreshold'], 3)
        self.assertEqual(swan['readinessProbe']['successThreshold'], 2)
        self.assertNotIn('livenessProbe', swan)
        self.assertIn('ip rule add pref 102 to '+self.a.peer_vip+'/32 lookup 100', swan['command'][-1])
        self.assertEqual(pod['metadata']['labels']['app'], 'gateway')
        result = subprocess.run(['/bin/sh', '-n'], input=swan['command'][-1], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_six_endpoints_selected_by_active_pod(self):
        run = h.Run(self.a)
        service = run.services
        service.obj = lambda *args: {'status': {'podIP': '192.0.2.44'}}
        service.client_pod = lambda name: name
        def execute(pod, container, *command):
            iface = command[-2]
            port = {'wg-dns': 51820, 'wg-broker': 51821, 'wg-transit': 51822}[iface]
            return 'unit-public-key\t192.0.2.44:'+str(port)+'\n'
        service.exec = execute
        endpoints = service.endpoints('owner')
        self.assertEqual(set(endpoints), set(h.services.CLIENTS))

    def test_matrix_hard_roundtrip_no_manual_ike_or_pod_resets(self):
        run = h.Run(self.a)
        events = []
        service = run.services
        service.wait = lambda fn, message: fn()
        service.ready = lambda name: True
        service.client_pod = lambda name: name
        service.settled = lambda expected: {'active': expected}
        service.dataplane = lambda expected: events.append(('services', expected)) or {'active': expected}
        run.identities = lambda: {'owner': 'unchanged', 'standby': 'unchanged', 'peer': 'unchanged'}
        run.wait_health = lambda name, seconds: events.append(('health', name))
        run.move = lambda destination: events.append(('move', destination))
        run.sas = lambda *args: 'unit-vici'
        run.observe_stages = lambda expected, children: (children(), {'expected': expected})
        counter = [0]
        def parsed(raw, reqids):
            counter[0] += 1
            return {name: {'counters': (counter[0],)*4} for name in h.CHILDREN}
        with patch.object(run, 'swan', side_effect=AssertionError('manual IKE control')), \
             patch.object(run, 'create', side_effect=AssertionError('pod recreation')), \
             patch.object(h, 'installed_children', side_effect=parsed):
            run.matrix()
        self.assertEqual([event for event in events if event[0] == 'move'],
                         [('move', self.a.standby_server_id), ('move', self.a.owner_server_id)])
        self.assertEqual([event for event in events if event[0] == 'services'],
                         [('services', 'owner'), ('services', 'standby'), ('services', 'owner')])

    def test_stage_observations_order_and_elapsed_are_not_outage_bound(self):
        run = h.Run(self.a)
        run.start = 100
        service = run.services
        snapshots = iter([{'healthy': ['standby'], 'active': None},
                          {'healthy': ['standby'], 'active': 'standby'}])
        service.snapshot = lambda: next(snapshots)
        endpoints = {name: '192.0.2.44:51820' for name in h.services.CLIENTS}
        service.endpoints = lambda expected: endpoints
        def wait(fn, message):
            for _ in range(3):
                result = fn()
                if result:
                    return result
            self.fail('offline wait did not converge: '+message)
        service.wait = wait
        children = {'customer': {'unit': True}, 'peer': {'unit': True}}
        with patch.object(h.time, 'monotonic', side_effect=[101, 102, 103, 104, 105, 106]), \
             patch.object(service, 'exec', return_value='unit-DNS-success') as dns, \
             patch.object(run, 'event'):
            before, stage = run.observe_stages('standby', lambda: children)
        self.assertEqual(before, children)
        self.assertEqual(stage['tXfrmReadyObservation'], 2)
        self.assertEqual(stage['tSwanReadyObservation'], 2)
        self.assertEqual(stage['tPodLeaseWGReady'], 3)
        self.assertEqual(stage['tEndpointsObserved'], 4)
        self.assertEqual(stage['tFirstDNSProbeCompleted'], 6)
        self.assertEqual(stage['extra_observed_seconds'], 4)
        self.assertEqual(stage['dns_attempts'], [{'started': 5, 'completed': 6, 'success': True}])
        self.assertIn('not packet outage or a guaranteed maximum', stage['measurement'])
        self.assertEqual(run.evidence['observed_service_stages'], [stage])
        dns.assert_called_once_with('provider', 'probe', 'python', '/probe/dns.py', self.a.peer_vip,
                                    h.DNS_VIPS[0], 'udp', 'allowed.example', '192.0.2.123', '1')

    def test_stage_dns_records_failed_attempt_before_first_success(self):
        run = h.Run(self.a)
        service = run.services
        service.snapshot = lambda: {'healthy': ['owner'], 'active': 'owner'}
        service.endpoints = lambda expected: {name: 'unit-endpoint' for name in h.services.CLIENTS}
        def wait(fn, message):
            for _ in range(3):
                try:
                    value = fn()
                    if value:
                        return value
                except RuntimeError:
                    pass
            self.fail('offline wait did not converge')
        service.wait = wait
        with patch.object(service, 'exec', side_effect=[RuntimeError('unit initial DNS timeout'), 'unit-success']), \
             patch.object(run, 'event'):
            before, stage = run.observe_stages('owner', lambda: {'installed': True})
        self.assertEqual([attempt['success'] for attempt in stage['dns_attempts']], [False, True])
        self.assertEqual(stage['tFirstDNSProbeCompleted'], stage['dns_attempts'][1]['completed'])
        self.assertGreaterEqual(stage['extra_observed_seconds'], 0)

    def test_move_waits_all_related_actions_after_assignment_ack(self):
        run = h.Run(self.a)
        events = []
        with patch.object(h.native.Run, 'move', side_effect=lambda *args, **kwargs: events.append('assign-ack')), \
             patch.object(run, 'settle_actions', side_effect=lambda **kwargs: events.append(('settle', kwargs))) as settle, \
             patch.object(run, 'verify_fip', side_effect=lambda owner: events.append(('verify', owner))):
            run.move(self.a.standby_server_id)
        self.assertEqual(events, ['assign-ack', ('settle', {'quiet_reads': 3}), ('verify', self.a.standby_server_id)])
        self.assertEqual([row['kind'] for row in run.evidence['events']],
                         ['provider-assignment-acknowledged', 'provider-all-tasks-settled'])
        run = h.Run(self.a)
        with patch.object(h.native.Run, 'move'), patch.object(run, 'settle_actions', side_effect=RuntimeError('unit pending unassign')):
            with self.assertRaisesRegex(RuntimeError, 'related Floating IP tasks did not settle'):
                run.move(self.a.standby_server_id)
        self.assertNotIn('provider-all-tasks-settled', [row['kind'] for row in run.evidence['events']])

    def test_diagnostics_readonly_commands_redacted_and_actual_status_preserved(self):
        run = h.Run(self.a)
        run.services.sensitive.append('unit-mqtt-secret')
        result = subprocess.CompletedProcess([], 7, run.psk+' unit-mqtt-secret', 'unit API Forbidden')
        with patch.object(run, 'exec', return_value=result) as execute, \
             patch.object(run, 'kubectl', return_value=result) as kube, \
             patch.object(run, 'diagnostic_cloud_get', return_value={'http_status': 429, 'error': 'rate limited'}) as cloud:
            report = run.diagnostics()
        serialized = json.dumps(report)
        self.assertNotIn(run.psk, serialized)
        self.assertNotIn('unit-mqtt-secret', serialized)
        self.assertIn('[REDACTED]', serialized)
        self.assertEqual(report['snapshots']['owner_network']['returncode'], 7)
        self.assertEqual(report['snapshots']['recent_actions']['http_status'], 429)
        self.assertEqual(report['budget_seconds'], 15)
        self.assertEqual(execute.call_count, 3)
        for call in execute.call_args_list:
            script = call.args[1][-1]
            self.assertIn('xfrm state list nokeys', script)
            self.assertIn('swanctl --list-sas --raw', script)
            for forbidden in ('--list-creds', '--list-secrets', 'env', 'flush', 'kill ', 'delete ', 'add ', 'replace '):
                self.assertNotIn(forbidden, script)
        for call in kube.call_args_list:
            args = call.args[1]
            self.assertNotIn('secret', args)
            if 'get' in args and 'pod' in args:
                self.assertIn('jsonpath={.status}', args)
            if 'logs' in args:
                self.assertIn('--tail=80', args)
        self.assertTrue(all(call.args[0].startswith('/floating_ips/'+str(self.a.floating_ip_id)) for call in cloud.call_args_list))

    def test_diagnostics_shared_budget_stops_io_at_fifteen_seconds(self):
        run = h.Run(self.a)
        original_end = run.end
        clock = [0.0]
        calls = []
        def io_result(*args, **kwargs):
            calls.append(clock[0])
            clock[0] += min(2, max(0, run.end-clock[0]))
            return subprocess.CompletedProcess([], 0, 'unit-readonly', '')
        def cloud_result(*args, **kwargs):
            io_result()
            return {'http_status': 200}
        with patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(run, 'exec', side_effect=io_result), patch.object(run, 'kubectl', side_effect=io_result), \
             patch.object(run, 'diagnostic_cloud_get', side_effect=cloud_result):
            report = run.diagnostics()
        self.assertEqual(report['elapsed_seconds'], 15)
        self.assertEqual(run.end, original_end)
        self.assertTrue(all(value < 15 for value in calls))
        self.assertTrue(any('skipped' in value for value in report['snapshots'].values()))

    def test_diagnostic_cloud_only_approved_gets_project_fields_and_http_errors(self):
        self.a.execute = True
        run = h.Run(self.a)
        action = {'id': 55, 'command': 'unassign_floating_ip', 'status': 'running', 'started': 'unit-start',
                  'finished': None, 'progress': 1, 'error': None, 'resources': [{'omit': 'unit-private-metadata'}]}
        response = io.StringIO(json.dumps({'actions': [action]}))
        response.status = 200
        path = '/floating_ips/'+str(self.a.floating_ip_id)+'/actions?per_page=10&sort=id:desc'
        with patch.dict(h.os.environ, {'HCLOUD_TOKEN': 'offline-only'}), \
             patch.object(h.native.urllib.request, 'urlopen', return_value=response) as get:
            result = run.diagnostic_cloud_get(path)
        self.assertEqual(get.call_args.args[0].get_method(), 'GET')
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(set(result['actions'][0]), {'id', 'command', 'status', 'started', 'finished', 'progress', 'error'})
        self.assertNotIn('resources', result['actions'][0])
        with patch.object(h.native.urllib.request, 'urlopen', side_effect=AssertionError('network')):
            with self.assertRaises(RuntimeError):
                run.diagnostic_cloud_get('/floating_ips/999/actions?per_page=10&sort=id:desc')
        error = h.native.urllib.error.HTTPError('https://example.invalid/', 429, 'Too Many Requests', None, None)
        with patch.dict(h.os.environ, {'HCLOUD_TOKEN': 'offline-only'}), \
             patch.object(h.native.urllib.request, 'urlopen', side_effect=error):
            self.assertEqual(run.diagnostic_cloud_get(path)['http_status'], 429)

    def test_failure_diagnostics_run_before_cleanup_even_when_diagnostics_fail(self):
        for diagnostic_fails in (False, True):
            order = []
            fake = unittest.mock.Mock()
            fake.evidence = {'success': False}
            fake.psk = 'unit-psk'
            fake.services.result = {}
            fake.services.redact = lambda text: text
            fake.setup.side_effect = RuntimeError('unit setup failure')
            def diagnostics():
                order.append('diagnostics')
                if diagnostic_fails:
                    raise RuntimeError('unit diagnostic failure')
            fake.diagnostics.side_effect = diagnostics
            fake.cleanup.side_effect = lambda: order.append('cleanup') or []
            with tempfile.TemporaryDirectory() as directory, patch.object(h, 'Run', return_value=fake), \
                 patch.object(h.signal, 'signal'):
                self.a.evidence_dir = directory
                self.assertEqual(h.execute(self.a), 1)
            self.assertEqual(order, ['diagnostics', 'cleanup'])
            self.assertEqual(fake.evidence['error'], 'unit setup failure')
            self.assertEqual('diagnostic_error' in fake.evidence, diagnostic_fails)

    def test_cleanup_numeric_membership_all_five_and_foreign_nearby_reqids(self):
        states, policies = [], []
        expected = []
        for index, selector in enumerate(h.selectors(self.a)):
            reqid, spi, policy_index = 12345+index, hex(256+index), 41+index
            states += ['src 203.0.113.20 dst 192.0.2.10', ' proto esp spi '+spi+' reqid '+str(reqid)+' mode tunnel']
            policies += ['src '+self.a.peer_vip+'/32 dst '+selector, ' dir out priority 1 index '+str(policy_index),
                         ' tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid '+str(reqid)+' mode tunnel']
            expected.append('DELETE xfrm state delete src 203.0.113.20 dst 192.0.2.10 proto esp spi '+spi)
        expected += ['DELETE xfrm policy delete index '+str(41+i)+' dir out' for i in range(5)]
        for index, reqid in enumerate((12344, 12350, 123450)):
            states += ['src 203.0.113.20 dst 192.0.2.10', ' proto esp spi '+hex(512+index)+' reqid '+str(reqid)+' mode tunnel']
            policies += ['src '+self.a.peer_vip+'/32 dst '+self.a.customer_vip+'/32',
                         ' dir out priority 1 index '+str(91+index),
                         ' tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid '+str(reqid)+' mode tunnel']
        fake = '''REQID=12345
REQIDS='12345 12346 12347 12348 12349'
PUBLIC_LOCAL=203.0.113.20
PUBLIC_REMOTE=192.0.2.10
VIP_LOCAL=198.19.70.2
VIP_REMOTE=198.19.70.1
ip() {
 case "$*" in
'''
        fake += "'xfrm state list nokeys') printf '%s\\n' "+' '.join(map(shlex.quote, states))+";;\n"
        fake += "'xfrm policy list') printf '%s\\n' "+' '.join(map(shlex.quote, policies))+";;\n"
        fake += ''''xfrm state delete '*|'xfrm policy delete '*) printf 'DELETE %s\\n' "$*";;
'-o addr show dev lo') :;;
*) return 77;;
esac
}
'''
        selection = h.expanded_cleanup(self.a).split('\nstates=$(', 1)[0]
        result = subprocess.run(['/bin/sh', '-ec', fake+'\n'+selection], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_five_installed_children_requires_names_reqids_and_state(self):
        reqids = (12345, 12346, 12347, 12348, 12349)
        raw = 'list-sa event { acceptance { child-sas {'+' '.join(
            name+'-1 { name='+name+' state=INSTALLED reqid='+str(reqid)+
            ' spi-in=abc bytes-in=20 bytes-out=30 packets-in=2 packets-out=3 }'
            for name, reqid in zip(h.CHILDREN, reqids))+'}}}'
        value = h.installed_children(raw, reqids)
        self.assertEqual(set(value), set(h.CHILDREN))
        self.assertEqual(value['protected-support']['counters'], (20, 30, 2, 3))
        for bad in (raw.replace('reqid=12349', 'reqid=999'),
                    raw.replace('name=protected-support', 'name=foreign'),
                    raw.replace('state=INSTALLED', 'state=CONNECTING', 1)):
            with self.assertRaises(RuntimeError):
                h.installed_children(bad, reqids)

    def test_sessions_expect_actual_peer_vip_not_standalone_apn(self):
        run = h.Run(self.a)
        flows = [{'client_id': 'unit-'+str(i)} for i in range(3)]
        def sessions(index):
            return [{'client_id': 'unit-'+str(index-1), 'peer_host': self.a.peer_vip, 'is_online': True,
                     'session_pid': 'unit-session', 'session_started_at': 'unit-time'}]
        run.services.session_rows = sessions
        proof = run.services.sessions(flows)
        self.assertEqual({row['peer_host'] for row in proof.values()}, {self.a.peer_vip})
        self.assertEqual({row['destination_port'] for row in proof.values()}, {12101, 12201, 1883})
        original = self.a.peer_vip
        self.a.peer_vip = '198.19.70.99'
        # Service args are copied, so changing unrelated controller args does not
        # silently rewrite the explicit source expected by this service proof.
        self.assertEqual(run.services.a.peer_vip, original)

    def test_secret_profile_is_auto_and_exact(self):
        run = h.Run(self.a)
        for peer in (False, True):
            profile = h.native.swan_config(self.a, peer, 'unit-psk', 123, auto=True)
            obj = {'kind': 'Secret', 'metadata': {'name': 'swan-peer' if peer else 'swan-customer'},
                   'data': {'auto.conf': base64.b64encode(profile.encode()).decode()}}
            with patch.object(h.native.Run, 'create', side_effect=lambda peer, obj: obj):
                actual = run.create(peer, obj)
            loaded = base64.b64decode(actual['data']['swanctl.conf']).decode()
            self.assertIn('dpd_action = restart', loaded)
            self.assertEqual(loaded, base64.b64decode(actual['data']['auto.conf']).decode())
            self.assertEqual(loaded.count('local_ts ='), 5)
            self.assertEqual(loaded.count('remote_ts ='), 5)


if __name__ == '__main__':
    unittest.main()
