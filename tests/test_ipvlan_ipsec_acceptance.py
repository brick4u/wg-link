#!/usr/bin/env python3
"""Offline tests only; no cluster, cloud, daemon or host networking execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ipvlan_ipsec_acceptance as h


def arguments():
    values = {
        'kubeconfig': 'customer-config', 'peer-kubeconfig': 'peer-config',
        'owner-node': 'customer-a', 'standby-node': 'customer-b', 'peer-node': 'external-peer',
        'floating-ip': '192.0.2.10', 'floating-ip-name': 'dedicated-test',
        'peer-public-ip': '203.0.113.20', 'gateway': '192.0.2.1',
        'parent-interface': 'enp1s0', 'customer-vip': '198.19.70.1', 'peer-vip': '198.19.70.2',
        'strongswan-image': 'example.invalid/swan@sha256:'+'a'*64,
        'tools-image': 'example.invalid/tools@sha256:'+'b'*64,
        'floating-ip-id': '100', 'owner-server-id': '200', 'standby-server-id': '300',
        'evidence-dir': 'private-evidence', 'approval-file': 'private-approval.json',
    }
    return [v for key, value in values.items() for v in ('--'+key, value)]


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.a = h.parser().parse_args(arguments())

    def test_review_has_no_io(self):
        with patch.object(h, 'execute', side_effect=AssertionError('runtime called')), \
             patch.object(h.subprocess, 'run', side_effect=AssertionError('process called')), \
             patch.object(h.urllib.request, 'urlopen', side_effect=AssertionError('network called')):
            self.assertEqual(h.main(arguments()), 0)

    def test_two_explicit_execute_guards(self):
        self.a.execute = True
        with patch.dict(os.environ, {'HCLOUD_TOKEN': 'offline-only'}):
            for cloud, host in ((False, False), (True, False), (False, True)):
                self.a.allow_test_fip_moves, self.a.allow_native_host_peer = cloud, host
                with self.assertRaises(RuntimeError):
                    h.validate(self.a)
            self.a.allow_test_fip_moves = self.a.allow_native_host_peer = True
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'approval.json'
                keys = ('floating_ip_id', 'floating_ip', 'floating_ip_name', 'owner_server_id',
                        'standby_server_id', 'owner_node', 'standby_node', 'peer_node', 'peer_public_ip')
                path.write_text(json.dumps({key: getattr(self.a, key) for key in keys}))
                path.chmod(0o600)
                self.a.approval_file = str(path)
                h.validate(self.a)
                path.chmod(0o644)
                with self.assertRaises(RuntimeError):
                    h.validate(self.a)
                path.chmod(0o600)
                path.write_text('{}')
                with self.assertRaises(RuntimeError):
                    h.validate(self.a)

    def test_vips_and_images_restricted(self):
        for key, value in [('customer_vip', '10.0.0.1'), ('peer_vip', self.a.customer_vip),
                           ('strongswan_image', 'mutable:latest'), ('timeout', 301)]:
            original = getattr(self.a, key)
            setattr(self.a, key, value)
            with self.assertRaises(RuntimeError):
                h.validate(self.a)
            setattr(self.a, key, original)

    def test_native_nad_is_standard(self):
        config = json.loads(h.nad(self.a, 'unit')['spec']['config'])
        self.assertEqual(config['cniVersion'], '1.1.0')
        ipvlan, sbr = config['plugins']
        self.assertEqual(ipvlan['type'], 'ipvlan')
        self.assertEqual(ipvlan['mode'], 'l2')
        self.assertEqual(ipvlan['ipam']['addresses'], [{'address': self.a.floating_ip+'/32'}])
        self.assertNotIn('gateway', ipvlan['ipam']['addresses'][0])
        self.assertEqual(ipvlan['ipam']['routes'][0]['scope'], 253)
        self.assertEqual(sbr, {'type': 'sbr', 'table': 100})

    def test_table_normalization(self):
        for table in (100, '100'):
            h.check_routes([{'dst': self.a.gateway, 'dev': 'net1', 'scope': 'link'},
                            {'dst': 'default', 'dev': 'net1', 'gateway': self.a.gateway}],
                           [{'src': self.a.floating_ip+'/32', 'table': table}], self.a.floating_ip,
                           self.a.gateway, [{'dst': 'default', 'dev': 'eth0'}])

    def test_exact_selectors_same_identity(self):
        psk = 'unit-test-secret'
        customer = h.swan_config(self.a, False, psk, 12345)
        peer = h.swan_config(self.a, True, psk, 12345)
        for text in (customer, peer):
            self.assertNotIn('0.0.0.0/0', text)
            self.assertIn('customer.acceptance.invalid', text)
            self.assertIn('peer.acceptance.invalid', text)
            self.assertIn('unique = replace', text)
            self.assertIn('dpd_timeout = 8s', text)
            self.assertIn('start_action = none', text)
            self.assertIn('dpd_action = clear', text)
            self.assertIn('close_action = none', text)
            self.assertIn('reqid = 12345', text)
            self.assertIn(psk, text)
        self.assertIn('local_ts = '+self.a.customer_vip+'/32', customer)
        self.assertIn('remote_ts = '+self.a.customer_vip+'/32', peer)

    def test_helper_armed_and_stops_before_cleanup(self):
        pod = h.recovery_pod(self.a, 'unit', 12345, 'unit-uuid')
        spec = pod['spec']
        self.assertTrue(spec['hostNetwork'])
        self.assertTrue(spec['hostPID'])
        self.assertFalse(spec['automountServiceAccountToken'])
        script = spec['containers'][0]['command'][-1]
        self.assertLess(script.index('test -f /tmp/armed'), script.index('stop_owned\n'))
        self.assertLess(script.index('stop_owned\n'), script.index('cleanup\n'))
        for guard in ('ACCEPTANCE_RUN=', 'ACCEPTANCE_ROLE=peer', 'ACCEPTANCE_POD_UID=',
                      '/proc/$pid/exe', '/proc/$pid/cgroup', 'IKE sockets remain'):
            self.assertIn(guard, script)
        self.assertNotIn('flush', script)
        self.assertNotIn('ip route', script)
        self.assertNotIn('sysctl', script)
        self.assertIn('reqid', script)
        self.assertGreater(spec['activeDeadlineSeconds'], self.a.timeout+30)

    def test_customer_only_namespace_netadmin(self):
        pod = h.endpoint_pod(self.a, 'unit', 'owner', self.a.owner_node)
        self.assertNotIn('hostNetwork', pod['spec'])
        self.assertNotIn('hostPID', pod['spec'])
        self.assertEqual(pod['spec']['volumes'][0]['secret']['secretName'], 'swan-customer')
        probe = pod['spec']['containers'][0]['readinessProbe']['exec']['command']
        self.assertEqual(probe, ['/bin/sh', '-ec', 'test -f /tmp/ready'])
        self.assertIn('net1', pod['metadata']['annotations']['k8s.v1.cni.cncf.io/networks'])

    def test_peer_watchdog_identity_downward_api(self):
        pod = h.endpoint_pod(self.a, 'unit', 'peer', self.a.peer_node, True, 'unique-unit-run')
        env = {x['name']: x for x in pod['spec']['containers'][0]['env']}
        self.assertEqual(env['ACCEPTANCE_RUN']['value'], 'unique-unit-run')
        self.assertEqual(env['ACCEPTANCE_POD_UID']['valueFrom']['fieldRef']['fieldPath'], 'metadata.uid')
        self.assertNotIn('hostPID', pod['spec'])

    def test_fip_guard_prevents_post(self):
        run = h.Run(self.a)
        calls = []
        def cloud(method, path, body=None):
            calls.append(method)
            return {'floating_ip': {'id': self.a.floating_ip_id, 'ip': self.a.floating_ip,
                                    'name': self.a.floating_ip_name, 'server': 999}}
        run.cloud = cloud
        run.settle_actions = lambda **kwargs: None
        with self.assertRaises(RuntimeError):
            run.move(self.a.standby_server_id)
        self.assertEqual(calls, ['GET'])

    def test_lost_move_response_restoration(self):
        run = h.Run(self.a)
        run.initial_verified = True
        calls = []
        def cloud(method, path, body=None):
            calls.append((method, path, body))
            if '?status=running' in path:
                return {'actions': []}
            if method == 'POST':
                return {'action': {'id': 55}}
            if path == '/actions/55':
                return {'action': {'status': 'success'}}
            owner = self.a.owner_server_id if any(c[0] == 'POST' for c in calls) else self.a.standby_server_id
            return {'floating_ip': {'id': self.a.floating_ip_id, 'ip': self.a.floating_ip,
                                    'name': self.a.floating_ip_name, 'server': owner}}
        run.cloud = cloud
        with patch.object(h.time, 'sleep'):
            self.assertEqual(run.cleanup(), [])
        self.assertTrue(any(c[0] == 'POST' and c[2] == {'server': self.a.owner_server_id} for c in calls))

    def test_ephemeral_namespaces_have_scoped_psa_labels(self):
        run = h.Run(self.a)
        namespaces = []
        def kubectl(peer, args, **kwargs):
            server = self.a.owner_server_id if args[2] == self.a.owner_node else self.a.standby_server_id
            return type('Result', (), {'stdout': json.dumps({'spec': {'providerID': 'hcloud://'+str(server)}})})()
        def create(peer, obj):
            if obj['kind'] == 'Namespace':
                namespaces.append((peer, obj))
                return {'metadata': {'uid': 'offline-uid'}}
            if obj['kind'] == 'NetworkAttachmentDefinition':
                raise RuntimeError('offline stop before resources')
            return {}
        run.kubectl = kubectl
        run.create = create
        run.settle_actions = lambda **kwargs: None
        run.verify_fip = lambda owner: None
        with self.assertRaisesRegex(RuntimeError, 'offline stop'):
            run.setup()
        self.assertEqual([peer for peer, obj in namespaces], [False, True])
        for peer, obj in namespaces:
            labels = obj['metadata']['labels']
            self.assertEqual(obj['metadata']['name'], run.ns)
            self.assertEqual(labels['acceptance-run'], run.run_uuid)
            for policy in ('enforce', 'audit', 'warn'):
                self.assertEqual(labels['pod-security.kubernetes.io/'+policy], 'privileged')

    def test_node_provider_id_mismatch_aborts_before_cloud_or_create(self):
        run = h.Run(self.a)
        with patch.object(run, 'kubectl', return_value=type('Result', (), {'stdout': json.dumps({'spec': {'providerID': 'hcloud://999'}})})()) as get, \
             patch.object(run, 'cloud', side_effect=AssertionError('cloud called')), \
             patch.object(run, 'create', side_effect=AssertionError('mutation called')):
            with self.assertRaisesRegex(RuntimeError, 'providerID mismatch'):
                run.setup()
        self.assertEqual(get.call_args.args[1][:2], ['get', 'node'])

    def test_ambiguous_post_marker_precedes_request(self):
        run = h.Run(self.a)
        run.settle_actions = lambda **kwargs: None
        run.verify_fip = lambda owner: None
        def lost_response(*args, **kwargs):
            self.assertTrue(run.assignment_attempted)
            raise TimeoutError('offline lost response')
        run.cloud = lost_response
        with self.assertRaises(TimeoutError):
            run.move(self.a.standby_server_id)
        self.assertTrue(run.assignment_attempted)

    def test_old_owner_get_cannot_skip_ambiguous_restore(self):
        run = h.Run(self.a)
        run.initial_verified = True
        run.assignment_attempted = True
        calls = []
        def cloud(method, path, body=None):
            calls.append((method, path, body))
            if '?status=running' in path:
                return {'actions': []}
            if method == 'POST':
                return {'action': {'id': 55}}
            if path == '/actions/55':
                return {'action': {'status': 'success'}}
            return {'floating_ip': {'id': self.a.floating_ip_id, 'ip': self.a.floating_ip,
                                    'name': self.a.floating_ip_name, 'server': self.a.owner_server_id}}
        run.cloud = cloud
        with patch.object(h.time, 'sleep'):
            self.assertEqual(run.cleanup(), [])
        self.assertTrue(any(c[0] == 'POST' and c[2] == {'server': self.a.owner_server_id} for c in calls))

    def test_cleanup_refuses_changed_fip_identity(self):
        run = h.Run(self.a)
        run.initial_verified = True
        run.settle_actions = lambda **kwargs: None
        run.cloud = lambda *args: {'floating_ip': {'id': self.a.floating_ip_id, 'ip': '192.0.2.99',
                                                   'name': self.a.floating_ip_name, 'server': self.a.standby_server_id}}
        self.assertIn('RESTORE FAILED', run.cleanup()[0])

    def test_qualification_resolves_applet_symlink_in_image(self):
        # Mock readlink and omit signals: only the generated resolution is run.
        with patch.object(h, 'STOP_OWNED_CHARON', ''):
            script = h.qualification_script('test "$EXPECTED_EXE" = /resolved/unit/tail\n')
        fake_readlink = '''readlink() {
  test "$1" = -f && test "$2" = /usr/bin/tail || return 77
  printf '%s\\n' /resolved/unit/tail
}
'''
        result = subprocess.run(['/bin/sh', '-ec', fake_readlink+script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('EXPECTED_EXE=/usr/bin/tail', script)
        self.assertNotIn('coreutils/tail', script)

    def test_scripts_parse_offline(self):
        helper = h.recovery_pod(self.a, 'unit', 12345, 'unit-uuid')
        scripts = [helper['spec']['containers'][0]['command'][-1], h.CLEANUP, h.STOP_OWNED_CHARON,
                   h.endpoint_pod(self.a, 'unit', 'owner', self.a.owner_node)['spec']['containers'][0]['command'][-1]]
        for script in scripts:
            result = subprocess.run(['/bin/sh', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleanup_filters_exact_owned_state_and_policy(self):
        # Only the shell function below is called 'ip'; no networking tool runs.
        fake_ip = r'''
REQID=12345
PUBLIC_LOCAL=203.0.113.20
PUBLIC_REMOTE=192.0.2.10
VIP_LOCAL=198.19.70.2
VIP_REMOTE=198.19.70.1
ip() {
  case "$*" in
    'xfrm state list nokeys')
      printf '%s\n' 'src 203.0.113.20 dst 192.0.2.10' '    proto esp spi 0x123 reqid 12345 mode tunnel' \
        'src 203.0.113.20 dst 192.0.2.10' '    proto esp spi 0x999 reqid 99999 mode tunnel' \
        'src 203.0.113.99 dst 192.0.2.10' '    proto esp spi 0x888 reqid 12345 mode tunnel';;
    'xfrm policy list')
      printf '%s\n' 'src 198.19.70.2/32 dst 198.19.70.1/32' '    dir out priority 1 index 41' \
        '    tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 12345 mode tunnel' \
        'src 198.19.70.2/32 dst 198.19.70.1/32' '    dir out priority 1 index 42' \
        '    tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 99999 mode tunnel' \
        'src 198.19.70.99/32 dst 198.19.70.1/32' '    dir out priority 1 index 43' \
        '    tmpl src 203.0.113.20 dst 192.0.2.10 proto esp reqid 12345 mode tunnel';;
    'xfrm state delete '*|'xfrm policy delete '*) printf 'DELETE %s\n' "$*";;
    '-o addr show dev lo') :;;
    *) echo "Unexpected mocked ip command: $*" >&2; return 77;;
  esac
}
'''
        selection_only = h.CLEANUP.split('\nstates=$(', 1)[0]
        result = subprocess.run(['/bin/sh', '-ec', fake_ip+'\n'+selection_only], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            'DELETE xfrm state delete src 203.0.113.20 dst 192.0.2.10 proto esp spi 0x123',
            'DELETE xfrm policy delete index 41 dir out'])

    def test_auto_actions_customer_and_passive_peer(self):
        for peer in (False, True):
            config = h.swan_config(self.a, peer, 'unit-psk', 123, auto=True)
            self.assertIn('start_action = '+('none' if peer else 'start'), config)
            self.assertIn('dpd_action = restart', config)
            self.assertIn('close_action = start', config)

    def test_cold_initiates_once_per_participant_not_per_poll(self):
        run = h.Run(self.a)
        participants = [('owner', False), ('standby', False)]
        rows = [{'owner': False, 'active_count': 0}, {'owner': True, 'active_count': 1},
                {'owner': True, 'active_count': 1}]
        with patch.object(run, 'initiate') as initiate, patch.object(run, 'sample', side_effect=rows) as sample, \
             patch.object(h.time, 'sleep'):
            run.wait_health('owner', 10, participants)
        self.assertEqual(initiate.call_args_list, [unittest.mock.call(*item) for item in participants])
        self.assertEqual(sample.call_count, 3)

    def test_sequential_overlap_sample_retained(self):
        run = h.Run(self.a)
        run.last_success = {'owner': 1.0, 'standby': 2.0}
        with patch.object(run, 'health', return_value=True), patch.object(run, 'sas', return_value='state=INSTALLED'):
            row = run.sample()
        self.assertEqual(row['active_count'], 2)
        self.assertTrue(row['sequential_overlap_observation'])
        self.assertEqual(run.evidence['samples'], [row])
        self.assertEqual(row['owner_success_t'], 1.0)
        self.assertEqual(row['standby_success_t'], 2.0)

    def test_auto_epoch_cold_then_peer_then_customers_then_steady(self):
        run = h.Run(self.a)
        events = []
        run.cold = lambda: events.append(('cold',))
        run.wait_health = lambda *args: events.append(('health',)+args)
        run.event = lambda *args, **kwargs: None
        run.swan = lambda *args, **kwargs: events.append(('load', args[0], kwargs.get('peer', False)))
        run.hard_move = lambda: events.append(('hard',))
        run.move = lambda destination: None
        run.matrix()
        boundary = events.index(('load', 'peer', True))
        self.assertEqual(events[boundary-1:boundary+5], [
            ('cold',), ('load', 'peer', True), ('load', 'owner', False), ('load', 'standby', False),
            ('health', 'owner', self.a.cold_timeout), ('hard',)])

    def test_baseline_precedes_extended(self):
        run = h.Run(self.a)
        events = []
        run.cold = lambda: events.append('cold')
        run.wait_health = lambda *args: events.append('health')
        run.event = lambda *args, **kwargs: None
        run.hard_move = lambda: events.append('hard-move')
        run.move = lambda destination: events.append('restore')
        run.swan = lambda *args, **kwargs: events.append('load-auto')
        run.lifecycle = lambda *args: self.fail('Extended lifecycle called in baseline')
        run.matrix()
        self.assertEqual(events[-3:], ['hard-move', 'restore', 'health'])

    def test_encapsulation_cli_configs_and_evidence(self):
        self.assertEqual(self.a.encapsulation, 'native')
        udp = h.parser().parse_args(arguments()+['--encapsulation', 'udp'])
        for peer in (False, True):
            for auto in (False, True):
                self.assertIn('encap = yes', h.swan_config(udp, peer, 'unit', 123, auto=auto))
                self.assertIn('encap = no', h.swan_config(self.a, peer, 'unit', 123, auto=auto))
        self.assertEqual(h.Run(udp).evidence['encapsulation'], 'udp')

    def test_forced_udp_requires_vici_ports_and_kernel_encapsulation(self):
        raw = ('version=1 state=ESTABLISHED state=INSTALLED encr-alg=AES_CBC encr-keysize=256 '
               'integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384 encap=yes local-port=4500 remote-port=4500')
        h.negotiated(raw, 'proto esp encap type espinudp', 'udp')
        for marker in ('encap=yes', 'local-port=4500', 'remote-port=4500'):
            with self.assertRaises(RuntimeError):
                h.negotiated(raw.replace(marker, ''), 'proto esp encap type espinudp', 'udp')
        with self.assertRaises(RuntimeError):
            h.negotiated(raw, 'proto esp', 'udp')

    def test_cold_empty_rejects_connecting_events(self):
        self.assertTrue(h.sas_empty('list-sas reply {}'))
        self.assertFalse(h.sas_empty('list-sa event { acceptance { state=CONNECTING }}'))
        self.assertFalse(h.sas_empty('list-sa event {}'))
        run = h.Run(self.a)
        snapshots = ['list-sa event { state=CONNECTING }']*3+['list-sas reply {}']*3
        with patch.object(run, 'swan'), patch.object(run, 'sas', side_effect=snapshots) as sas, \
             patch.object(h.time, 'sleep'):
            run.cold()
        self.assertEqual(sas.call_count, 6)

    def test_mtu_directions_required_and_observational_sizes(self):
        run = h.Run(self.a)
        def probe(endpoint, command, peer, **kwargs):
            payload = int(command[command.index('-s')+1])
            self.assertEqual(kwargs['timeout'], 5)
            self.assertFalse(kwargs['check'])
            return subprocess.CompletedProcess(command, 1 if payload in (1400, 1410) else 0,
                                               stdout='', stderr='message too long' if payload in (1400, 1410) else '')
        with patch.object(run, 'exec', side_effect=probe) as execute, patch.object(run, 'wait_health') as health:
            run.mtu('owner')
        self.assertEqual(execute.call_count, 8)
        health.assert_called_once_with('owner', 15)
        probes = [e for e in run.evidence['events'] if e['kind'] == 'protected-mtu-probe']
        self.assertEqual({e['endpoint'] for e in probes}, {'owner', 'peer'})
        self.assertEqual([e['payload'] for e in probes if e['required']], [1200, 16000, 1200, 16000])
        self.assertEqual([e['pmtud'] for e in probes], ['do', 'do', 'do', 'dont']*2)
        self.assertTrue(all(e['encapsulation'] == 'native' for e in probes))

    def test_mtu_required_failure_fails_and_records_result(self):
        run = h.Run(self.a)
        with patch.object(run, 'exec', return_value=subprocess.CompletedProcess([], 1, '', 'message too long')):
            with self.assertRaisesRegex(RuntimeError, 'Required protected MTU'):
                run.mtu('owner')
        event = run.evidence['events'][0]
        self.assertEqual(event['payload'], 1200)
        self.assertEqual(event['returncode'], 1)
        self.assertFalse(event['unsupported'])

    def test_mtu_fragmentation_explicit_unsupported_is_recorded(self):
        run = h.Run(self.a)
        def probe(endpoint, command, peer, **kwargs):
            unsupported = '16000' in command
            return subprocess.CompletedProcess(command, 2 if unsupported else 0, '',
                                               'ping: invalid argument: dont' if unsupported else '')
        with patch.object(run, 'exec', side_effect=probe), patch.object(run, 'wait_health'):
            run.mtu('owner')
        skipped = [e for e in run.evidence['events'] if e.get('unsupported')]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all(e['payload'] == 16000 for e in skipped))

    def test_native_assertion_rejects_natt(self):
        raw = ('version=1 state=ESTABLISHED state=INSTALLED encr-alg=AES_CBC encr-keysize=256 '
               'integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384')
        h.negotiated(raw, 'proto esp')
        with self.assertRaises(RuntimeError):
            h.negotiated(raw+' encap=yes', 'proto esp encap type espinudp')


if __name__ == '__main__':
    unittest.main()
