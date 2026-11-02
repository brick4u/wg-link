#!/usr/bin/env python3
"""Opt-in local Docker forwarding test, NOT cross-node acceptance. Stdlib only.

Uses only cached images; --execute is required before any Docker invocation.
Evidence is retained in a private /tmp directory; all owned resources and keys
are removed even on failure. No host networking, fixed Docker IPs or builds.
"""
import argparse
import ast
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

# Reuse the acceptance probe verbatim without importing its controller.
def probe_source():
    tree = ast.parse(Path(__file__).with_name('kubernetes_acceptance.py').read_text())
    return next(ast.literal_eval(n.value) for n in tree.body
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PROBE' for t in n.targets))


class Harness:
    def __init__(self, args):
        self.args = args
        self.token = uuid.uuid4().hex
        self.label = 'wg-link.forwarding-test=' + self.token
        self.network = 'wg-forward-' + self.token[:12]
        self.names = {}
        self.keys = []
        self.secret = Path(tempfile.mkdtemp(prefix='wg-forward-secrets-')).resolve()
        self.out = Path(tempfile.mkdtemp(prefix='wg-forward-results-')).resolve()
        os.chmod(self.secret, 0o700)
        os.chmod(self.out, 0o700)
        self.result = {'scope': 'local shared internal Docker bridge; not cross-node acceptance',
                       'token': self.token, 'checks': [], 'images': {}, 'passed': False}

    def redact(self, text):
        for key in self.keys:
            text = text.replace(key, '[REDACTED]')
        return text

    def docker(self, *args, data=None, allow=False):
        p = subprocess.run(['docker', *args], input=data, text=True, capture_output=True, timeout=45)
        if p.returncode and not allow:
            raise RuntimeError(self.redact('docker ' + ' '.join(args[:3]) + ': ' + p.stderr))
        return p.stdout + (p.stderr if args and args[0] == 'logs' else '')

    def execute(self, role, *args):
        return self.docker('exec', self.names[role], *args)

    def wait(self, fn, description, seconds=45):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                value = fn()
                if value:
                    return value
            except (RuntimeError, AssertionError, ValueError, KeyError):
                pass
            time.sleep(.3)
        raise RuntimeError('timeout: ' + description)

    def put(self, path, text):
        temporary = path.with_suffix('.new')
        temporary.write_text(text)
        os.chmod(temporary, 0o644)
        temporary.replace(path)

    def snapshot(self):
        value = json.loads(self.execute('router', 'nft', '-j', 'list', 'ruleset'))
        return value

    @staticmethod
    def counts(value):
        totals = {'accept': 0, 'drop': 0}
        rules = {'accept': 0, 'drop': 0}
        for entry in value['nftables']:
            rule = entry.get('rule', {})
            expr = rule.get('expr', [])
            for verdict in totals:
                if any(verdict in e for e in expr):
                    rules[verdict] += 1
                    totals[verdict] += sum(e.get('counter', {}).get('packets', 0) for e in expr)
        return {'packets': totals, 'rules': rules}

    def events(self):
        text = self.execute('pa', 'python', '-c', "print(open('/tmp/events.jsonl').read())")
        return [json.loads(line) for line in text.splitlines() if line]

    def mark(self, name):
        self.execute('pa', 'python', '/probe/probe.py', 'mark', name)
        return next(e['mono_ns'] for e in reversed(self.events()) if e.get('name') == name)

    def check(self, role, dst, port, proto, expected=True, source=None):
        value = json.loads(self.execute(role, 'python', '/probe/probe.py', 'check', dst, str(port), proto))
        assert value['ok'] == expected, (role, dst, port, proto, value)
        if expected:
            assert value['source'] == source, ('source rewritten', value, source)
        self.result['checks'].append(dict(role=role, destination=dst, port=port,
                                          protocol=proto, expected=expected, observed=value))

    def ping(self, role, dst, expected):
        value = json.loads(self.execute(role, 'python', '/probe/probe.py', 'ping', dst))
        assert value['ok'] == expected, (role, dst, value)
        self.result['checks'].append(dict(role=role, destination=dst, protocol='icmp', expected=expected, observed=value))

    def matrix(self, allowed):
        for role, dst, source in [('pa', '198.18.30.1', '198.18.10.2'), ('pc', '198.18.10.2', '198.18.30.1')]:
            self.ping(role, dst, allowed)
            for proto in ('tcp', 'udp'):
                self.check(role, dst, 18080, proto, allowed, source)

    def identity(self):
        return {role: {k: value[k] for k in ('Id', 'State')} for role in ('a', 'router', 'c')
                for value in [json.loads(self.docker('inspect', self.names[role]))[0]]}

    def run(self):
        for image in (self.args.image, self.args.probe_image):
            self.result['images'][image] = json.loads(self.docker('image', 'inspect', image))[0]['Id']
        self.docker('network', 'create', '--internal', '--label', self.label, self.network)
        keys = {}
        for name in ('a', 'ra', 'rt', 'c'):
            private = self.docker('run', '--rm', '--pull=never', '--label', self.label, '--network=none', '--cap-drop=ALL', '--entrypoint=wg', self.args.image, 'genkey').strip()
            self.keys.append(private)
            public = self.docker('run', '--rm', '-i', '--pull=never', '--label', self.label, '--network=none', '--cap-drop=ALL', '--entrypoint=wg', self.args.image, 'pubkey', data=private + '\n').strip()
            keys[name] = (private, public)
        addresses = {}
        for role in ('a', 'router', 'c'):
            directory = self.secret / role
            directory.mkdir(mode=0o755)
            self.names[role] = self.network + '-' + role
            launcher = 'n=0; while [ ! -f /config/config.json ]; do n=$((n+1)); [ "$n" -lt 120 ] || exit 1; sleep 1; done; exec /usr/local/bin/wg-link -config /config/config.json'
            self.docker('run', '-d', '--pull=never', '--name', self.names[role], '--label', self.label,
                        '--network', self.network, '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--read-only',
                        *(['--sysctl', 'net.ipv4.ip_forward=1'] if role == 'router' else []),
                        '--mount', 'type=bind,src=' + str(directory) + ',dst=/config,readonly',
                        '--entrypoint=/bin/sh', self.args.image, '-c', launcher)
            addresses[role] = json.loads(self.docker('inspect', self.names[role]))[0]['NetworkSettings']['Networks'][self.network]['IPAddress']
        def iface(name, key, addr, routes, peer, allowed, endpoint, port):
            return dict(name=name, addresses=addr, mtu=1280, listenPort=port, privateKeyFile='/config/' + key,
                        routes=routes, peers=[dict(publicKey=keys[peer][1], allowedIPs=allowed,
                                                  persistentKeepalive=1, endpoint=addresses[endpoint] + ':' + str(port))])
        configs = {
            'a': {'interfaces': [iface('wg-access', 'a', ['198.18.10.2/32'], ['198.18.30.0/24'], 'ra', ['198.18.30.0/24'], 'router', 51821)]},
            'router': {'interfaces': [iface('wg-access', 'ra', ['198.18.10.1/32'], ['198.18.10.2/32'], 'a', ['198.18.10.2/32'], 'a', 51821), iface('wg-transit', 'rt', ['198.18.20.1/32'], ['198.18.30.0/24'], 'c', ['198.18.30.0/24'], 'c', 51820)]},
            'c': {'interfaces': [iface('wg-transit', 'c', ['198.18.20.2/32', '198.18.30.1/32', '198.18.30.2/32'], ['198.18.10.2/32'], 'rt', ['198.18.10.2/32'], 'router', 51820)]}}
        rules = []
        for src, dst, frm, to in [('198.18.10.2/32', '198.18.30.1/32', 'wg-access', 'wg-transit'), ('198.18.30.1/32', '198.18.10.2/32', 'wg-transit', 'wg-access')]:
            for protocols, ports in [(['icmp'], None), (['tcp', 'udp'], [18080])]:
                rule = dict(source=src, destination=dst, protocols=protocols, **{'from': frm, 'to': to})
                if ports:
                    rule['ports'] = ports
                rules.append(rule)
        configs['router']['forwarding'] = dict(enabled=True, rules=rules)
        for role, names in [('a', ['a']), ('router', ['ra', 'rt']), ('c', ['c'])]:
            for name in names:
                self.put(self.secret / role / name, keys[name][0] + '\n')
            self.put(self.secret / role / 'config.json', json.dumps(configs[role]))
        probe = self.secret / 'probe'
        probe.mkdir(mode=0o755)
        self.put(probe / 'probe.py', probe_source())
        for role, agent, source, target in [('pa', 'a', '198.18.10.2', '198.18.30.1'), ('pc', 'c', '198.18.30.1', '')]:
            self.names[role] = self.network + '-' + role
            self.docker('run', '-d', '--pull=never', '--name', self.names[role], '--label', self.label,
                        '--network=container:' + self.names[agent], '--cap-drop=ALL', '--cap-add=NET_RAW',
                        '--read-only', '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m',
                        '--mount', 'type=bind,src=' + str(probe) + ',dst=/probe,readonly',
                        '-e', 'SOURCE=' + source, '-e', 'TARGET=' + target, self.args.probe_image, 'python', '/probe/probe.py')
        self.wait(lambda: json.loads(self.execute('pa', 'python', '/probe/probe.py', 'ping', '198.18.30.1'))['ok'], 'forwarding readiness')
        before = self.identity()
        # Span several reconciliation ticks: a single initial handshake is not
        # evidence that addresses and connectivity survive steady-state apply.
        stable_start = time.monotonic()
        samples = 0
        while time.monotonic() - stable_start < 6:
            for role, interface, expected in [('a', 'wg-access', {'198.18.10.2'}),
                                              ('router', 'wg-access', {'198.18.10.1'}),
                                              ('router', 'wg-transit', {'198.18.20.1'}),
                                              ('c', 'wg-transit', {'198.18.20.2', '198.18.30.1', '198.18.30.2'})]:
                state = json.loads(self.execute(role, 'ip', '-j', 'address', 'show', 'dev', interface))
                present = {a['local'] for entry in state for a in entry.get('addr_info', [])}
                assert expected <= present, ('steady-state address loss', role, state)
            self.ping('pa', '198.18.30.1', True)
            self.ping('pc', '198.18.10.2', True)
            samples += 1
            time.sleep(.3)
        self.result['steady_state'] = dict(duration_seconds=time.monotonic() - stable_start, samples=samples)
        self.matrix(True)
        for role, local, source, remote in [('pa', '198.18.10.2', '198.18.10.2', '198.18.30.1'), ('pc', '198.18.30.1', '198.18.30.1', '198.18.10.2')]:
            for proto in ('tcp', 'udp'):
                self.check(role, local, 18081, proto, True, source)
                self.check(role, remote, 18081, proto, False)
        # Unauthorized destination is routable and its listeners are locally live.
        for proto in ('tcp', 'udp'):
            self.check('pc', '198.18.30.2', 18080, proto, True, '198.18.30.1')
            self.check('pa', '198.18.30.2', 18080, proto, False)
        self.ping('pa', '198.18.30.2', False)
        # Exercise the unauthorized alias as a source too, not just destination.
        for proto in ('tcp', 'udp'):
            value = json.loads(self.docker('exec', '-e', 'SOURCE=198.18.30.2', self.names['pc'],
                                          'python', '/probe/probe.py', 'check', '198.18.10.2', '18080', proto))
            assert not value['ok'], ('unauthorized source passed', proto, value)
            self.result['checks'].append(dict(role='pc', source='198.18.30.2', destination='198.18.10.2',
                                              protocol=proto, expected=False, observed=value))
        self.result['baseline_nft'] = self.snapshot()
        assert self.counts(self.result['baseline_nft'])['packets']['accept'] > 0
        self.execute('pa', 'python', '-c', "open('/tmp/held-start','w').close()")
        self.wait(lambda: len([e for e in self.events() if e['kind'] == 'held_echo']) >= 3, 'held TCP established')
        connection = next(e for e in self.events() if e['kind'] == 'held_connect')
        denied = copy.deepcopy(configs['router'])
        denied['forwarding']['rules'] = []
        self.put(self.secret / 'router' / 'config.json', json.dumps(denied))
        self.wait(lambda: self.counts(self.snapshot())['rules']['accept'] == 0, 'live ACL revoke')
        time.sleep(1)
        stamp = self.mark('denied')
        drop_before = self.counts(self.snapshot())['packets']['drop']
        self.matrix(False)
        time.sleep(4)
        during = [e for e in self.events() if e['mono_ns'] > stamp and e['kind'].startswith('held_')]
        assert not any(e['kind'] in ('held_echo', 'held_connect', 'held_fatal') for e in during), during
        assert len([e for e in during if e['kind'] == 'held_attempt' and not e['ok']]) >= 3
        self.result['revoked_nft'] = self.snapshot()
        assert self.counts(self.result['revoked_nft'])['packets']['drop'] > drop_before
        self.put(self.secret / 'router' / 'config.json', json.dumps(configs['router']))
        self.wait(lambda: self.counts(self.snapshot())['rules']['accept'] > 0, 'live ACL restore')
        restored = self.mark('restored')
        self.wait(lambda: len([e for e in self.events() if e['kind'] == 'held_echo' and e['mono_ns'] > restored]) >= 3, 'same held socket recovers', 60)
        self.matrix(True)
        events = self.events()
        assert len([e for e in events if e['kind'] == 'held_connect']) == 1
        assert not any(e['kind'] == 'held_fatal' for e in events)
        for event in events:
            if event['kind'] in ('held_echo', 'held_attempt'):
                assert event['local'] == connection['local'] and event['peer'] == connection['peer']
        after = self.identity()
        for role in before:
            assert before[role]['Id'] == after[role]['Id']
            for field in ('Pid', 'StartedAt', 'Restarting'):
                assert before[role]['State'][field] == after[role]['State'][field]
        restored_nft = self.snapshot()
        assert self.counts(restored_nft)['packets']['accept'] > 0, 'restored kernel allow counter did not advance'
        self.result.update(passed=True, identities_before=before, identities_after=after,
                           held_connection=connection, held_events=events, restored_nft=restored_nft)

    def cleanup(self):
        errors = []
        # Discover by exact unique token, then verify ownership before removal.
        ids = self.docker('ps', '-aq', '--filter', 'label=' + self.label, allow=True).split()
        for cid in ids:
            try:
                info = json.loads(self.docker('inspect', cid))[0]
                assert info['Config']['Labels'].get('wg-link.forwarding-test') == self.token
                name = info['Name'].lstrip('/')
                if name in [self.names.get(r) for r in ('pa', 'pc')]:
                    events = self.docker('exec', cid, 'python', '-c', "print(open('/tmp/events.jsonl').read())", allow=True)
                    (self.out / (name + '-events.jsonl')).write_text(self.redact(events))
                if name in [self.names.get(r) for r in ('a', 'router', 'c')]:
                    diagnostics = self.docker('exec', cid, 'ip', '-j', 'address', 'show', allow=True)
                    (self.out / (name + '-addresses.json')).write_text(self.redact(diagnostics))
                logs = self.docker('logs', cid, allow=True)
                (self.out / (name + '.log')).write_text(self.redact(logs))
                self.docker('rm', '-f', cid)
            except Exception as exc:
                errors.append(self.redact(str(exc)))
        info = self.docker('network', 'inspect', self.network, allow=True)
        if info.strip():
            try:
                assert json.loads(info)[0]['Labels'].get('wg-link.forwarding-test') == self.token
                self.docker('network', 'rm', self.network)
            except Exception as exc:
                errors.append(self.redact(str(exc)))
        resolved = self.secret.resolve()
        assert resolved == self.secret and resolved.parent == Path('/tmp') and resolved.name.startswith('wg-forward-secrets-')
        shutil.rmtree(resolved)
        self.result['cleanup_errors'] = errors
        if errors:
            self.result['passed'] = False
        (self.out / 'evidence.json').write_text(self.redact(json.dumps(self.result, indent=2)))
        return not errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='explicitly create disposable Docker resources')
    parser.add_argument('--image', default='wg-link:test')
    parser.add_argument('--probe-image', default='python:3.14-alpine')
    args = parser.parse_args()
    if not args.execute:
        parser.error('--execute is required; no Docker resources touched')
    harness = Harness(args)
    try:
        harness.run()
    except Exception as exc:
        harness.result['error'] = harness.redact(str(exc))
    finally:
        harness.cleanup()
    print(('PASS' if harness.result['passed'] else 'FAIL') + ' local Docker forwarding; evidence: ' + str(harness.out / 'evidence.json'))
    if not harness.result['passed']:
        print(harness.result.get('error', 'cleanup failed'))
    return 0 if harness.result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
