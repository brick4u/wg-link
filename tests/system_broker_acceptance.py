"""Broker topology and real-MQTT assertions for system_acceptance (offline import safe)."""
import json
import re
import secrets
import time

OWNER = 'wg-link.test/owner'
APN = '198.18.10.2'
CLIENT = '198.18.40.2'
BROKER_IP = '192.0.2.80'
BROKER_PORTS = [12101, 12201, 1883]


class BrokerAcceptance:
    def broker_resources(self, objects):
        password = secrets.token_hex(24)
        self.sensitive.append(password)
        objects.append(self.resource('Secret', 'mqtt-auth', stringData={
            'credentials.json': json.dumps({'username': 'wgtest', 'password': password}), 'password': password}))
        objects.append(self.resource('ConfigMap', 'mqtt-acl', data={'vmq.acl': 'user wgtest\ntopic isolated/#\n'}))
        for i in range(1, 4):
            name = 'broker-'+str(i)
            broker = self.container('vernemq', self.a.broker_image,
                env=[{'name': 'DOCKER_VERNEMQ_ALLOW_ANONYMOUS', 'value': 'off'},
                     {'name': 'DOCKER_VERNEMQ_USER_WGTEST', 'valueFrom': {'secretKeyRef': {'name': 'mqtt-auth', 'key': 'password'}}},
                     {'name': 'DOCKER_VERNEMQ_LISTENER__TCP__DEFAULT', 'value': '0.0.0.0:1883'},
                     {'name': 'DOCKER_VERNEMQ_LISTENER__TCP__DEFAULT__PROXY_PROTOCOL', 'value': 'on'},
                     {'name': 'DOCKER_VERNEMQ_VMQ_ACL__ACL_FILE', 'value': '/test-acl/vmq.acl'},
                     {'name': 'ERL_FLAGS', 'value': '+S 2:2 +A 4'}],
                readinessProbe={'tcpSocket': {'port': 1883}, 'periodSeconds': 3},
                volumeMounts=[{'name': 'data', 'mountPath': '/vernemq/data'},
                              {'name': 'log', 'mountPath': '/vernemq/log'},
                              {'name': 'acl', 'mountPath': '/test-acl', 'readOnly': True}])
            broker['securityContext'].update(runAsUser=10000, runAsGroup=10000)
            broker['resources'] = {'requests': {'cpu': '100m', 'memory': '256Mi'}, 'limits': {'memory': '768Mi'}}
            pod = self.pod(name, self.a.nodes[(i-1) % 3], [broker],
                           [{'name': 'data', 'emptyDir': {}}, {'name': 'log', 'emptyDir': {}},
                            {'name': 'acl', 'configMap': {'name': 'mqtt-acl'}}])
            pod['spec']['automountServiceAccountToken'] = False
            pod['spec']['securityContext']['fsGroup'] = 10000
            pod['metadata']['labels']['app'] = name
            objects.append(pod)
            objects.append(self.resource('Service', name, spec={'selector': {'app': name},
                'ports': [{'name': 'mqtt', 'port': 1883, 'targetPort': 1883, 'protocol': 'TCP'}]}))

    def haproxy_config(self, index, timeout='2h'):
        return f'''# wg-system-config-{timeout}
global
 log stdout format raw local0
 maxconn 1200
defaults
 log global
 mode tcp
 timeout connect 5s
 timeout client {timeout}
 timeout server {timeout}
resolvers kubernetes
 parse-resolv-conf
 accepted_payload_size 8192
 hold valid 5s
 timeout resolve 1s
 timeout retry 1s
frontend mqtt
 bind 0.0.0.0:1883
 default_backend mqtt_backend
backend mqtt_backend
 server broker broker-{index}.{self.ns}.svc.cluster.local:1883 resolvers kubernetes init-addr last,libc,none check inter 2s send-proxy-v2 check-send-proxy
'''

    def proxy_resources(self, objects, cfg):
        for i in range(1, 4):
            name = 'proxy-'+str(i)
            objects.append(self.resource('ConfigMap', name+'-haproxy', data={'haproxy.cfg': self.haproxy_config(i)}))
            wg = self.container('wg-link', self.a.wg_image, ['NET_ADMIN'],
                args=['-config', '/config/config.yaml', '-listen', ':9090'],
                readinessProbe={'httpGet': {'path': '/readyz', 'port': 9090}, 'periodSeconds': 2},
                volumeMounts=[{'name': 'config', 'mountPath': '/config', 'readOnly': True},
                              {'name': 'keys', 'mountPath': '/keys', 'readOnly': True}])
            proxy = self.container('haproxy', self.a.haproxy_image,
                command=['/usr/local/sbin/haproxy', '-W', '-db', '-f', '/config/haproxy.cfg'],
                readinessProbe={'exec': {'command': ['/bin/sh', '-ec', 'nc -z -w 1 127.0.0.1 1883']},
                                'periodSeconds': 2, 'timeoutSeconds': 2},
                volumeMounts=[{'name': 'haproxy', 'mountPath': '/config', 'readOnly': True}])
            proxy['securityContext'].update(runAsUser=99, runAsGroup=99)
            pod = self.pod(name, self.a.nodes[(i+1) % 3], [wg, proxy],
                [{'name': 'config', 'configMap': {'name': name}},
                 {'name': 'keys', 'secret': {'secretName': name, 'defaultMode': 256}},
                 {'name': 'haproxy', 'configMap': {'name': name+'-haproxy'}}])
            pod['metadata']['labels']['app'] = name
            deployment = self.resource('Deployment', name, spec={'replicas': 1, 'strategy': {'type': 'Recreate'},
                'selector': {'matchLabels': {'app': name, OWNER: self.token}},
                'template': {'metadata': {'labels': pod['metadata']['labels']}, 'spec': pod['spec']}})
            deployment['apiVersion'] = 'apps/v1'
            objects.append(deployment)

    def proxy_pod(self, name):
        items = json.loads(self.k('get', 'pods', '-n', self.ns, '-l', 'app='+name, '-o', 'json'))['items']
        items = [p for p in items if not p['metadata'].get('deletionTimestamp')]
        assert len(items) == 1, 'proxy must have exactly one live Pod'
        assert items[0]['metadata']['labels'][OWNER] == self.token
        return items[0]

    def mqtt(self, action, **kwargs):
        self.progress('MQTT driver: '+action)
        request = json.dumps(dict(action=action, **kwargs))
        code = ('import urllib.request; r=urllib.request.Request("http://127.0.0.1:18083/",'
                'data='+repr(request.encode())+',headers={"Content-Type":"application/json"}); '
                'print(urllib.request.urlopen(r,timeout='+str(self.a.timeout)+').read().decode())')
        raw = self.k('exec', '-n', self.ns, 'provider', '-c', 'probe', '--', 'python', '-c', code,
                     timeout=self.a.timeout+10)
        value = json.loads(raw)
        assert value['ok'], value
        return value['result']

    def session_rows(self, index):
        raw = self.exec('broker-'+str(index), 'vernemq', '/vernemq/bin/vmq-admin', 'session', 'show',
                        '--client_id', '--peer_host', '--is_online', '--session_pid', '--session_started_at',
                        '--limit=1100', '--format=json')
        parsed = json.loads(raw)
        rows = []
        def visit(value):
            if isinstance(value, dict):
                if 'client_id' in value and 'peer_host' in value:
                    rows.append(value)
                else:
                    for child in value.values(): visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
        visit(parsed)
        return rows

    def sessions(self, flows):
        by_broker = {i: self.session_rows(i) for i in range(1, 4)}
        evidence = {}
        for flow in flows:
            index = int(flow['client_id'].rsplit('-', 1)[1]) % 3 + 1
            matching = [r for r in by_broker[index] if r['client_id'] == flow['client_id']]
            assert len(matching) == 1, ('missing actual broker session', flow['client_id'])
            row = matching[0]
            assert row['peer_host'] == APN, ('PROXYv2 APN identity lost', row)
            assert row['is_online'] in (True, 'true'), 'broker session not online'
            evidence[flow['client_id']] = {k: row[k] for k in ('peer_host', 'session_pid', 'session_started_at')}
        return evidence

    def stable_identity(self, names):
        result = {}
        for name in names:
            pod = self.proxy_pod(name) if name.startswith('proxy-') else self.obj('pod', name)
            result[name] = {'uid': pod['metadata']['uid'], 'containers': {
                c['name']: [c['containerID'], c['restartCount']] for c in pod['status']['containerStatuses']}}
        return result

    def sa_identity(self):
        raw = self.exec('gateway', 'strongswan', 'swanctl', '--list-sas', '--raw')
        fields = re.findall(r'\b(?:uniqueid|initiator-spi|responder-spi|spi-in|spi-out)=([^\s}]+)', raw)
        assert len(fields) >= 5, 'SA identifiers/SPIs missing from VICI evidence'
        return sorted(fields)

    def held_check(self, flows):
        after = self.mqtt('check', ids=[f['client_id'] for f in flows])
        for old, new in zip(flows, after):
            assert old['client_id'] == new['client_id'] and old['socket'] == new['socket']
            assert new['sequence'] > old['sequence'] and new['puback'] and new['subscribed_echo']
        return after

    def mqtt_paths(self):
        for i in range(1, 4):
            self.wait(lambda i=i: self.ready('broker-'+str(i)), 'VerneMQ backend readiness')
            self.wait(lambda i=i: self.ready(self.proxy_pod('proxy-'+str(i))['metadata']['name']), 'HAProxy + WG readiness')
        opened = self.wait(self.open_three, 'real MQTT CONNECT + SUBSCRIBE + QoS1 PUBACK through all original ports')
        self.held = self.held_check(opened['flows'])
        self.held_sessions = self.sessions(self.held)
        self.result['mqtt_initial'] = {'connections': opened, 'broker_sessions': self.held_sessions}
        for host, port in [(BROKER_IP, 19999), ('192.0.2.81', BROKER_PORTS[0])]:
            code = ('import socket; s=socket.socket();s.settimeout(2);s.bind(('+repr(APN)+',0));'
                    'r=s.connect_ex(('+repr(host)+','+str(port)+'));assert r!=0;s.close()')
            self.exec('provider', 'probe', 'python', '-c', code)
        return True

    def proxy_reload(self):
        names = ['gateway', 'provider', 'dns-1', 'dns-2', 'support', 'support-client',
                 'broker-1', 'broker-2', 'broker-3', 'proxy-1', 'proxy-2', 'proxy-3']
        before, sas = self.stable_identity(names), self.sa_identity()
        pod = self.proxy_pod('proxy-1')['metadata']['name']
        assert self.exec(pod, 'haproxy', 'cat', '/proc/1/comm').strip() == 'haproxy'
        self.apply([self.resource('ConfigMap', 'proxy-1-haproxy', data={'haproxy.cfg': self.haproxy_config(1, '3h')})])
        self.wait(lambda: 'wg-system-config-3h' in self.exec(pod, 'haproxy', 'cat', '/config/haproxy.cfg'),
                  'projected HAProxy ConfigMap marker')
        self.exec(pod, 'haproxy', 'haproxy', '-c', '-f', '/config/haproxy.cfg')
        children = set(self.exec(pod, 'haproxy', 'cat', '/proc/1/task/1/children').split())
        assert children, 'HAProxy master has no worker'
        self.exec(pod, 'haproxy', '/bin/sh', '-ec', 'kill -USR2 1')
        self.wait(lambda: set(self.exec(pod, 'haproxy', 'cat', '/proc/1/task/1/children').split())-children,
                  'new HAProxy worker generation after master USR2')
        fresh = self.mqtt('fresh', prefix='new-worker-'+self.token[:8], port=12101)
        assert fresh['puback'] and fresh['subscribed_echo']
        start = time.monotonic()
        rounds = 0
        while time.monotonic()-start < 10:
            self.held = self.held_check(self.held)
            rounds += 1
            time.sleep(0.5)
        assert self.held_sessions == self.sessions(self.held), 'reload replaced MQTT broker sessions'
        assert before == self.stable_identity(names), 'reload changed Pod/container identity'
        assert sas == self.sa_identity(), 'reload changed IPsec SA identity/SPIs'
        self.result['haproxy_reload'] = {'valid_timeout_change': '2h -> 3h', 'held_flows': self.held,
            'sustained_rounds': rounds, 'sustained_seconds': time.monotonic()-start,
            'new_worker_fresh_mqtt': fresh, 'stable_pods_containers_and_sa_spis': True}
        return True

    def proxy_restart(self):
        names = ['gateway', 'provider', 'dns-1', 'dns-2', 'support', 'support-client',
                 'broker-1', 'broker-2', 'broker-3', 'proxy-2', 'proxy-3']
        before, sas = self.stable_identity(names), self.sa_identity()
        old = self.proxy_pod('proxy-1')
        deployment = self.obj('deployment', 'proxy-1')
        assert deployment['metadata']['labels'][OWNER] == self.token
        assert deployment['spec']['replicas'] == 1 and deployment['spec']['strategy']['type'] == 'Recreate'
        owners = old['metadata'].get('ownerReferences', [])
        assert len(owners) == 1 and owners[0]['kind'] == 'ReplicaSet'
        replica = self.obj('replicaset', owners[0]['name'])
        assert any(r['uid'] == deployment['metadata']['uid'] for r in replica['metadata']['ownerReferences'])
        self.k('delete', '--raw', '/api/v1/namespaces/'+self.ns+'/pods/'+old['metadata']['name'],
               '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions',
                    'preconditions': {'uid': old['metadata']['uid']}}))
        survivors = [f for f in self.held if not f['client_id'].endswith('-0')]
        self.held_check(survivors)
        self.wait(lambda: self.mqtt('broken', id=self.held[0]['client_id'])['broken'], 'old MQTT connection breaks')
        def replaced():
            pod = self.proxy_pod('proxy-1')
            return pod if pod['metadata']['uid'] != old['metadata']['uid'] and self.ready(pod['metadata']['name']) else None
        new = self.wait(replaced, 'replacement proxy Pod ready')
        assert new['status']['podIP'] != old['status']['podIP'], 'replacement must exercise a changed Pod IP'
        def endpoint():
            slices = json.loads(self.k('get', 'endpointslices', '-n', self.ns, '-l',
                                     'kubernetes.io/service-name=proxy-1', '-o', 'json'))['items']
            ready = [e for s in slices for e in s.get('endpoints', []) if e.get('conditions', {}).get('ready')]
            if len(ready) != 1 or ready[0].get('targetRef', {}).get('uid') != new['metadata']['uid']: return False
            wire = self.exec('gateway', 'wg-link', 'wg', 'show', 'wg-broker', 'endpoints')
            return new['status']['podIP']+':51823' in wire
        self.wait(endpoint, 'single Ready EndpointSlice and gateway WG endpoint replacement')
        self.held_check(survivors)
        assert {f['client_id']: self.held_sessions[f['client_id']] for f in survivors} == self.sessions(survivors)
        assert before == self.stable_identity(names), 'unrelated Pod/container changed on proxy replacement'
        assert sas == self.sa_identity(), 'proxy replacement changed IPsec SAs'
        self.dns()
        self.echo('support-client', APN, source=CLIENT)
        opened = self.wait(self.open_three, 'automatic restored broker VIP path')
        self.held = self.held_check(opened['flows'])
        self.result['proxy_restart'] = {'old_uid': old['metadata']['uid'], 'new_uid': new['metadata']['uid'],
            'old_ip': old['status']['podIP'], 'new_ip': new['status']['podIP'],
            'other_flows_survived': survivors, 'stable_sa_spis': True, 'automatic_endpoint_restored': True}
        return True

    def open_three(self):
        self.mqtt('close')
        value = self.mqtt('open', prefix='held-'+self.token[:8], count=3)
        self.result['last_mqtt_open'] = value
        return value if value['established'] == 3 and not value['errors'] else None

    def mqtt_burst(self):
        self.mqtt('close')
        opened = self.mqtt('open', prefix='burst-'+self.token[:8], count=self.a.connection_count,
                           interval=self.a.connection_interval)
        self.result['mqtt_reconnect'] = opened
        assert opened['established'] == self.a.connection_count and not opened['errors'], opened
        held = self.held_check(opened['flows'])
        self.result['mqtt_reconnect']['broker_sessions'] = self.sessions(held)
        self.result['mqtt_reconnect']['verified_online_count'] = len(held)
        self.result['proxy_resources'] = {}
        for i in range(1, 4):
            name = self.proxy_pod('proxy-'+str(i))['metadata']['name']
            raw = self.k('get', '--raw', '/apis/metrics.k8s.io/v1beta1/namespaces/'+self.ns+'/pods/'+name, allow=True)
            try: self.result['proxy_resources'][name] = json.loads(raw)
            except json.JSONDecodeError: self.result['proxy_resources'][name] = {'available': False}
            pids = ['1'] + self.exec(name, 'haproxy', 'cat', '/proc/1/task/1/children').split()
            rss = {}
            for pid in pids:
                assert pid.isdigit()
                status = self.exec(name, 'haproxy', 'cat', '/proc/'+pid+'/status')
                rss[pid] = next((line for line in status.splitlines() if line.startswith('VmRSS:')), 'unavailable')
            self.result['proxy_resources'][name]['process_rss_not_additive'] = rss
        self.mqtt('close')
        self.result['mqtt_reconnect']['capacity_scope'] = 'Concurrent authenticated MQTT clients in the isolated dev topology'
        return True
