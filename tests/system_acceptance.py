#!/usr/bin/env python3
"""Opt-in, disposable overall integration topology. No subprocess runs without --execute.

All images MUST be supplied as immutable repository@sha256 digests. The caller
supplies three distinct node names and kubeconfig; no environment defaults apply.
Only namespace-scoped resources are changed. Namespace deletion is unconditional
on exit, but guarded by a unique ownership label. SIGINT/SIGTERM use that path.

Topology: provider (IKE only) -> gateway -> DNS and support transit; external
support client -> support -> gateway -> APN. A sixth Pod is a mock Internet sink.
Provider/gateway use standard image entrypoints and swanctl load-all. The strongSwan
image must load /etc/strongswan.conf, start charon as PID 1, provide swanctl, and
read /etc/swanctl/swanctl.conf. Exporter flags follow torilabs v1.10.2.
Unbound uses explicit static policy answers: recursion/DNSSEC/public Internet are
not acceptance claims. No SLA or production/APN interoperability claim is made.

Run --help for parameters. Without --execute only validates arguments. This file
can be imported for offline manifest inspection; importing has no side effects.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import tempfile
import time
import uuid

OWNER = 'wg-link.test/owner'
APN = '198.18.10.2'
DNS = ['198.18.53.1', '198.18.53.2']
CLIENT = '198.18.40.2'
# Reuse the existing generic echo/ICMP implementation without importing its CLI.
_spec = importlib.util.spec_from_file_location('wg_accept_probe', Path(__file__).with_name('kubernetes_acceptance.py'))
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
PROBE = r'''
import http.server,threading,json
class EchoHTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=json.dumps({'source':self.client_address[0],'path':self.path}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*args):pass
threading.Thread(target=http.server.ThreadingHTTPServer(('0.0.0.0',18082),EchoHTTP).serve_forever,daemon=True).start()
''' + _module.PROBE
DNS_PROBE = r'''
import json,socket,struct,sys,random
source,dst,proto,name,expected=sys.argv[1:]
ident=random.randrange(65536)
q=struct.pack('!HHHHHH',ident,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM)
s.settimeout(3);s.bind((source,0));s.connect((dst,53))
def exact(n):
 b=b''
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:raise RuntimeError('short DNS response')
  b+=c
 return b
if proto=='tcp':
 s.sendall(struct.pack('!H',len(q))+q);b=exact(struct.unpack('!H',exact(2))[0])
else:s.send(q);b=s.recv(4096)
assert struct.unpack('!H',b[:2])[0]==ident and b[3]&15==0 and b[2]&128
# The static answer must occur as an A RDATA, not merely somewhere in the packet.
def skip(off):
 while b[off]:
  if b[off]&192==192:return off+2
  off+=1+b[off]
 return off+1
o=skip(12)+4;answers=[]
for _ in range(struct.unpack('!H',b[6:8])[0]):
 o=skip(o);typ,cls,ttl,n=struct.unpack('!HHIH',b[o:o+10]);o+=10
 if typ==1 and cls==1 and n==4:answers.append(socket.inet_ntoa(b[o:o+4]))
 o+=n
assert expected in answers,(expected,answers)
print(json.dumps({'ok':True,'answers':answers,'transport':proto,'server':dst,'source':source}))
'''


class Harness:
    def __init__(self, args):
        self.a = args
        self.token = uuid.uuid4().hex
        self.ns = 'wg-system-' + self.token[:12]
        self.created = False
        self.sensitive = []
        self.out = Path(args.output or tempfile.mkdtemp(prefix='wg-system-')).resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        os.chmod(self.out, 0o700)
        self.result = {'schema': 1, 'checks': [], 'images': {k: getattr(args, k) for k in
                       ('wg_image', 'strongswan_image', 'unbound_image', 'exporter_image', 'probe_image')},
                       'limitations': ['static DNS policy, not recursive DNSSEC validation',
                                       'mock APN and Internet only', 'no failover SLA', 'IPv4 only']}

    def redact(self, text):
        for item in self.sensitive:
            text = text.replace(item, '[REDACTED]')
        return text

    def run(self, argv, data=None, timeout=45, allow=False):
        if not self.a.execute:
            raise RuntimeError('--execute is required for subprocess execution')
        p = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout)
        if p.returncode and not allow:
            raise RuntimeError('subprocess failed: ' + self.redact(p.stderr[-3000:]))
        return p.stdout

    def k(self, *args, data=None, timeout=45, allow=False):
        return self.run(['kubectl', '--kubeconfig', self.a.kubeconfig,
                         '--request-timeout=25s', *args], data, timeout, allow)

    def resource(self, kind, name, **rest):
        return dict(apiVersion='v1', kind=kind, metadata={'name': name, 'namespace': self.ns,
                    'labels': {OWNER: self.token}}, **rest)

    def apply(self, objects):
        self.k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}))

    def obj(self, kind, name):
        return json.loads(self.k('get', kind, name, '-n', self.ns, '-o', 'json'))

    def wait(self, fn, message):
        end = time.monotonic() + self.a.timeout
        last = None
        while time.monotonic() < end:
            try:
                value = fn()
                if value:
                    return value
            except (RuntimeError, KeyError, AssertionError, json.JSONDecodeError) as e:
                last = type(e).__name__
            time.sleep(1)
        raise RuntimeError('timeout: ' + message + ' (' + str(last) + ')')

    def exec(self, role, container, *cmd, allow=False):
        return self.k('exec', '-n', self.ns, role, '-c', container, '--', *cmd, allow=allow)

    def check(self, name, fn):
        start = time.monotonic()
        value = fn()
        assert value is not False, name
        self.result['checks'].append({'name': name, 'ok': True,
                                     'controller_duration_seconds': time.monotonic()-start})
        return value

    def ready(self, role):
        p = self.obj('pod', role)
        return p if any(c['type']=='Ready' and c['status']=='True'
                        for c in p.get('status', {}).get('conditions', [])) else None

    def security(self, caps=()):
        return {'runAsUser': 0, 'allowPrivilegeEscalation': False,
                'capabilities': {'drop': ['ALL'], 'add': list(caps)}}

    def container(self, name, image, caps=(), **rest):
        return dict(name=name, image=image, imagePullPolicy='IfNotPresent',
                    securityContext=self.security(caps), resources={'requests': {'cpu': '10m', 'memory': '32Mi'},
                    'limits': {'memory': '256Mi'}}, **rest)

    def pod(self, role, node, containers, volumes=(), init=()):
        return self.resource('Pod', role, spec={'nodeName': node, 'serviceAccountName': 'wg-link',
            'restartPolicy': 'Always', 'terminationGracePeriodSeconds': 5,
            'securityContext': {'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': containers, 'initContainers': list(init), 'volumes': list(volumes)})

    def service(self, name, role, ports):
        r = self.resource('Service', name, spec={'selector': {'app': role}, 'ports': [
            {'name': n, 'port': p, 'targetPort': p, 'protocol': 'UDP'} for n, p in ports]})
        return r

    def probe(self, source):
        return self.container('probe', self.a.probe_image, ['NET_RAW'],
            command=['python', '/probe/probe.py'], env=[{'name': 'SOURCE', 'value': source}],
            volumeMounts=[{'name': 'probe', 'mountPath': '/probe', 'readOnly': True}])

    def setup(self):
        # Read-only identity snapshots, no node mutation/labeling is performed.
        self.nodes = {}
        for n in self.a.nodes:
            v = json.loads(self.k('get', 'node', n, '-o', 'json'))
            assert any(c['type']=='Ready' and c['status']=='True' for c in v['status']['conditions'])
            self.nodes[n] = (v['metadata']['uid'], v['spec'].get('unschedulable', False))
        ns = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.ns, 'labels': {
            OWNER: self.token, 'pod-security.kubernetes.io/enforce': 'privileged'}}}
        # Set before request: cleanup also handles ambiguous API response failures.
        self.created = True
        # Never adopt/relabel an existing namespace, even on a UUID collision.
        self.k('create','-f','-',data=json.dumps(ns))
        objects = [self.resource('ServiceAccount', 'wg-link'), self.resource('ConfigMap', 'probe',
                   data={'probe.py': PROBE, 'dns.py': DNS_PROBE})]
        role = self.resource('Role', 'discovery', rules=[
            {'apiGroups': [''], 'resources': ['services'], 'verbs': ['get', 'list', 'watch']},
            {'apiGroups': ['discovery.k8s.io'], 'resources': ['endpointslices'], 'verbs': ['get', 'list', 'watch']}])
        role['apiVersion'] = 'rbac.authorization.k8s.io/v1'
        bind = self.resource('RoleBinding', 'discovery', subjects=[{'kind': 'ServiceAccount', 'name': 'wg-link', 'namespace': self.ns}],
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'discovery'})
        bind['apiVersion'] = 'rbac.authorization.k8s.io/v1'
        objects += [role, bind]
        sink = self.pod('internet-sink', self.a.nodes[2], [self.probe('0.0.0.0')],
                        [{'name': 'probe', 'configMap': {'name': 'probe'}}])
        objects.append(sink)
        self.apply(objects)
        self.wait(lambda: self.ready('internet-sink'), 'mock Internet sink ready')
        self.sink = self.obj('pod', 'internet-sink')['status']['podIP']
        self.topology()

    def topology(self):
        keys = {}
        for name in ('gd', 'gt', 'dns', 'st', 'sa', 'client'):
            private = self.run(['docker', 'run', '--rm', '--network=none', '--entrypoint', 'wg', self.a.wg_image, 'genkey']).strip()
            public = self.run(['docker', 'run', '--rm', '-i', '--network=none', '--entrypoint', 'wg', self.a.wg_image, 'pubkey'], private+'\n').strip()
            self.sensitive += [private, public]
            keys[name] = (private, public)
        def iface(name, key, addr, routes, peer, allowed, service, port):
            return {'name': name, 'addresses': addr, 'routes': routes, 'listenPort': port,
                'privateKeyFile': '/keys/'+key, 'peers': [{'publicKey': keys[peer][1], 'allowedIPs': allowed,
                'persistentKeepalive': 1, 'service': {'namespace': self.ns, 'name': service, 'port': 'p'+str(port)}}]}
        cfg = {
            'gateway': {'interfaces': [
                iface('wg-dns', 'gd', ['198.18.51.1/32'], ['198.18.53.0/24'], 'dns', ['198.18.53.0/24'], 'dns', 51820),
                iface('wg-transit', 'gt', ['198.18.52.1/32'], ['198.18.40.0/24'], 'st', ['198.18.40.0/24'], 'support', 51822)]},
            'dns': {'interfaces': [iface('wg-dns', 'dns', [x+'/32' for x in DNS], ['198.18.10.0/24'], 'gd', ['198.18.10.0/24'], 'gateway', 51820)]},
            'support': {'interfaces': [
                iface('wg-support', 'sa', ['198.18.40.1/32'], [CLIENT+'/32'], 'client', [CLIENT+'/32'], 'support-client', 51821),
                iface('wg-transit', 'st', ['198.18.52.2/32'], ['198.18.10.0/24'], 'gt', ['198.18.10.0/24'], 'gateway', 51822)]},
            'support-client': {'interfaces': [iface('wg-support', 'client', [CLIENT+'/32'], ['198.18.10.0/24'], 'sa', ['198.18.10.0/24'], 'support', 51821)]}}
        def rule(frm, to, src, dst, protocols, ports=None):
            v = {'from': frm, 'to': to, 'source': src, 'destination': dst, 'protocols': protocols}
            if ports: v['ports'] = ports
            return v
        rules = []
        for dst, interface, ports in [('198.18.53.1/32', 'wg-dns', [53, 18080]),
                                       ('198.18.53.2/32', 'wg-dns', [53]),
                                       (CLIENT+'/32', 'wg-transit', [18080]),
                                       (self.sink+'/32', 'eth0', [18080,18082])]:
            rules.append(rule('eth0', interface, '198.18.10.0/24', dst, ['tcp', 'udp'], ports))
            rules.append(rule(interface, 'eth0', dst, '198.18.10.0/24', ['tcp', 'udp'], [18080]))
            if interface == 'wg-transit':
                rules += [rule('eth0', interface, '198.18.10.0/24', dst, ['icmp']),
                          rule(interface, 'eth0', dst, '198.18.10.0/24', ['icmp'])]
        cfg['gateway']['forwarding'] = {'enabled': True, 'externalInterfaces': ['eth0'], 'rules': rules,
            'masquerade': [{'from': 'eth0', 'to': 'eth0', 'source': '198.18.10.0/24', 'destination': self.sink+'/32'}]}
        cfg['support']['forwarding'] = {'enabled': True, 'rules': [
            rule(f, t, s, d, protos, ports) for f,t,s,d in [
                ('wg-support','wg-transit',CLIENT+'/32','198.18.10.0/24'),
                ('wg-transit','wg-support','198.18.10.0/24',CLIENT+'/32')]
            for protos,ports in [(['icmp'],None), (['tcp','udp'],[18080])]]}
        objects = []
        for role, config in cfg.items():
            used = {'gateway': ['gd','gt'], 'dns': ['dns'], 'support': ['st','sa'], 'support-client': ['client']}[role]
            objects += [self.resource('ConfigMap', role, data={'config.yaml': json.dumps(config)}),
                        self.resource('Secret', role, type='Opaque', data={k: base64.b64encode(keys[k][0].encode()).decode() for k in used})]
            ports = {'gateway': [51820,51822], 'dns': [51820], 'support': [51821,51822], 'support-client': [51821]}[role]
            objects.append(self.service(role, role, [('p'+str(p),p) for p in ports]))
        psk = secrets.token_hex(32)
        self.sensitive.append(psk)
        for role, remote, localid, remoteid, localts, remotets, action in [
            ('gateway','provider-peer','gateway.example','provider.example','0.0.0.0/0','198.18.10.0/24','none'),
            ('provider','ipsec-gateway','provider.example','gateway.example','198.18.10.0/24','0.0.0.0/0','start')]:
            sw = f'''connections {{ apn {{ version = 1
 local_addrs = %any
 remote_addrs = {('%any' if role=='gateway' else remote+'.'+self.ns+'.svc.cluster.local')}
 proposals = aes256-sha256-ecp384
 encap = yes
 keyingtries = 0
 dpd_delay = 2s
 dpd_timeout = 6s
 local {{ auth = psk\n id = {localid} }}
 remote {{ auth = psk\n id = {remoteid} }}
 children {{ apn {{ local_ts = {localts}\n remote_ts = {remotets}\n esp_proposals = aes256-sha256-ecp384\n start_action = {action}\n dpd_action = restart\n close_action = restart }} }}
 }} }}
secrets {{ ike-apn {{ id-1 = gateway.example\n id-2 = provider.example\n secret = {psk} }} }}
'''
            # Preserve image defaults, including charon start-scripts load-all,
            # stderr logging, plugin loading and the standard /run VICI socket.
            objects.append(self.resource('Secret', role+'-ipsec', stringData={'swanctl.conf': sw}))
            objects.append(self.service('ipsec-gateway' if role=='gateway' else 'provider-peer', role, [('ike',500),('natt',4500)]))
        unbound = '''server:
 interface: 0.0.0.0
 interface-automatic: yes
 port: 53
 username: ""
 chroot: ""
 directory: "/var/unbound"
 module-config: "validator iterator"
 auto-trust-anchor-file: "/var/unbound/root.key"
 use-syslog: no
 logfile: ""
 verbosity: 1
 log-queries: yes
 log-replies: yes
 access-control: 198.18.10.0/24 allow
 access-control: 0.0.0.0/0 refuse
 local-zone: "allowed.example." static
 local-data: "allowed.example. 60 IN A 192.0.2.123"
 local-zone: "sinkhole.example." static
 local-data: "sinkhole.example. 60 IN A 127.0.0.1"
'''
        objects.append(self.resource('ConfigMap', 'unbound', data={'unbound.conf': unbound}))
        for role, node in [('provider',self.a.nodes[0]),('gateway',self.a.nodes[1]),('dns',self.a.nodes[2]),
                           ('support',self.a.nodes[0]),('support-client',self.a.nodes[2])]:
            volumes = [{'name':'probe','configMap':{'name':'probe'}}]
            containers = []
            if role in cfg:
                volumes += [{'name':'config','configMap':{'name':role}}, {'name':'keys','secret':{'secretName':role,'defaultMode':256}}]
                containers.append(self.container('wg-link',self.a.wg_image,['NET_ADMIN'],
                    args=['-config','/config/config.yaml','-listen',':9090'],
                    readinessProbe={'httpGet':{'path':'/readyz','port':9090},'periodSeconds':2},
                    volumeMounts=[{'name':'config','mountPath':'/config','readOnly':True},{'name':'keys','mountPath':'/keys','readOnly':True}]))
            source = {'provider':APN, 'gateway':'198.18.51.1', 'dns':DNS[0], 'support': '198.18.40.1', 'support-client':CLIENT}[role]
            containers.append(self.probe(source))
            init = []
            if role in ('gateway','provider'):
                volumes += [{'name':'run','emptyDir':{}}, {'name':'ipsec','secret':{'secretName':role+'-ipsec'}}]
                containers.append(self.container('strongswan',self.a.strongswan_image,['NET_ADMIN','NET_RAW','NET_BIND_SERVICE'],
                    readinessProbe={'exec':{'command':['swanctl','--stats']},'periodSeconds':3},
                    livenessProbe={'exec':{'command':['swanctl','--stats']},'initialDelaySeconds':30,'periodSeconds':10,'failureThreshold':6},
                    volumeMounts=[{'name':'run','mountPath':'/run'},
                        {'name':'ipsec','mountPath':'/etc/swanctl/swanctl.conf','subPath':'swanctl.conf','readOnly':True}]))
                if role=='provider':
                    init.append(self.container('apn-alias',self.a.wg_image,['NET_ADMIN'],command=['ip','addr','add',APN+'/32','dev','lo']))
                else:
                    containers.append(self.container('vici-exporter',self.a.exporter_image,
                        args=['--vici-network=unix','--vici-address=/run/charon.vici','--server-port=8079'],
                        volumeMounts=[{'name':'run','mountPath':'/run'}]))
            if role=='dns':
                volumes.append({'name':'unbound','configMap':{'name':'unbound'}})
                resolver=self.container('unbound',self.a.unbound_image,['NET_BIND_SERVICE'],
                    command=['/usr/sbin/unbound','-d','-c','/config/unbound.conf'],
                    volumeMounts=[{'name':'unbound','mountPath':'/config','readOnly':True}])
                resolver['securityContext'].update(runAsUser=101,runAsGroup=102,readOnlyRootFilesystem=False)
                containers.append(resolver)
            pod = self.pod(role,node,containers,volumes,init)
            pod['metadata']['labels']['app']=role
            objects.append(pod)
        self.apply(objects)

    def echo(self, role, target, proto='tcp', port=18080, expected=True, source=None):
        v = json.loads(self.exec(role,'probe','python','/probe/probe.py','check',target,str(port),proto))
        assert v['ok']==expected, (role,target,proto,port,v)
        if source and expected: assert v['source']==source, ('unexpected source',v)
        return v

    def dns(self):
        for server in DNS:
            for proto in ('udp','tcp'):
                for name,answer in [('allowed.example','192.0.2.123'),('sinkhole.example','127.0.0.1')]:
                    self.exec('provider','probe','python','/probe/dns.py',APN,server,proto,name,answer)
        return True

    def load(self):
        for role in ('gateway','provider'):
            self.exec(role,'strongswan','swanctl','--load-all')
        self.exec('provider','strongswan','swanctl','--initiate','--child','apn',allow=True)

    def datapath(self):
        try:
            self.echo('support-client', APN, source=CLIENT)
            self.dns()
            return True
        except (RuntimeError, AssertionError):
            return False

    def metrics(self):
        text = self.exec('gateway','probe','python','-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8079/metrics',timeout=3).read().decode())")
        # Parse metric names/labels, never accept build_info or process metrics.
        samples=[]
        for line in text.splitlines():
            if not line or line.startswith('#'):continue
            match=re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([^\s]+)(?:\s+\d+)?',line)
            if match:samples.append((match[1],match[2] or '',float(match[3])))
        assert any(n=='strongswan_ike_count' and v>=1 for n,l,v in samples), 'no IKE SA count'
        assert any(n=='strongswan_ike_children_size' and v>=1 for n,l,v in samples), 'no CHILD SA count'
        assert any(n=='strongswan_ike_version' and v==1 for n,l,v in samples), 'no IKEv1 SA metric'
        assert any(n=='strongswan_sa_status' and v==0 for n,l,v in samples), 'no INSTALLED SA metric'
        traffic_names={'strongswan_sa_inbound_bytes','strongswan_sa_inbound_packets',
                       'strongswan_sa_outbound_bytes','strongswan_sa_outbound_packets'}
        traffic=[(n,v) for n,l,v in samples if n in traffic_names]
        assert {n for n,v in traffic}==traffic_names, 'missing SA traffic metrics'
        assert all(v>0 for n,v in traffic), 'SA traffic counters must be positive both directions'
        return text

    def tests(self):
        for role in ('provider','gateway','dns','support','support-client'):
            self.wait(lambda r=role:self.ready(r), role+' local readiness')
        self.load()
        self.wait(self.datapath, 'IKE + support + DNS convergence')
        self.check('DNS policy both aliases UDP/TCP',self.dns)
        for role,target,source in [('provider',CLIENT,APN),('support-client',APN,CLIENT)]:
            self.check(role+' ICMP',lambda r=role,t=target: json.loads(self.exec(r,'probe','python','/probe/probe.py','ping',t))['ok'])
            for proto in ('tcp','udp'):
                self.check(role+' '+proto,lambda r=role,t=target,p=proto,s=source:self.echo(r,t,p,source=s))
                # Verify the denied service exists at the target before claiming ACL denial.
                other = 'provider' if role=='support-client' else 'support-client'
                self.echo(other,target,proto,18081)
                self.check(role+' denied '+proto,lambda r=role,t=target,p=proto:self.echo(r,t,p,18081,False))
        for proto in ('tcp','udp'):
            self.check('internal source preserved '+proto,lambda p=proto:self.echo('provider',DNS[0],p,source=APN))
            gwip=self.obj('pod','gateway')['status']['podIP']
            self.check('Internet destination scoped masquerade '+proto,lambda p=proto:self.echo('provider',self.sink,p,source=gwip))
        http=json.loads(self.exec('provider','probe','python','-c',
            "import http.client,json; c=http.client.HTTPConnection("+repr(self.sink)+",18082,timeout=3,source_address=("+repr(APN)+",0)); c.request('GET','/generic'); print(c.getresponse().read().decode())"))
        assert http['source']==gwip, 'HTTP mock Internet source was not masqueraded'
        self.result['checks'].append({'name':'mock Internet HTTP source masqueraded','ok':True})
        for proto in ('tcp','udp'):
            self.echo('dns',DNS[1],proto,18080)  # destination really has a listener
            self.check('denied DNS broker alias '+proto,lambda p=proto:self.echo('provider',DNS[1],p,18080,False))
        sas=self.exec('gateway','strongswan','swanctl','--list-sas')
        assert 'IKEv1' in sas and 'INSTALLED' in sas, 'IKEv1 CHILD SA not installed'
        self.check('exporter SA metrics',self.metrics)
        logs=self.k('logs','-n',self.ns,'dns','-c','unbound')
        assert APN in logs and 'allowed.example' in logs, 'Unbound did not observe APN source'
        self.check('datapath loss distinct from daemon liveness',self.health_failure)
        self.check('charon-only restart and exporter reconnect',self.restart)
        # Read-only counters; never manipulate nft/XFRM outside the applications.
        for role in ('gateway','support'):
            self.result[role+'_nft']=json.loads(self.exec(role,'wg-link','nft','-j','list','table','inet','wg_link'))
        self.result['xfrm_policy']=self.exec('gateway','strongswan','ip','xfrm','policy')
        for n,identity in self.nodes.items():
            v=json.loads(self.k('get','node',n,'-o','json'))
            assert identity==(v['metadata']['uid'],v['spec'].get('unschedulable',False)), 'node identity/state changed'

    def health_failure(self):
        # Remove credentials/connections from provider so automatic reinitiation cannot
        # defeat the failure window. Local VICI liveness remains independent.
        # Standard load-conns unloads configurations absent from the supplied file.
        # /dev/null is an empty configuration; no unsupported unload-conns command.
        self.exec('provider','strongswan','swanctl','--load-conns','--file','/dev/null')
        try:
            for role in ('provider','gateway'):
                self.exec(role,'strongswan','swanctl','--terminate','--ike','apn',allow=True)
            self.wait(lambda:not self.datapath(),'datapath failure')
            for role in ('provider','gateway'):
                self.exec(role,'strongswan','swanctl','--stats')
        finally:
            self.load()
        self.wait(self.datapath,'datapath recovery')
        return True

    def restart(self):
        before=self.obj('pod','gateway')
        status={c['name']:c for c in before['status']['containerStatuses']}
        pid=self.exec('gateway','probe','python','-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8079/metrics').read().decode())")
        # PID 1 must be the image's charon, not a supervisor; fail safely otherwise.
        comm=self.exec('gateway','strongswan','cat','/proc/1/comm').strip()
        assert 'charon' in comm, 'strongSwan image must run charon as PID 1'
        self.exec('gateway','strongswan','/bin/sh','-ec','kill -TERM 1',allow=True)
        self.wait(lambda:next(c for c in self.obj('pod','gateway')['status']['containerStatuses']
                             if c['name']=='strongswan')['restartCount']>status['strongswan']['restartCount'], 'charon container restart')
        self.wait(lambda:self.ready('gateway'),'local readiness after restart')
        # Image startup must load its standard swanctl configuration. Provider
        # DPD restart is responsible for recovery; no controller initiate here.
        self.wait(self.datapath,'automatic DPD datapath recovery after restart')
        self.wait(self.metrics,'exporter reconnect')
        after=self.obj('pod','gateway')
        assert before['metadata']['uid']==after['metadata']['uid']
        for c in after['status']['containerStatuses']:
            if c['name']!='strongswan':
                assert c['restartCount']==status[c['name']]['restartCount']==0
                assert c['containerID']==status[c['name']]['containerID']
        return True

    def diagnostics(self):
        """Best-effort bounded evidence; never collect Secrets or config manifests."""
        if not self.created:return
        def capture(name, *args):
            try:
                text=self.k(*args,timeout=8,allow=True)
                path=self.out/name
                path.write_text(self.redact(text))
                os.chmod(path,0o600)
                return text
            except BaseException as e:
                self.result.setdefault('diagnostic_errors',[]).append(name+': '+type(e).__name__)
                return ''
        # Ownership guards diagnostics too: never inspect a colliding foreign namespace.
        try:
            namespace=json.loads(self.k('get','namespace',self.ns,'-o','json',timeout=8))
            if namespace['metadata'].get('labels',{}).get(OWNER)!=self.token:return
        except BaseException:return
        pods=capture('failure-pods.txt','get','pods','-n',self.ns,'-o','wide')
        capture('failure-events.txt','get','events','-n',self.ns,'--sort-by=.metadata.creationTimestamp')
        try:
            raw=self.k('get','pods','-n',self.ns,'-o','json',timeout=8)
            items=json.loads(raw)['items']
        except BaseException:items=[]
        for pod in items:
            name=pod['metadata']['name']
            if pod['metadata'].get('labels',{}).get(OWNER)!=self.token:continue
            for container in pod['spec'].get('containers',[])+pod['spec'].get('initContainers',[]):
                c=container['name']
                for previous in (False,True):
                    capture('failure-'+name+'-'+c+('-previous' if previous else '')+'.log',
                        'logs','-n',self.ns,name,'-c',c,'--tail=200',
                        *(['--previous'] if previous else []))
        for name,container,command in [
            ('routes','wg-link',['ip','route','show','table','all']),
            ('nft','wg-link',['nft','-j','list','table','inet','wg_link']),
            ('xfrm-policy','strongswan',['ip','xfrm','policy']),
            ('xfrm-state-nokeys','strongswan',['ip','-s','xfrm','state','nokeys'])]:
            capture('failure-gateway-'+name+'.txt','exec','-n',self.ns,'gateway','-c',container,'--',*command)

    def cleanup(self):
        if not self.created:return
        text=self.k('get','namespace',self.ns,'--ignore-not-found','-o','json')
        if not text.strip():return
        obj=json.loads(text)
        assert obj['metadata'].get('labels',{}).get(OWNER)==self.token, 'cleanup ownership mismatch'
        self.k('delete','namespace',self.ns,'--wait=true','--timeout=180s',timeout=200)
        assert not self.k('get','namespace',self.ns,'--ignore-not-found','-o','name').strip()
        self.result['cleanup_verified']=True

    def main(self):
        def stop(signum, frame):raise KeyboardInterrupt('signal '+str(signum))
        old={s:signal.signal(s,stop) for s in (signal.SIGINT,signal.SIGTERM)}
        try:
            self.setup()
            self.tests()
            self.result['ok']=True
        except BaseException as e:
            self.result['ok']=False
            self.result['error']=self.redact(str(e))
            # Interrupts during evidence collection must not bypass namespace cleanup.
            for s in old:signal.signal(s,signal.SIG_IGN)
            try:self.diagnostics()
            except BaseException as diagnostic_error:
                self.result['diagnostics_error']=type(diagnostic_error).__name__
            raise
        finally:
            # Prevent a second interrupt from abandoning cleanup.
            for s in old:signal.signal(s,signal.SIG_IGN)
            try:self.cleanup()
            except BaseException as e:
                self.result['cleanup_verified']=False
                self.result['cleanup_error']=self.redact(str(e))
                self.result['ok']=False
                raise
            finally:
                (self.out/'result.json').write_text(self.redact(json.dumps(self.result,indent=2)))
                os.chmod(self.out/'result.json',0o600)
                for s,handler in old.items():signal.signal(s,handler)


def arguments(argv=None):
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--execute',action='store_true',help='explicitly permit Docker and Kubernetes execution')
    p.add_argument('--kubeconfig',required=True,help='explicit caller-owned kubeconfig; never inferred')
    p.add_argument('--nodes',nargs=3,required=True,metavar=('PROVIDER_NODE','GATEWAY_NODE','DNS_NODE'))
    for name in ('wg','strongswan','unbound','exporter','probe'):
        p.add_argument('--'+name+'-image',required=True,help='immutable repository@sha256 digest')
    p.add_argument('--output',help='private evidence directory (no manifests or secret logs)')
    p.add_argument('--timeout',type=int,default=220)
    a=p.parse_args(argv)
    if len(set(a.nodes))!=3:p.error('--nodes requires three distinct node names')
    if a.timeout<30:p.error('--timeout must be at least 30 seconds')
    for key in ('wg_image','strongswan_image','unbound_image','exporter_image','probe_image'):
        if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',getattr(a,key)):
            p.error('--'+key.replace('_','-')+' requires an immutable sha256 digest')
    return a


if __name__=='__main__':
    args=arguments()
    if not args.execute:
        print('Arguments valid. No Docker or Kubernetes operation performed; add --execute to run.')
    else:
        Harness(args).main()
