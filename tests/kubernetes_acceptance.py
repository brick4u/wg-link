#!/usr/bin/env python3
"""Opt-in isolated Kubernetes acceptance; --help is safe and never contacts Kubernetes.

Only executes when --execute is supplied. Requires kubectl, docker (for throwaway
WireGuard keys), published digest images, and the explicit brick-dev kubeconfig.
No host networking/mounts, privileged containers, or node mutations are used.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid

# Runs in a disposable sidecar, not in the application image. All timestamps in
# this stream use ONE probe process's monotonic clock, including mutation marks.
PROBE = r'''
import concurrent.futures, json, os, socket, struct, sys, threading, time
PATH='/tmp/events.jsonl'
lock=threading.Lock()
def record(x):
    x['mono_ns']=time.monotonic_ns()
    with lock:
        with open(PATH,'a') as f: f.write(json.dumps(x)+'\n')
def checksum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s>>16)+(s&65535); s+=(s>>16)
    return (~s)&65535
def ping(dst,seq,continuous=True):
    ident=os.getpid()&65535
    payload=b'wg-link-acceptance'
    hdr=struct.pack('!BBHHH',8,0,0,ident,seq&65535)
    packet=struct.pack('!BBHHH',8,0,checksum(hdr+payload),ident,seq&65535)+payload
    t=time.monotonic(); ok=False
    with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP) as s:
        s.settimeout(.6); s.bind((os.environ['SOURCE'],0)); s.sendto(packet,(dst,0))
        while time.monotonic()-t<.6:
            try: b,_=s.recvfrom(4096)
            except socket.timeout: break
            off=(b[0]&15)*4
            if len(b)>=off+8:
                typ,_,_,pid,n=struct.unpack('!BBHHH',b[off:off+8])
                if typ==0 and pid==ident and n==seq&65535: ok=True; break
    record({'kind':'ping','seq':seq,'target':dst,'continuous':continuous,'ok':ok,'started_ns':int(t*1e9),'duration':time.monotonic()-t})
    return ok
def tcp_client(c,a,port):
    with c:
        c.settimeout(1); pending=b''; end=time.monotonic()+600
        while time.monotonic()<end:
            try: data=c.recv(4096)
            except socket.timeout: continue
            except OSError: break
            if not data: break
            pending+=data
            while b'\n' in pending:
                line,pending=pending.split(b'\n',1)
                try: c.sendall(json.dumps({'source':a[0],'payload':line.decode()}).encode()+b'\n')
                except OSError: return
                record({'kind':'received','protocol':'tcp','port':port,'source':a[0],'payload':line.decode()})
def held_tcp():
    while not os.path.exists('/tmp/held-start'): time.sleep(.1)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(1); s.bind((os.environ['SOURCE'],0))
        try: s.connect((os.environ['TARGET'],18080))
        except OSError as e: record({'kind':'held_connect','ok':False,'error':str(e)}); return
        identity={'local':s.getsockname(),'peer':s.getpeername()}
        record({'kind':'held_connect','ok':True,**identity})
        seq=0; pending=b''; end=time.monotonic()+600
        while time.monotonic()<end and not os.path.exists('/tmp/held-stop'):
            seq+=1; ok=False; started=time.monotonic_ns()
            try:
                s.sendall(('held:'+str(seq)+'\n').encode())
                data=s.recv(4096)
                if not data: raise ConnectionError('held TCP peer closed')
                pending+=data
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1); echo=json.loads(line)
                    record({'kind':'held_echo','echo':echo,**identity});ok=True
            except socket.timeout: pass
            except OSError as e:
                record({'kind':'held_fatal','error':str(e),**identity});return
            record({'kind':'held_attempt','seq':seq,'started_ns':started,'ok':ok,**identity})
            time.sleep(.2)
        record({'kind':'held_stopped',**identity})
def echo(proto,port):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',port))
    if proto=='tcp': s.listen()
    else: s.setsockopt(socket.SOL_IP,getattr(socket,'IP_PKTINFO',8),1)
    while True:
        if proto=='tcp':
            c,a=s.accept()
            threading.Thread(target=tcp_client,args=(c,a,port),daemon=True).start()
            continue
        else:
            data,ancillary,flags,a=s.recvmsg(1024,socket.CMSG_SPACE(12))
            pktinfo=[(level,typ,value) for level,typ,value in ancillary if level==socket.SOL_IP and typ==getattr(socket,'IP_PKTINFO',8)]
            # Preserve the addressed alias, not the egress interface primary IP.
            s.sendmsg([json.dumps({'source':a[0],'payload':data.decode()}).encode()],pktinfo,0,a)
        record({'kind':'received','protocol':proto,'port':port,'source':a[0]})
def check(dst,port,proto):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM)
    s.settimeout(2); s.bind((os.environ['SOURCE'],0))
    try:
        s.connect((dst,int(port))); s.sendall(b'acceptance\n' if proto=='tcp' else b'acceptance')
        data=s.recv(1024)
        if proto=='tcp':
            while b'\n' not in data:
                chunk=s.recv(1024)
                if not chunk: raise ConnectionError('echo closed before newline')
                data+=chunk
        result=json.loads(data); result['ok']=True
    except OSError: result={'ok':False}
    finally: s.close()
    print(json.dumps(result))
if len(sys.argv)>1:
    if sys.argv[1]=='mark': record({'kind':'mark','name':sys.argv[2]})
    elif sys.argv[1]=='check': check(*sys.argv[2:])
    elif sys.argv[1]=='ping': print(json.dumps({'ok':ping(sys.argv[2],60000,False)}))
    sys.exit()
for proto in ('tcp','udp'):
    for port in (18080,18081): threading.Thread(target=echo,args=(proto,port),daemon=True).start()
if os.environ.get('TARGET'):
    threading.Thread(target=held_tcp,daemon=True).start()
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=8)
    seq=0; deadline=time.monotonic()
    while True:
        pool.submit(ping,os.environ['TARGET'],seq); seq+=1; deadline+=.2
        time.sleep(max(0,deadline-time.monotonic()))
else:
    while True: time.sleep(3600)
'''


class Harness:
    def __init__(self, args):
        self.a = args
        self.token = uuid.uuid4().hex
        self.ns = 'wg-accept-' + self.token[:12]
        self.out = Path(args.output or tempfile.mkdtemp(prefix='wg-accept-results-')).resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        os.chmod(self.out, 0o700)
        self.result = {'namespace': self.ns, 'image': args.image, 'probe_image': args.probe_image,
                       'events': [], 'checks': [], 'untested': ['node failure/drain/reboot', 'IPv6',
                       'production workloads', 'performance/MTU stress', 'external APN integration'],
                       'clock_note': 'Controller and probe monotonic clocks are separate. Gap calculations use probe clock only.',
                       'latency_note': 'ICMP samples every 0.2s with 0.6s timeout. maximum_observed_success_gap_seconds is the actual observed receive gap, not exact packet-loss duration. prechange_to_confirmed_recovery_seconds runs from the :before mark to the FIFTH successful probe after convergence and includes API command, pod startup and EndpointSlice/kernel peer convergence; prewarming excludes pulls when cached images remain available.'}
        self.created = False
        self.stop = threading.Event()
        self.watcher = None
        self.secrets = []

    def run(self, cmd, data=None, timeout=40, allow=False):
        p = subprocess.run(cmd, input=data, text=True, capture_output=True, timeout=timeout)
        if p.returncode and not allow:
            # Never expose command stdin (contains private keys for Secret apply).
            raise RuntimeError('command failed: ' + ' '.join(cmd[:8]) + ': ' + self.redact(p.stderr))
        return p.stdout

    def redact(self, value):
        for key in self.secrets:
            value = value.replace(key, '[REDACTED]')
        return value

    def k(self, *args, data=None, timeout=40, allow=False):
        return self.run(['kubectl', '--kubeconfig', str(Path('~/.kube/config.brick-dev').expanduser()),
                         '--request-timeout=20s', *args], data, timeout, allow)

    def obj(self, kind, name=None):
        return json.loads(self.k('get', kind, *([name] if name else []), '-n', self.ns, '-o', 'json'))

    def apply(self, objects):
        self.k('apply', '-f', '-', data=json.dumps({'apiVersion':'v1','kind':'List','items':objects}))

    def resource(self, kind, name, **rest):
        return dict(apiVersion='v1', kind=kind, metadata={'name':name,'namespace':self.ns}, **rest)

    def ready_nodes(self):
        nodes = json.loads(self.k('get', 'nodes', '-o', 'json'))['items']
        by = {n['metadata']['name']: n for n in nodes}
        for name in ('cp1','cp2','cp3'):
            assert name in by, 'missing node ' + name
            assert any(c['type']=='Ready' and c['status']=='True' for c in by[name]['status']['conditions']), name+' not Ready'
        return {n: {'uid':by[n]['metadata']['uid'], 'unschedulable':by[n]['spec'].get('unschedulable',False)} for n in ('cp1','cp2','cp3')}

    def wait(self, fn, message, seconds=None):
        end=time.monotonic()+(seconds or self.a.timeout)
        while time.monotonic()<end:
            try:
                value=fn()
                if value: return value
            except (RuntimeError, KeyError, AssertionError, json.JSONDecodeError): pass
            time.sleep(.5)
        raise RuntimeError('timeout: '+message)

    def pod(self, role):
        pods=json.loads(self.k('get','pods','-n',self.ns,'-l','app='+role,'-o','json'))['items']
        ready=[p for p in pods if not p['metadata'].get('deletionTimestamp') and any(c['type']=='Ready' and c['status']=='True' for c in p.get('status',{}).get('conditions',[]))]
        return ready[0] if len(ready)==1 else None

    def execute(self, role, container, *cmd, allow=False):
        pod=self.wait(lambda:self.pod(role),role+' ready')
        return self.k('exec','-n',self.ns,pod['metadata']['name'],'-c',container,'--',*cmd,allow=allow)

    def mark(self, name):
        self.execute('a','probe','python','/probe/probe.py','mark',name)
        self.result['events'].append({'kind':'mark','name':name,'controller_mono_ns':time.monotonic_ns()})

    def service(self, role):
        return self.resource('Service',role,spec={'selector':{'app':role},'ports':[
            {'name':'access','port':51821,'targetPort':51821,'protocol':'UDP'},
            {'name':'transit','port':51820,'targetPort':51820,'protocol':'UDP'}]})

    def topology(self):
        keys={}
        for name in ('a','ra','rt','c'):
            private=self.run(['docker','run','--rm','--network=none','--entrypoint','wg',self.a.key_image,'genkey']).strip()
            self.secrets.append(private)
            public=self.run(['docker','run','--rm','-i','--network=none','--entrypoint','wg',self.a.key_image,'pubkey'],private+'\n').strip()
            self.secrets.append(public)
            keys[name]=(private,public)
        def iface(name, key, addr, routes, peer, allowed, service, port):
            return {'name':name,'addresses':addr,'mtu':1280,'listenPort':port,'privateKeyFile':'/keys/'+key,
                    'routes':routes,'peers':[{'publicKey':keys[peer][1],'allowedIPs':allowed,'persistentKeepalive':1,
                    'service':{'namespace':self.ns,'name':service,'port':'access' if port==51821 else 'transit'}}]}
        configs={
            'a':{'interfaces':[iface('wg-access','a',['198.18.10.2/32'],['198.18.30.0/24'], 'ra',['198.18.30.0/24'],'router',51821)]},
            'router':{'interfaces':[
                iface('wg-access','ra',['198.18.10.1/32'],['198.18.10.2/32'],'a',['198.18.10.2/32'],'a',51821),
                iface('wg-transit','rt',['198.18.20.1/32'],['198.18.30.0/24'],'c',['198.18.30.0/24'],'c',51820)]},
            'c':{'interfaces':[iface('wg-transit','c',['198.18.20.2/32','198.18.30.1/32','198.18.30.2/32'],['198.18.10.2/32'],'rt',['198.18.10.2/32'],'router',51820)]}}
        rules=[]
        for src,dst,frm,to in [('198.18.10.2/32','198.18.30.1/32','wg-access','wg-transit'),('198.18.30.1/32','198.18.10.2/32','wg-transit','wg-access')]:
            for protos,ports in [(['icmp'],None),(['tcp','udp'],[18080])]:
                r=dict(source=src,destination=dst,**{'from':frm,'to':to},protocols=protos)
                if ports:r['ports']=ports
                rules.append(r)
        configs['router']['forwarding']={'enabled':True,'rules':rules}
        self.configs=configs
        objects=[self.resource('ServiceAccount','wg-link'),self.resource('ConfigMap','probe',data={'probe.py':PROBE})]
        objects += [dict(apiVersion='rbac.authorization.k8s.io/v1',kind='Role',metadata={'name':'discovery','namespace':self.ns},rules=[{'apiGroups':[''],'resources':['services'],'verbs':['get','list','watch']},{'apiGroups':['discovery.k8s.io'],'resources':['endpointslices'],'verbs':['get','list','watch']}]),
                    dict(apiVersion='rbac.authorization.k8s.io/v1',kind='RoleBinding',metadata={'name':'discovery','namespace':self.ns},subjects=[{'kind':'ServiceAccount','name':'wg-link','namespace':self.ns}],roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'discovery'})]
        for role,node,keynames in [('a','cp1',['a']),('router','cp2',['ra','rt']),('c','cp3',['c'])]:
            objects += [self.resource('ConfigMap',role,data={'config.yaml':json.dumps(configs[role])}),self.resource('Secret',role,type='Opaque',data={k:base64.b64encode(keys[k][0].encode()).decode() for k in keynames}),self.service(role)]
            caps={'drop':['ALL'],'add':['NET_ADMIN']}
            agent={'name':'wg-link','image':self.a.image,'imagePullPolicy':'IfNotPresent','args':['-config','/config/config.yaml','-listen',':9090'],
                'securityContext':{'runAsUser':0,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':caps},
                'readinessProbe':{'httpGet':{'path':'/readyz','port':9090},'periodSeconds':1},
                'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True},{'name':'keys','mountPath':'/keys','readOnly':True}],
                'resources':{'requests':{'cpu':'20m','memory':'64Mi'},'limits':{'memory':'256Mi'}}}
            probe={'name':'probe','image':self.a.probe_image,'command':['python','/probe/probe.py'],
                'env':[{'name':'SOURCE','value':'198.18.10.2' if role=='a' else '198.18.30.1'}]+([{'name':'TARGET','value':'198.18.30.1'}] if role=='a' else []),
                'securityContext':{'runAsUser':0,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL'],'add':['NET_RAW']}},
                'volumeMounts':[{'name':'probe','mountPath':'/probe','readOnly':True}],
                'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'memory':'128Mi'}}}
            containers=[agent]+([probe] if role!='router' else [])
            spec={'nodeSelector':{'kubernetes.io/hostname':node},'serviceAccountName':'wg-link','terminationGracePeriodSeconds':3,
                  'tolerations':[{'operator':'Exists','effect':'NoSchedule'}], 'securityContext':{'seccompProfile':{'type':'RuntimeDefault'}},
                  'containers':containers,'volumes':[{'name':'config','configMap':{'name':role}},{'name':'keys','secret':{'secretName':role,'defaultMode':256}},{'name':'probe','configMap':{'name':'probe'}}]}
            if role=='router' and self.a.set_forwarding_sysctl:
                spec['securityContext']['sysctls']=[{'name':'net.ipv4.ip_forward','value':'1'}]
            objects.append(dict(apiVersion='apps/v1',kind='Deployment',metadata={'name':role,'namespace':self.ns},spec={'replicas':1,'strategy':{'type':'Recreate'},'selector':{'matchLabels':{'app':role}},'template':{'metadata':{'labels':{'app':role}},'spec':spec}}))
        self.apply(objects)

    def progress(self, message):
        print(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())+' '+message,flush=True)

    def checks(self, phase, allowed=True):
        self.progress(phase+': checking bidirectional ICMP/TCP/UDP and negative controls')
        for role,dst,source in [('a','198.18.30.1','198.18.10.2'),('c','198.18.10.2','198.18.30.1')]:
            icmp=json.loads(self.execute(role,'probe','python','/probe/probe.py','ping',dst))
            self.result['checks'].append(dict(phase=phase,role=role,protocol='icmp',result=icmp))
            assert icmp['ok']==allowed, 'unexpected ICMP result '+role
            # Confirm denied-port servers really listen; a closed port is not an ACL test.
            local=json.loads(self.execute(role,'probe','python','/probe/probe.py','check',source,'18081','tcp'))
            assert local['ok'], 'negative-control TCP echo listener unavailable'
            local=json.loads(self.execute(role,'probe','python','/probe/probe.py','check',source,'18081','udp'))
            assert local['ok'], 'negative-control UDP echo listener unavailable'
            for protocol in ('tcp','udp'):
                for port,expected in [(18080,allowed),(18081,False)]:
                    value=json.loads(self.execute(role,'probe','python','/probe/probe.py','check',dst,str(port),protocol))
                    self.result['checks'].append(dict(phase=phase,role=role,protocol=protocol,port=port,result=value))
                    assert value['ok']==expected, str((role,protocol,port,value))
                    if expected: assert value['source']==source, 'source address changed (NAT)'
        denied_icmp=json.loads(self.execute('a','probe','python','/probe/probe.py','ping','198.18.30.2'))
        assert not denied_icmp['ok'], 'unauthorized ICMP destination forwarded'
        self.result['checks'].append(dict(phase=phase,unauthorized_destination=True,protocol='icmp',result=denied_icmp))
        for protocol in ('tcp','udp'):
            value=json.loads(self.execute('a','probe','python','/probe/probe.py','check','198.18.30.2','18080',protocol))
            self.result['checks'].append(dict(phase=phase,unauthorized_destination=True,protocol=protocol,result=value))
            assert not value['ok'], 'unauthorized destination forwarded'

    def ping_events(self):
        text=self.execute('a','probe','python','-c',"print(open('/tmp/events.jsonl').read())")
        return [json.loads(line) for line in text.splitlines() if line]

    def sustained(self, after=0, expected=True):
        def check():
            p=[e for e in self.ping_events() if e['kind']=='ping' and e.get('continuous',True) and e['started_ns']>after]
            return len(p)>=5 and all(e['ok']==expected for e in sorted(p,key=lambda e:e['started_ns'])[-5:])
        self.wait(check,'five sustained '+('successful' if expected else 'blocked')+' ICMP probes')

    def forwarding_snapshot(self):
        value=json.loads(self.execute('router','wg-link','nft','-j','list','table','inet','wg_link'))
        items=value.get('nftables',[])
        assert any(x.get('table',{}).get('comment')=='wg-link:v1' and x['table'].get('family')=='inet' and x['table'].get('name')=='wg_link' for x in items), 'owned nft table absent'
        rules=[x['rule'] for x in items if x.get('rule',{}).get('table')=='wg_link' and x['rule'].get('chain')=='forward']
        accepts=[r for r in rules if any('accept' in e for e in r.get('expr',[]))]
        drops=[r for r in rules if any('drop' in e for e in r.get('expr',[]))]
        # Both ingress and egress owned-interface guards must survive revocation.
        scoped_drops=[r for r in drops if 'owned_interfaces' in json.dumps(r)]
        assert len(scoped_drops)>=2, 'scoped owned-interface drop guards missing'
        return value,len(accepts)

    def acl_revocation(self):
        self.progress('acl-revocation: live ConfigMap deny/restore; no router restart')
        original=self.pod('router')
        identity=(original['metadata']['uid'],[(c['name'],c.get('restartCount',0)) for c in original['status']['containerStatuses']])
        saved=json.loads(json.dumps(self.configs['router']))
        denied=json.loads(json.dumps(saved));denied['forwarding']['rules']=[]
        self.execute('a','probe','python','-c',"open('/tmp/held-start','w').close()")
        def held_ready():
            events=self.ping_events()
            assert not any(e['kind']=='held_fatal' for e in events), 'held TCP failed before revocation'
            return len([e for e in events if e['kind']=='held_echo'])>=3
        self.wait(held_ready,'held TCP established and echoing without reconnect')
        connection=next(e for e in self.ping_events() if e['kind']=='held_connect' and e['ok'])
        self.mark('acl-revocation:before')
        def update(config):
            start=time.monotonic_ns()
            self.apply([self.resource('ConfigMap','router',data={'config.yaml':json.dumps(config)})])
            self.result['events'].append({'kind':'acl_configmap_update','deny':not bool(config['forwarding']['rules']),'controller_start_ns':start,'controller_end_ns':time.monotonic_ns()})
        def kernel(expected_accept):
            value,count=self.forwarding_snapshot()
            if (count>0)!=expected_accept:return False
            return value
        try:
            update(denied)
            self.progress('acl-revocation: waiting for projected ConfigMap and kernel accept-rule removal (up to timeout)')
            snapshot=self.wait(lambda:kernel(False),'live nft ACL revocation')
            (self.out/'acl-revoked-nft.json').write_text(self.redact(json.dumps(snapshot,indent=2)))
            # Drain any echo already delivered before the nft transaction before
            # opening the denial observation window on the A process clock.
            time.sleep(1)
            self.mark('acl-revocation:denied')
            stamp=next(e['mono_ns'] for e in reversed(self.ping_events()) if e.get('name')=='acl-revocation:denied')
            self.sustained(stamp,expected=False)
            self.checks('acl-revoked',allowed=False)
            held_denied=[e for e in self.ping_events() if e['mono_ns']>stamp and e['kind'].startswith('held_')]
            assert not any(e['kind'] in ('held_echo','held_fatal','held_connect') for e in held_denied), 'held TCP echoed, failed fatally or reconnected during revoked ACL'
            assert len([e for e in held_denied if e['kind']=='held_attempt' and not e['ok']])>=3, 'held TCP denial interval lacks failed request evidence'
            self.result['held_tcp_denial']={'connection':connection,'events':held_denied,'no_reconnect':True}
            self.progress('acl-revocation: held TCP and new traffic blocked; restoring original ACL')
        finally:
            # Restore even when an assertion fails, without touching other resources.
            update(saved)
        snapshot=self.wait(lambda:kernel(True),'live nft ACL restoration')
        (self.out/'acl-restored-nft.json').write_text(self.redact(json.dumps(snapshot,indent=2)))
        self.mark('acl-revocation:returned')
        stamp=next(e['mono_ns'] for e in reversed(self.ping_events()) if e.get('name')=='acl-revocation:returned')
        self.sustained(stamp)
        def held_restored():
            events=self.ping_events()
            connects=[e for e in events if e['kind']=='held_connect']
            assert len(connects)==1 and connects[0]['ok'], 'held TCP reconnected'
            assert not any(e['kind']=='held_fatal' for e in events), 'held TCP failed fatally'
            echoes=[e for e in events if e['kind']=='held_echo' and e['mono_ns']>stamp]
            assert all(e['local']==connection['local'] and e['peer']==connection['peer'] for e in echoes), 'held TCP socket tuple changed'
            return len(echoes)>=3
        self.wait(held_restored,'original held TCP session resumes after ACL restore')
        self.execute('a','probe','python','-c',"open('/tmp/held-stop','w').close()")
        self.mark('acl-revocation:recovered')
        self.checks('acl-restored')
        current=self.pod('router')
        assert identity==(current['metadata']['uid'],[(c['name'],c.get('restartCount',0)) for c in current['status']['containerStatuses']]), 'router restarted during live ACL update'
        self.result['acl_revocation']={'passed':True,'router_restarted':False,'established_tcp_revocation_tested':True,'same_tcp_session_restored':True,'continuous_icmp':True,'new_connections_both_directions':['tcp','udp']}
        self.progress('acl-revocation: PASS (new traffic denied; original established TCP blocked and restored without reconnect)')

    def observe(self):
        while not self.stop.is_set():
            start=time.monotonic_ns()
            try:
                slices=self.obj('endpointslices')['items']
                endpoints=[{'service':s['metadata']['labels'].get('kubernetes.io/service-name'),'ports':s.get('ports'), 'endpoints':s.get('endpoints')} for s in slices]
                peers={}
                for role in ('a','c'):
                    p=self.pod(role)
                    if p:
                        peers[role]=self.k('exec','-n',self.ns,p['metadata']['name'],'-c','wg-link','--','wg','show','all','endpoints',allow=True)
                self.result['events'].append({'kind':'observation','controller_start_ns':start,'controller_end_ns':time.monotonic_ns(),'endpointslices':endpoints,'peer_endpoints':peers})
            except Exception as e:
                self.result['events'].append({'kind':'observation_error','error':self.redact(str(e))})
            self.stop.wait(.5)

    def mutation(self,name,fn):
        self.progress(name+': starting isolated workload/service mutation (not a node failure test)')
        self.sustained()
        self.mark(name+':before')
        start=time.monotonic_ns()
        fn()
        self.result['events'].append({'kind':'mutation_return','name':name,'controller_start_ns':start,'controller_end_ns':time.monotonic_ns()})
        self.k('rollout','status','deployment/router','-n',self.ns,'--timeout='+str(self.a.timeout)+'s',timeout=self.a.timeout+30)
        self.wait(self.discovery_converged, 'EndpointSlices and actual kernel peer endpoints converge')
        self.mark(name+':returned')
        marks=[e for e in self.ping_events() if e.get('name')==name+':returned']
        self.sustained(marks[-1]['mono_ns'])
        self.mark(name+':recovered')
        self.checks(name)
        self.progress(name+': PASS')

    def discovery_converged(self):
        router=self.pod('router')
        if not router:return False
        ip=router['status']['podIP']
        slices=self.obj('endpointslices')['items']
        addresses=[a for s in slices if s['metadata']['labels'].get('kubernetes.io/service-name')=='router' for e in s.get('endpoints',[]) if e.get('conditions',{}).get('ready') for a in e.get('addresses',[])]
        if not addresses or set(addresses)!={ip}:return False
        for role,port in [('a',51821),('c',51820)]:
            value=self.execute(role,'wg-link','wg','show','all','endpoints')
            if ip+':'+str(port) not in value:return False
        return True

    def diagnostics(self, phase):
        for role in ('a','router','c'):
            pods=json.loads(self.k('get','pods','-n',self.ns,'-l','app='+role,'-o','json',allow=True) or '{"items":[]}')['items']
            for p in pods:
                name=p['metadata']['name']
                log=self.k('logs','-n',self.ns,name,'-c','wg-link','--tail=300',allow=True)
                (self.out/(phase+'-'+name+'.log')).write_text(self.redact(log))
                if role=='router':
                    for label,cmd in [('nft',['nft','-j','list','ruleset']),('forwarding',['cat','/proc/sys/net/ipv4/ip_forward'])]:
                        text=self.k('exec','-n',self.ns,name,'-c','wg-link','--',*cmd,allow=True)
                        (self.out/(phase+'-'+label+'.json' if label=='nft' else phase+'-'+label+'.txt')).write_text(self.redact(text))
                        if phase=='baseline':
                            if label=='forwarding': assert text.strip()=='1','router ip_forward must be 1; rerun with --set-forwarding-sysctl if admission permits'
                            else:
                                value=json.loads(text)
                                counters=[]
                                def walk(x):
                                    if isinstance(x,dict):
                                        if 'counter' in x and isinstance(x['counter'],dict): counters.append(x['counter'])
                                        for v in x.values():walk(v)
                                    elif isinstance(x,list):
                                        for v in x:walk(v)
                                owned=[item for item in value.get('nftables',[]) if any(isinstance(v,dict) and (v.get('table')=='wg_link' or (k=='table' and v.get('name')=='wg_link')) for k,v in item.items())]
                                assert owned, 'owned inet wg_link nft table missing'
                                walk(owned)
                                assert any(c.get('packets',0)>0 for c in counters),'no live owned kernel nft packet counters'
                                verdict_packets={'accept':0,'drop':0}
                                for item in owned:
                                    expr=item.get('rule',{}).get('expr',[])
                                    for verdict in verdict_packets:
                                        if any(verdict in x for x in expr):
                                            verdict_packets[verdict]+=sum(x.get('counter',{}).get('packets',0) for x in expr)
                                assert all(verdict_packets.values()), 'owned allow and deny nft rules must both count packets'
                                self.result['baseline_nft_counters']={'counters':counters,'verdict_packets':verdict_packets}

    def prewarm(self):
        for node in ('cp1','cp2','cp3'):
            self.progress('prewarm: '+node+' application and probe images')
            self.apply([self.resource('Pod','prewarm-'+node,spec={'nodeSelector':{'kubernetes.io/hostname':node},'tolerations':[{'operator':'Exists','effect':'NoSchedule'}], 'restartPolicy':'Never','containers':[
                {'name':'agent','image':self.a.image,'command':['/bin/sh','-c','sleep 600']},
                {'name':'probe','image':self.a.probe_image,'command':['python','-c','import time; time.sleep(600)']} ]})])
            self.k('wait','-n',self.ns,'--for=condition=Ready','pod/prewarm-'+node,'--timeout='+str(self.a.timeout)+'s',timeout=self.a.timeout+30)
        self.k('delete','pods','-n',self.ns,'prewarm-cp1','prewarm-cp2','prewarm-cp3','--wait=true',timeout=self.a.timeout)

    def main(self):
        self.progress('preflight: verify cp1/cp2/cp3 Ready using explicit brick-dev kubeconfig')
        before=self.ready_nodes(); self.result['nodes_before']=before
        try:
            # Create, never adopt/relabel an existing namespace.
            self.k('create','-f','-',data=json.dumps({'apiVersion':'v1','kind':'Namespace','metadata':{'name':self.ns,'labels':{'wg-link-acceptance-owner':self.token,'pod-security.kubernetes.io/enforce':'privileged','pod-security.kubernetes.io/audit':'privileged','pod-security.kubernetes.io/warn':'privileged'}}}))
            self.created=True
            if not self.a.skip_prewarm:self.prewarm()
            self.progress('topology: creating isolated A cp1 / router cp2 / C cp3 workloads')
            self.topology()
            for role in ('a','router','c'):self.wait(lambda:self.pod(role),role+' startup')
            self.watcher=threading.Thread(target=self.observe); self.watcher.start()
            self.sustained(); self.checks('baseline'); self.diagnostics('baseline')
            self.progress('baseline: PASS')
            self.acl_revocation()
            self.mutation('move-cp2-to-cp3',lambda:self.k('patch','deployment/router','-n',self.ns,'--type=merge','-p',json.dumps({'spec':{'template':{'spec':{'nodeSelector':{'kubernetes.io/hostname':'cp3'}}}}})))
            assert self.pod('router')['spec']['nodeName']=='cp3'
            self.mutation('delete-router-pod',lambda:self.k('delete','pod',self.pod('router')['metadata']['name'],'-n',self.ns,'--wait=true'))
            def scale():
                self.k('scale','deployment/router','-n',self.ns,'--replicas=0')
                self.wait(lambda:not self.obj('pods')['items'] or not any(p['metadata'].get('labels',{}).get('app')=='router' for p in self.obj('pods')['items']),'router removed')
                time.sleep(3)
                self.k('scale','deployment/router','-n',self.ns,'--replicas=1')
            self.mutation('scale-zero-one',scale)
            def service():
                old=self.obj('service','router')['spec']['clusterIP']
                self.k('delete','service/router','-n',self.ns,'--wait=true')
                # Reserve the old IP in this namespace so recreation MUST get a different IP.
                hold=self.service('old-ip-reservation'); hold['spec']['clusterIP']=old; hold['spec']['selector']={'app':'absent'}
                self.apply([hold,self.service('router')])
                new=self.obj('service','router')['spec']['clusterIP']; assert old!=new
                self.result['service_recreation']={'old_cluster_ip':old,'new_cluster_ip':new}
            self.mutation('service-new-cluster-ip',service)
            self.diagnostics('final')
            self.result['passed']=True
        except BaseException as e:
            self.result['passed']=False; self.result['error']=self.redact(str(e))
            if self.created:
                try:self.diagnostics('failure')
                except Exception as diagnostic_error:self.result['diagnostics_error']=self.redact(str(diagnostic_error))
            raise
        finally:
            self.progress('cleanup: collect sanitized evidence and delete only owned namespace '+self.ns)
            self.stop.set()
            if self.watcher:self.watcher.join(timeout=240)
            if self.watcher and self.watcher.is_alive():
                self.result['observer_error']='observer failed to stop within bounded API timeouts'
                self.result['passed']=False
            if self.created:
                try:
                    events=self.ping_events(); self.result['probe_events']=events
                    self.summarize(events)
                    for role in ('a','c'):
                        text=self.execute(role,'probe','python','-c',"print(open('/tmp/events.jsonl').read())")
                        (self.out/('probe-'+role+'.jsonl')).write_text(self.redact(text))
                except Exception as e:
                    self.result['probe_collection_error']=self.redact(str(e)); self.result['passed']=False
                try:
                    ns=json.loads(self.k('get','namespace',self.ns,'-o','json'))
                    assert ns['metadata']['labels'].get('wg-link-acceptance-owner')==self.token,'namespace ownership changed; refusing cleanup'
                    self.k('delete','namespace',self.ns,'--wait=true','--timeout='+str(self.a.timeout)+'s',timeout=self.a.timeout+30)
                    self.result['namespace_deleted']=True
                except Exception as e:self.result['cleanup_error']=self.redact(str(e)); self.result['passed']=False
            try:
                after=self.ready_nodes();self.result['nodes_after']=after
                assert before==after,'node identity or scheduling state changed'
            except Exception as e:self.result['node_check_error']=str(e);self.result['passed']=False
            (self.out/'results.json').write_text(self.redact(json.dumps(self.result,indent=2)))
            print('Results: '+str(self.out/'results.json'))

    def summarize(self,events):
        p=sorted([e for e in events if e['kind']=='ping' and e.get('continuous',True)],key=lambda e:e['started_ns'])
        marks={e['name']:e['mono_ns'] for e in events if e['kind']=='mark'}
        summaries=[]
        for name,t in marks.items():
            if not name.endswith(':before'):continue
            prefix=name[:-7]; end=marks.get(prefix+':recovered',2**63)
            prior=[e for e in p if e['ok'] and e['mono_ns']<t]
            post=[e for e in p if e['started_ns']>t and e['mono_ns']<=end]
            threshold=marks.get(prefix+':returned',t)
            converged=[e for e in post if e['started_ns']>threshold]
            first=None;confirmed=None
            for i in range(len(converged)-4):
                if all(e['ok'] for e in converged[i:i+5]):
                    first=converged[i];confirmed=converged[i+4];break
            last=prior[-1] if prior else None
            successes=sorted(([last] if last else [])+[e for e in post if e['ok']],key=lambda e:e['mono_ns'])
            maxgap=max(((b['mono_ns']-a['mono_ns'])/1e9 for a,b in zip(successes,successes[1:])),default=None)
            failed=[e for e in post if not e['ok']]
            loss_start=failed[0]['started_ns'] if failed else None
            loss_prior=[e for e in successes if loss_start is not None and e['started_ns']<loss_start]
            last_before_loss=max(loss_prior,key=lambda e:e['mono_ns']) if loss_prior else None
            after_loss=[e for e in post if loss_start is not None and e['started_ns']>loss_start]
            data_recovery=None
            for i in range(len(after_loss)-4):
                if all(e['ok'] for e in after_loss[i:i+5]):data_recovery=after_loss[i];break
            summaries.append({'name':prefix,'last_prechange_success_ns':last['mono_ns'] if last else None,'first_sustained_success_after_convergence_ns':first['mono_ns'] if first else None,
                              'observed_loss':bool(failed),'first_failed_probe_started_ns':loss_start,
                              'last_success_before_loss_ns':last_before_loss['mono_ns'] if last_before_loss else None,
                              'first_sustained_success_after_loss_ns':data_recovery['mono_ns'] if data_recovery else None,
                              'last_before_loss_to_sustained_recovery_seconds':(data_recovery['mono_ns']-last_before_loss['mono_ns'])/1e9 if data_recovery and last_before_loss else None,
                              'maximum_observed_success_gap_seconds':maxgap,
                              'confirmed_fifth_success_ns':confirmed['mono_ns'] if confirmed else None,
                              'prechange_to_confirmed_recovery_seconds':(confirmed['mono_ns']-t)/1e9 if confirmed else None,
                              'failed_probes':sum(not e['ok'] for e in post),'sample_interval_seconds':.2,'icmp_timeout_seconds':.6})
        self.result['recovery']=summaries
        if self.result.get('passed'):
            expected={'move-cp2-to-cp3','delete-router-pod','scale-zero-one','service-new-cluster-ip'}
            assert expected.issubset({s['name'] for s in summaries}), 'incomplete latency scenario evidence'
            assert all(s['confirmed_fifth_success_ns'] is not None and
                       s['prechange_to_confirmed_recovery_seconds'] is not None and
                       s['maximum_observed_success_gap_seconds'] is not None for s in summaries), 'missing recovery measurement'
            self.result['latency_evidence_complete']=True


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True,help='Published wg-link image@sha256:digest')
    p.add_argument('--probe-image',required=True,help='Published python:3.14-alpine image@sha256:digest (stdlib + raw sockets)')
    p.add_argument('--key-image',default='wg-link:test',help='Local image containing wg, used with docker --network=none only')
    p.add_argument('--output',help='Private result directory (default new temporary directory)')
    p.add_argument('--timeout',type=int,default=180)
    p.add_argument('--skip-prewarm',action='store_true')
    p.add_argument('--set-forwarding-sysctl',action='store_true',help='Request pod-only net.ipv4.ip_forward=1; cluster admission may reject it')
    p.add_argument('--execute',action='store_true',help='Explicit consent to create/delete isolated test namespace and workloads')
    a=p.parse_args()
    for image in (a.image,a.probe_image):
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}',image):p.error('images must use immutable sha256 digests')
    if not a.execute:p.error('no changes made: supply --execute to run the isolated acceptance test')
    if a.timeout<10:p.error('--timeout must be at least 10 seconds')
    def interrupted(signum,frame):raise KeyboardInterrupt('signal '+str(signum))
    signal.signal(signal.SIGTERM,interrupted)
    h=Harness(a)
    try:h.main()
    except BaseException as e:print('Acceptance failed: '+h.redact(str(e)));return 1
    return 0 if h.result.get('passed') else 1

if __name__=='__main__':raise SystemExit(main())
