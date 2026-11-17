#!/usr/bin/env python3
"""Bounded Flannel/Multus IPvlan acceptance; Python standard library only.

No cluster I/O without --execute. Run flannel mode before ipvlan mode. The caller
owns installing Multus/plugins and assigning the test Floating IP to --node.
No host changes, IP moves, restarts, production protocols, or credentials are used.
UDP/TCP ingress must be permitted to the two test ports. The controller must be
outside the cluster, with a direct public route (not a VPN) to the Floating IP.
An initiating UDP packet warms a home NAT mapping; the same bound socket receives
the reply. This demonstrates ordinary UDP, not native ESP or a production VPN.
Evidence includes public addresses; keep the output directory private.

Example (replace placeholders):
  python3 tests/ipvlan_acceptance.py --execute --mode ipvlan \\
    --kubeconfig <config> --node <node> --peer-node <other-node> \\
    --floating-ip <test-ip> --gateway <gateway> --parent-interface <nic> \\
    --python-image <image@sha256:digest> --tools-image <image@sha256:digest> \\
    --evidence-dir <private-directory>

Explicit table 100 keeps the primary eth0 default unchanged. The gateway /32
link-scope route precedes the default; addresses deliberately have no gateway.
CNI version is caller-selectable; confirm secondary 1.1.0 support before execution.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid


POD_PROGRAM = r'''
import concurrent.futures, json, os, socket, struct, threading, time
BIND=os.environ['BIND']; UDP=int(os.environ['UDP_PORT']); TCP=int(os.environ['TCP_PORT'])
def reply(data, peer, local, method, ifindex=None):
    request=json.loads(data)
    return json.dumps(dict(nonce=request['nonce'], method=method, observed_source=list(peer),
                           local_address=local, ifindex=ifindex)).encode()
def udp_loop():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((BIND,UDP))
    s.setsockopt(socket.IPPROTO_IP,8,1) # Linux IP_PKTINFO; no raw capability needed.
    while True:
        data,anc,flags,peer=s.recvmsg(2048,128)
        idx=None; local=s.getsockname()[0]
        for level,kind,value in anc:
            if level==socket.IPPROTO_IP and kind==8:
                idx,_,dst=struct.unpack('I4s4s',value[:12]); local=socket.inet_ntoa(dst)
        try: s.sendto(reply(data,peer,local,'udp',idx),peer)
        except (ValueError,KeyError,OSError): pass
u=threading.Thread(target=udp_loop,daemon=True)
def connection(c,peer):
    with c:
        c.settimeout(3); data=b''
        try:
            while b'\n' not in data and len(data)<2048:
                chunk=c.recv(2048-len(data))
                if not chunk: return
                data+=chunk
            c.sendall(reply(data,peer,c.getsockname()[0],'tcp')+b'\n')
        except (ValueError,KeyError,OSError): pass
def primary_probe():
    service=os.environ['KUBERNETES_SERVICE_HOST']
    answers=sorted({a[4][0] for a in socket.getaddrinfo('kubernetes.default.svc.cluster.local',443)})
    if service not in answers: raise RuntimeError('Cluster DNS did not return API service IP')
    with socket.create_connection((service,443),5) as c: source=c.getsockname()[0]
    return dict(dns=answers,api_service=service,api_source=source)
result=primary_probe()
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((BIND,TCP)); s.listen(16)
u.start()
# Ensure the UDP thread bound successfully before declaring readiness.
time.sleep(.1)
if not u.is_alive(): raise RuntimeError('UDP listener failed')
fd=os.open('/tmp/acceptance-ready.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f: json.dump(result,f)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    while True:
        c,peer=s.accept(); pool.submit(connection,c,peer)
'''

PEER_PROBE = r'''
import json,socket,sys
host,port,nonce=sys.argv[1:]
with socket.create_connection((host,int(port)),5) as s:
    source=s.getsockname()[0]; s.sendall(json.dumps({'nonce':nonce}).encode()+b'\n')
    data=b''
    while b'\n' not in data:
        chunk=s.recv(2048)
        if not chunk: raise RuntimeError('short peer response')
        data+=chunk
    result=json.loads(data); result['client_source']=source; print(json.dumps(result))
'''


def parser():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--execute',action='store_true',help='Explicitly allow ephemeral cluster resources and probes')
    p.add_argument('--mode',choices=['flannel','ipvlan'],required=True)
    p.add_argument('--kubeconfig',required=True)
    p.add_argument('--node',required=True,help='Main test node; Floating IP must already be assigned here')
    peer=p.add_mutually_exclusive_group(required=True)
    peer.add_argument('--peer-node',help='Different node in the same cluster')
    peer.add_argument('--peer-kubeconfig',help='Peer cluster/config; requires existing Pod-IP routing')
    for name in ['floating-ip','gateway','parent-interface','python-image','tools-image','evidence-dir']:
        p.add_argument('--'+name,required=True)
    p.add_argument('--cni-version',choices=['1.0.0','1.1.0'],default='1.1.0')
    p.add_argument('--timeout',type=int,default=140,help='Work deadline in seconds (30..160); cleanup has separate 15s budget')
    p.add_argument('--udp-port',type=int,default=15682)
    p.add_argument('--tcp-port',type=int,default=15683)
    return p


def validate(a):
    for key in ['floating_ip','gateway']:
        value=ipaddress.ip_address(getattr(a,key))
        if value.version!=4 or value.is_unspecified or value.is_multicast:
            raise ValueError(key+' must be a unicast IPv4 address')
    if not 30<=a.timeout<=160: raise ValueError('timeout must be 30..160 seconds')
    if a.peer_node==a.node: raise ValueError('peer-node must differ from node')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',a.parent_interface): raise ValueError('invalid parent interface')
    for image in [a.python_image,a.tools_image]:
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}',image): raise ValueError('images must use immutable sha256 digests')
    if not all(1024<=port<=65535 for port in [a.udp_port,a.tcp_port]): raise ValueError('ports must be 1024..65535')


def nad(a,namespace):
    config={'cniVersion':a.cni_version,'name':'acceptance-ipvlan','plugins':[
        {'type':'ipvlan','master':a.parent_interface,'mode':'l2','ipam':{'type':'static',
         'addresses':[{'address':a.floating_ip+'/32'}],
         'routes':[{'dst':a.gateway+'/32','scope':253,'table':100},
                   {'dst':'0.0.0.0/0','gw':a.gateway,'table':100}]}},
        {'type':'sbr','table':100}]}
    return {'apiVersion':'k8s.cni.cncf.io/v1','kind':'NetworkAttachmentDefinition',
            'metadata':{'name':'acceptance-ipvlan','namespace':namespace},'spec':{'config':json.dumps(config)}}


def pod(a,namespace,name,node,secondary=False):
    annotations={}
    if secondary: annotations['k8s.v1.cni.cncf.io/networks']=json.dumps([{'name':'acceptance-ipvlan','interface':'net1'}])
    security={'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']},'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}}
    spec={'restartPolicy':'Never','activeDeadlineSeconds':180,'terminationGracePeriodSeconds':1,
          'automountServiceAccountToken':False,'dnsPolicy':'ClusterFirst',
          'containers':[{'name':'probe','image':a.python_image,'imagePullPolicy':'IfNotPresent',
           'command':['python3','-u','-c',POD_PROGRAM], 'env':[
            {'name':'BIND','value':a.floating_ip if secondary else '0.0.0.0'},
            {'name':'UDP_PORT','value':str(a.udp_port)},{'name':'TCP_PORT','value':str(a.tcp_port)}],
           'securityContext':security,'resources':{'requests':{'cpu':'10m','memory':'24Mi'},'limits':{'cpu':'200m','memory':'96Mi'}},
           'readinessProbe':{'exec':{'command':['/bin/sh','-ec','test -s /tmp/acceptance-ready.json']},'timeoutSeconds':3,'periodSeconds':2}},
          {'name':'tools','image':a.tools_image,'imagePullPolicy':'IfNotPresent',
           'command':['sleep','180'],'securityContext':security,
           'resources':{'requests':{'cpu':'1m','memory':'8Mi'},'limits':{'cpu':'100m','memory':'64Mi'}}}]}
    if node: spec['nodeName']=node
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':namespace,'annotations':annotations},'spec':spec}


class Run:
    def __init__(self,a):
        self.a=a; self.end=time.monotonic()+a.timeout; self.cleanup_end=None
        self.namespaces=[]; self.evidence={'mode':a.mode,'success':False}
    def kubectl(self,config,args,body=None,cleanup=False):
        deadline=self.cleanup_end if cleanup else self.end
        remaining=max(.1,deadline-time.monotonic())
        cmd=['kubectl','--kubeconfig',config,'--request-timeout='+str(max(1,int(remaining)))+'s']+args
        result=subprocess.run(cmd,input=None if body is None else json.dumps(body),text=True,capture_output=True,timeout=remaining)
        if result.returncode: raise RuntimeError('kubectl '+args[0]+': '+result.stderr.strip())
        return result.stdout
    def create(self,config,obj):
        return json.loads(self.kubectl(config,['create','-f','-','-o','json'],obj))
    def namespace(self,config):
        name='ipvlan-acceptance-'+uuid.uuid4().hex[:16]
        obj=self.create(config,{'apiVersion':'v1','kind':'Namespace','metadata':{'name':name,'labels':{'acceptance-run':name}}})
        self.namespaces.append((config,name,obj['metadata']['uid']))
        return name
    def exec(self,config,ns,podname,container,command):
        return self.kubectl(config,['-n',ns,'exec',podname,'-c',container,'--']+command)
    def ready(self,config,ns,name):
        self.kubectl(config,['-n',ns,'wait','--for=condition=Ready','pod/'+name,'--timeout='+str(max(1,int(self.end-time.monotonic())))+'s'])
        obj=json.loads(self.kubectl(config,['-n',ns,'get','pod',name,'-o','json']))
        return obj
    def cleanup(self):
        errors=[]; self.cleanup_end=time.monotonic()+15
        # Issue all UID-guarded deletions first, then confirm deletion within one budget.
        for config,name,uid in reversed(self.namespaces):
            try:
                self.kubectl(config,['delete','--raw','/api/v1/namespaces/'+name,'-f','-'],
                             {'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'propagationPolicy':'Background'},cleanup=True)
            except Exception as e: errors.append(str(e))
        for config,name,_ in reversed(self.namespaces):
            try:
                seconds=max(1,int(self.cleanup_end-time.monotonic()))
                self.kubectl(config,['wait','--for=delete','namespace/'+name,'--timeout='+str(seconds)+'s'],cleanup=True)
            except Exception as e: errors.append(str(e))
        self.evidence['cleanup_errors']=errors
        return errors


def require(condition,message):
    if not condition: raise RuntimeError(message)


def external(a,end):
    result=[]
    for method in ['udp','tcp']:
        for _ in range(3):
            nonce=secrets.token_hex(16)
            timeout=min(5,max(.1,end-time.monotonic()))
            kind=socket.SOCK_DGRAM if method=='udp' else socket.SOCK_STREAM
            port=a.udp_port if method=='udp' else a.tcp_port
            with socket.socket(socket.AF_INET,kind) as s:
                s.settimeout(timeout); s.bind(('0.0.0.0',0)); s.connect((a.floating_ip,port))
                s.sendall(json.dumps({'nonce':nonce}).encode()+b'\n')
                data=b''
                while b'\n' not in data:
                    chunk=s.recv(2048)
                    require(bool(chunk),'empty external response'); data+=chunk
                    if method=='udp': break
                    require(len(data)<8192,'oversize external response')
                reply=json.loads(data)
                require(reply['nonce']==nonce and reply['method']==method,'external nonce/method mismatch')
                require(reply['local_address']==a.floating_ip,'external response not served on Floating IP')
                result.append({'method':method,'response':reply,'reply_source':list(s.getpeername())})
    return result


def check_routes(routes,rules,fip,gateway,main):
    require(any(r.get('dst')=='default' and r.get('dev')=='eth0' for r in main),'primary eth0 default missing')
    require(any(r.get('dst')==gateway and r.get('dev')=='net1' and r.get('scope')=='link' for r in routes),'table100 gateway link route missing')
    require(any(r.get('dst')=='default' and r.get('dev')=='net1' and r.get('gateway')==gateway for r in routes),'table100 default missing')
    require(any(r.get('src') in [fip,fip+'/32'] and str(r.get('table'))=='100' for r in rules),'explicit source rule table100 missing')


def check_controller_route(route):
    require(any(item.get('dev')=='net1' and str(item.get('table'))=='100' for item in route),'Floating IP reply to controller does not use net1 table100')


def prepare_evidence(directory):
    evidence=Path(directory)
    evidence.mkdir(mode=0o700,parents=True,exist_ok=True)
    require(evidence.is_dir() and not evidence.is_symlink(),'evidence directory must not be a symlink')
    require(evidence.stat().st_mode & 0o077==0,'evidence directory must be private (mode 0700)')
    return evidence


def execute(a):
    # Reject unsafe evidence storage before any cluster resources are created.
    evidence=prepare_evidence(a.evidence_dir)
    r=Run(a)
    try:
        ns=r.namespace(a.kubeconfig)
        if a.mode=='ipvlan': r.create(a.kubeconfig,nad(a,ns))
        r.create(a.kubeconfig,pod(a,ns,'main',a.node,a.mode=='ipvlan'))
        peerconfig=a.peer_kubeconfig or a.kubeconfig
        peerns=r.namespace(peerconfig) if a.peer_kubeconfig else ns
        r.create(peerconfig,pod(a,peerns,'peer',a.peer_node))
        main=r.ready(a.kubeconfig,ns,'main'); peer=r.ready(peerconfig,peerns,'peer')
        mainip=main['status']['podIP']; peerip=peer['status']['podIP']
        require(mainip!=a.floating_ip,'primary Pod IP must differ from Floating IP')
        if not a.peer_kubeconfig: require(peer['spec']['nodeName']!=main['spec']['nodeName'],'peer is not on another node')
        r.evidence['pods']={'main_ip':mainip,'peer_ip':peerip,'main_node':main['spec']['nodeName'],'peer_node':peer['spec']['nodeName']}
        for cfg,n,name in [(a.kubeconfig,ns,'main'),(peerconfig,peerns,'peer')]:
            primary=json.loads(r.exec(cfg,n,name,'probe',['python3','-c',"print(open('/tmp/acceptance-ready.json').read())"]))
            expected=mainip if name=='main' else peerip
            require(primary['api_source']==expected,'API connection did not use primary Pod IP')
            r.evidence[name+'_primary']=primary
        nonce=secrets.token_hex(16)
        reply=json.loads(r.exec(a.kubeconfig,ns,'main','probe',['python3','-c',PEER_PROBE,peerip,str(a.tcp_port),nonce]))
        require(reply['nonce']==nonce and reply['observed_source'][0]==mainip and reply['client_source']==mainip,'cross-node primary path source mismatch')
        r.evidence['primary_peer']=reply
        if a.mode=='ipvlan':
            status=json.loads(main['metadata']['annotations'].get('k8s.v1.cni.cncf.io/network-status','[]'))
            require(any(s.get('interface')=='net1' and a.floating_ip in s.get('ips',[]) for s in status),'Multus net1 Floating IP status missing')
            query=lambda *cmd: json.loads(r.exec(a.kubeconfig,ns,'main','tools',['ip','-j']+list(cmd)))
            routes=query('route','show','table','100'); rules=query('rule','show'); mainroutes=query('route','show','table','main')
            addresses=query('address','show')
            r.evidence['routes']={'table100':routes,'rules':rules,'main':mainroutes,'addresses':addresses}
            check_routes(routes,rules,a.floating_ip,a.gateway,mainroutes)
            net1=next((link for link in addresses if link.get('ifname')=='net1'),None)
            require(net1 is not None,'net1 interface missing')
            ipv4=[item for item in net1.get('addr_info',[]) if item.get('family')=='inet']
            require(len(ipv4)==1 and ipv4[0].get('local')==a.floating_ip and ipv4[0].get('prefixlen')==32,'net1 must have only the Floating IP /32 IPv4 address')
            r.evidence['external']=external(a,r.end)
            r.evidence['controller_routes']=[]
            for exchange in r.evidence['external']:
                reply=exchange['response']
                if exchange['method']=='udp':
                    require(reply['ifindex']==net1['ifindex'],'UDP did not arrive through net1')
                source=reply['observed_source'][0]
                route=query('route','get',source,'from',a.floating_ip)
                check_controller_route(route)
                r.evidence['controller_routes'].append({'destination':source,'route':route})
        r.evidence['success']=True
    except Exception as e:
        r.evidence['error']=str(e)
        # Read-only diagnostics, still within the same work deadline.
        for cfg,n,_ in r.namespaces:
            try:
                r.evidence.setdefault('diagnostics',[]).append(r.kubectl(cfg,['-n',n,'get','pods,events','-o','json']))
                for name in ['main','peer']:
                    try: r.evidence.setdefault('logs',[]).append(r.kubectl(cfg,['-n',n,'logs',name,'-c','probe','--tail=40']))
                    except Exception: pass
            except Exception: pass
    finally:
        if r.cleanup(): r.evidence['success']=False
        destination=evidence/('acceptance-'+uuid.uuid4().hex+'.json')
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f: json.dump(r.evidence,f,indent=2)
        print(json.dumps({'success':r.evidence['success'],'evidence':str(destination)}))
    return 0 if r.evidence['success'] else 1


def main(argv=None):
    p=parser(); a=p.parse_args(argv)
    try: validate(a)
    except ValueError as e: p.error(str(e))
    if not a.execute:
        p.error('no cluster I/O performed: add --execute to authorize this test run')
    return execute(a)


if __name__=='__main__':
    sys.exit(main())
