"""Offline acceptance-harness tests. No kubectl or cluster access is performed."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('ipvlan_acceptance',Path(__file__).with_name('ipvlan_acceptance.py'))
h=importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def arguments(extra=()):
    return ['--mode','ipvlan','--kubeconfig','example-config','--node','test-node',
            '--peer-node','peer-node','--floating-ip','192.0.2.10','--gateway','192.0.2.1',
            '--parent-interface','eth0','--python-image','python@example'.replace('@example','@sha256:'+'a'*64),
            '--tools-image','tools@sha256:'+'b'*64,'--evidence-dir','private-evidence']+list(extra)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.a=h.parser().parse_args(arguments())

    def test_help_does_not_invoke_cluster(self):
        with patch.object(h.subprocess,'run',side_effect=AssertionError('cluster I/O')),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as error: h.main(['--help'])
        self.assertEqual(error.exception.code,0)

    def test_execute_guard_does_not_invoke_cluster(self):
        with patch.object(h.subprocess,'run',side_effect=AssertionError('cluster I/O')),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error: h.main(arguments())
        self.assertEqual(error.exception.code,2)

    def test_requires_peer_selector(self):
        args=arguments(); index=args.index('--peer-node'); del args[index:index+2]
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit): h.parser().parse_args(args)

    def test_static_routes_and_explicit_sbr(self):
        config=json.loads(h.nad(self.a,'test')['spec']['config'])
        ipvlan,sbr=config['plugins']
        self.assertEqual(ipvlan['mode'],'l2')
        self.assertEqual(ipvlan['ipam']['addresses'],[{'address':'192.0.2.10/32'}])
        self.assertEqual(ipvlan['ipam']['routes'],[
            {'dst':'192.0.2.1/32','scope':253,'table':100},
            {'dst':'0.0.0.0/0','gw':'192.0.2.1','table':100}])
        self.assertEqual(sbr,{'type':'sbr','table':100})

    def test_pod_privileges_and_lifetime(self):
        obj=h.pod(self.a,'test','main','test-node',True)
        spec=obj['spec']
        self.assertEqual(spec['activeDeadlineSeconds'],180)
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertNotIn('hostNetwork',spec)
        self.assertEqual(spec['dnsPolicy'],'ClusterFirst')
        self.assertEqual(spec['containers'][0]['readinessProbe'],{
            'exec':{'command':['/bin/sh','-ec','test -s /tmp/acceptance-ready.json']},
            'timeoutSeconds':3,'periodSeconds':2})
        for container in spec['containers']:
            self.assertEqual(container['securityContext']['capabilities'],{'drop':['ALL']})
            self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
        networks=json.loads(obj['metadata']['annotations']['k8s.v1.cni.cncf.io/networks'])
        self.assertEqual(networks,[{'name':'acceptance-ipvlan','interface':'net1'}])

    def test_flannel_pod_is_unannotated_and_wildcard(self):
        obj=h.pod(self.a,'test','main','test-node',False)
        self.assertEqual(obj['metadata']['annotations'],{})
        self.assertEqual(obj['spec']['containers'][0]['env'][0]['value'],'0.0.0.0')

    def test_digest_and_deadline_validation(self):
        h.validate(self.a)
        self.a.python_image='python:latest'
        with self.assertRaises(ValueError): h.validate(self.a)
        self.a=h.parser().parse_args(arguments(['--timeout','161']))
        with self.assertRaises(ValueError): h.validate(self.a)

    def test_peer_must_differ(self):
        self.a.peer_node=self.a.node
        with self.assertRaises(ValueError): h.validate(self.a)

    def test_route_acceptance(self):
        routes=[{'dst':'192.0.2.1','scope':'link','dev':'net1'},
                {'dst':'default','gateway':'192.0.2.1','dev':'net1'}]
        rules=[{'src':'192.0.2.10','table':100}]
        primary=[{'dst':'default','dev':'eth0'}]
        for table in [100,'100']:
            with self.subTest(table=table):
                rules[0]['table']=table
                h.check_routes(routes,rules,'192.0.2.10','192.0.2.1',primary)
        with self.assertRaises(RuntimeError): h.check_routes(routes,[],'192.0.2.10','192.0.2.1',primary)
        with self.assertRaises(RuntimeError): h.check_routes(routes,rules,'192.0.2.10','192.0.2.1',[])

    def test_controller_route_table_string_and_integer(self):
        for table in [100,'100']:
            with self.subTest(table=table):
                h.check_controller_route([{'dev':'net1','table':table}])
        for route in [[],[{'dev':'net1','table':101}],[{'dev':'net1','table':'main'}],
                      [{'dev':'eth0','table':'100'}],[{'dev':'net1'}]]:
            with self.subTest(route=route),self.assertRaises(RuntimeError):
                h.check_controller_route(route)

    def test_namespace_cleanup_uses_uid_precondition(self):
        run=h.Run(self.a)
        run.namespaces=[('example-config','test-namespace','test-uid')]
        with patch.object(run,'kubectl',return_value='{}') as call:
            self.assertEqual(run.cleanup(),[])
        args,kwargs=call.call_args_list[0]
        self.assertEqual(args[1],['delete','--raw','/api/v1/namespaces/test-namespace','-f','-'])
        self.assertEqual(args[2]['preconditions'],{'uid':'test-uid'})
        self.assertTrue(kwargs['cleanup'])

    def test_cleanup_failure_is_reported(self):
        run=h.Run(self.a); run.namespaces=[('example-config','test-namespace','test-uid')]
        with patch.object(run,'kubectl',side_effect=RuntimeError('cleanup failed')):
            self.assertEqual(run.cleanup(),['cleanup failed','cleanup failed'])

    def test_private_evidence_guard(self):
        with tempfile.TemporaryDirectory() as parent:
            path=Path(parent)/'evidence'
            self.assertEqual(h.prepare_evidence(path),path)
            self.assertEqual(path.stat().st_mode & 0o777,0o700)
            path.chmod(0o755)
            with self.assertRaises(RuntimeError): h.prepare_evidence(path)

    def test_embedded_programs_compile(self):
        compile(h.POD_PROGRAM,'pod-probe','exec')
        compile(h.PEER_PROBE,'peer-probe','exec')


if __name__=='__main__':
    unittest.main()
