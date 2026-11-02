"""Offline measurement tests: no Docker or Kubernetes operations."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('kubernetes_acceptance.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def scenario(name, offset=0):
    def ns(seconds):
        return round((seconds + offset) * 1_000_000_000)
    events = [
        {'kind': 'ping', 'ok': True, 'continuous': True, 'started_ns': ns(.8), 'mono_ns': ns(.81)},
        {'kind': 'mark', 'name': name + ':before', 'mono_ns': ns(1)},
        {'kind': 'ping', 'ok': False, 'continuous': True, 'started_ns': ns(1.2), 'mono_ns': ns(1.8)},
        {'kind': 'mark', 'name': name + ':returned', 'mono_ns': ns(1.9)},
    ]
    for i in range(5):
        t = 2 + i * .2
        events.append({'kind': 'ping', 'ok': True, 'continuous': True, 'started_ns': ns(t), 'mono_ns': ns(t + .01)})
    events.append({'kind': 'mark', 'name': name + ':recovered', 'mono_ns': ns(3)})
    return events


class MeasurementTests(unittest.TestCase):
    def harness(self, passed=False):
        h = object.__new__(acceptance.Harness)
        h.result = {'passed': passed}
        return h

    def test_first_reply_and_fifth_confirmation_are_distinct(self):
        h = self.harness()
        h.summarize(scenario('move-cp2-to-cp3'))
        s = h.result['recovery'][0]
        self.assertAlmostEqual(s['prechange_to_confirmed_recovery_seconds'], 1.81)
        self.assertAlmostEqual(s['maximum_observed_success_gap_seconds'], 1.2)
        self.assertAlmostEqual(s['last_before_loss_to_sustained_recovery_seconds'], 1.2)
        self.assertEqual(s['confirmed_fifth_success_ns'], 2_810_000_000)
        self.assertEqual(s['failed_probes'], 1)
        self.assertTrue(s['observed_loss'])

    def test_release_evidence_requires_all_scenarios(self):
        h = self.harness(passed=True)
        with self.assertRaisesRegex(AssertionError, 'incomplete latency'):
            h.summarize(scenario('move-cp2-to-cp3'))

    def test_complete_evidence_is_marked(self):
        h = self.harness(passed=True)
        names = ['move-cp2-to-cp3', 'delete-router-pod', 'scale-zero-one', 'service-new-cluster-ip']
        events = sum((scenario(name, i * 10) for i, name in enumerate(names)), [])
        h.summarize(events)
        self.assertTrue(h.result['latency_evidence_complete'])
        self.assertEqual(len(h.result['recovery']), 4)

    def test_additional_acl_timing_does_not_invalidate_complete_evidence(self):
        h = self.harness(passed=True)
        names = ['acl-revocation', 'move-cp2-to-cp3', 'delete-router-pod', 'scale-zero-one', 'service-new-cluster-ip']
        events = sum((scenario(name, i * 10) for i, name in enumerate(names)), [])
        h.summarize(events)
        self.assertTrue(h.result['latency_evidence_complete'])
        self.assertEqual(len(h.result['recovery']), 5)

    def test_embedded_probe_compiles(self):
        compile(acceptance.PROBE, 'probe.py', 'exec')


if __name__ == '__main__':
    unittest.main()
