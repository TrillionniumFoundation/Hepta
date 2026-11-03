from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from tools.summarize_hia_reduction_tails import summarize


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        request = dict(workload='linear', backend='hia_reduction', group='control',
                       n=0, seed=7, calls=1, samples=1, warmup=0)
        registration = json.dumps({'requests': [request]}).encode()
        (self.path / 'REGISTRATION.json').write_bytes(registration)
        response = {k: request[k] for k in ('n', 'seed', 'calls', 'samples', 'warmup')}
        response.update(wall_resolution_ns=1, cpu_resolution_ns=1,
                        observations=[dict(wall_ns=12000, cpu_envelope_ns=100, checksum=0)])
        self.result = dict(status='completed', inputs_unchanged=True, driver_unchanged=True,
            registration_sha256=sha256(registration).hexdigest(), observations=[dict(
                request=request, returncode=0, response=response, stdout=json.dumps(response))])

    def write(self, result):
        (self.path / 'RESULT.json').write_text(json.dumps(result))

    def test_summarizes_without_qualification(self):
        self.write(self.result)
        result = summarize(self.path)
        self.assertEqual((result['requests'], result['samples']), (1, 1))
        self.assertEqual(result['arms']['hia_reduction']['wall_minus_cpu_over_10us_count'], 1)
        self.assertFalse(result['performance_qualified'])
        self.assertFalse(result['historical_gates_changed'])

    def test_rejects_incomplete_changed_or_inconsistent_campaign(self):
        mutations = [lambda r: r.update(status='failed'), lambda r: r.update(inputs_unchanged=False),
            lambda r: r.update(driver_unchanged=False), lambda r: r.update(registration_sha256='0'*64),
            lambda r: r['observations'].clear(), lambda r: r['observations'][0].update(returncode=1),
            lambda r: r['observations'][0]['request'].update(n=1),
            lambda r: r['observations'][0]['response']['observations'][0].update(wall_ns=1)]
        for mutation in mutations:
            result = deepcopy(self.result); mutation(result); self.write(result)
            with self.assertRaises(ValueError): summarize(self.path)
