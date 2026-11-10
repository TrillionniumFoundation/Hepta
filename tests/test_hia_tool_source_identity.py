"""Fresh qualification and worker receipts bind installed nested HIA sources."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_agent_contract import DISCOVERY_FILES
from tools.qualify_hia_macro_multistep import SOURCES


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = 'hepta/native/effect_closure.hiaasm'

PROBE = r'''
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_macro_policy import digest
from tools import qualify_hia_direct_native as direct
from tools import qualify_hia_candidate as candidate
from tools import qualify_hia_macro_campaign as campaign
from tools import qualify_hia_macro_multistep as multistep
from tools import validate

evidence = campaign.Evidence(Path(sys.argv[1]))
worker = campaign._worker_sources(evidence)
result = {
    'direct': direct.source_identity(),
    'candidate': candidate.sources(),
    'validation': validate.compiler_identity(),
    'macro': multistep.source_identity(),
    'worker': worker,
    'worker_sha256': digest(worker),
    'installed_worker_sha256': installation_manifest()['worker_sha256'],
}
if sys.argv[2] == 'qualify':
    class Stable(unittest.TestCase):
        def runTest(self):
            self.assertTrue(Path('hepta/native/effect_closure.hiaasm').is_file())

    class ChangeNativeAuthority(unittest.TestCase):
        def runTest(self):
            with Path('hepta/native/effect_closure.hiaasm').open('ab') as stream:
                stream.write(b'\n# fresh qualification identity mutation\n')

    # Execute the real qualification/report path with a finite sentinel suite.
    # The second suite passes its assertion but must fail source stability.
    with redirect_stdout(io.StringIO()):
        direct.SUITES = ('__main__.Stable',)
        result['stable_qualification'] = direct.qualify()
        direct.SUITES = ('__main__.ChangeNativeAuthority',)
        result['changed_qualification'] = direct.qualify()
print(json.dumps(result, sort_keys=True))
'''


class ToolSourceIdentityTests(unittest.TestCase):
    def test_fresh_manifests_and_qualification_detect_nested_HIA_authority_change(self):
        with tempfile.TemporaryDirectory(prefix='hia-tool-source-identity-') as temporary:
            base = Path(temporary)
            checkout = base / 'source'
            checkout.mkdir()
            # Copy the actual installed authority and tool implementations;
            # keep this mutation entirely outside the working repository.
            for directory in ('hepta', 'tools'):
                for path in (ROOT / directory).rglob('*'):
                    if path.suffix not in {'.py', '.hiaasm'}:
                        continue
                    destination = checkout / path.relative_to(ROOT)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
            selected = set(SOURCES) | {'docs/' + name for name in DISCOVERY_FILES} | {
                'docs/HIA_OPCODE_REFERENCE.md', 'docs/hia-opcode-catalog.v8.json',
                'docs/HIA_DIRECT_NATIVE.md', '.github/workflows/hia-direct-native.yml',
                '.github/workflows/hia-unified-candidate.yml'}
            for name in selected:
                destination = checkout / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            nested_python = checkout / 'hepta/native/nested/identity_fixture.py'
            nested_python.parent.mkdir(parents=True)
            nested_python.write_bytes(b'identity_fixture = True\n')
            original = (checkout / NATIVE_SOURCE).read_bytes()

            def fresh(label, mode):
                result = subprocess.run([sys.executable, '-B', '-E', '-s', '-c', PROBE,
                    str(base / label), mode], cwd=checkout,
                    env=dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1'),
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            before = fresh('before', 'qualify')
            changed = (checkout / NATIVE_SOURCE).read_bytes()
            self.assertNotEqual(changed, original)
            after = fresh('after', 'inventory')
            for label in ('direct', 'candidate', 'validation', 'macro', 'worker'):
                with self.subTest(manifest=label):
                    old = before[label]['files'] if label in {'direct', 'candidate'} else before[label]
                    new = after[label]['files'] if label in {'direct', 'candidate'} else after[label]
                    self.assertEqual(old[NATIVE_SOURCE], sha256(original).hexdigest())
                    self.assertEqual(new[NATIVE_SOURCE], sha256(changed).hexdigest())
                    self.assertIn('hepta/native/nested/identity_fixture.py', old)
                    self.assertNotEqual(old, new)
            for row in (before, after):
                self.assertEqual(row['worker_sha256'], row['installed_worker_sha256'])
            self.assertNotEqual(before['worker_sha256'], after['worker_sha256'])
            stable = before['stable_qualification']
            mutated = before['changed_qualification']
            self.assertTrue(stable['ok'])
            self.assertTrue(stable['source_unchanged'])
            self.assertEqual(mutated['tests_run'], 1)
            self.assertTrue(mutated['inventory_complete'])
            self.assertEqual(mutated['failures'], [])
            self.assertEqual(mutated['errors'], [])
            self.assertFalse(mutated['source_unchanged'])
            self.assertFalse(mutated['ok'])
            self.assertFalse(mutated['claims']['finite_same_source_test_run'])
            self.assertEqual(mutated['source']['files'][NATIVE_SOURCE], sha256(original).hexdigest())
            original_evidence = base / 'before/objects' / sha256(original).hexdigest()
            changed_evidence = base / 'after/objects' / sha256(changed).hexdigest()
            self.assertEqual(original_evidence.read_bytes(), original)
            self.assertEqual(changed_evidence.read_bytes(), changed)


if __name__ == '__main__':
    unittest.main()
