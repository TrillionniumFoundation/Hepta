"""Installed HIA execution and pinned worker ownership with no authoring imports.

The original VM computes independent reports before the installed process runs.
The installed child poisons that VM and observes real native entrypoints. A
source-drift child must refuse its pinned bundle before any execution can occur.
These component controls do not qualify the whole toolchain.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'examples/hia_bootstrap/program_execution.hiaasm'
SELECTOR = 'HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST'


class ExecutionIntegrationSourceTests(unittest.TestCase):
    def test_installed_execution_has_source_release_worker_and_checker_custody(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_checker_identity import CORE_SOURCE_FILES, NATIVE_OWNERS
        from tools.hia_selfhost_contract import SOURCE_FILES
        from tools.hia_release import BOOTSTRAP_FILES
        self.assertIn(RESOURCE, NATIVE_SOURCE_FILES)
        self.assertIn('include ' + RESOURCE, (ROOT / 'MANIFEST.in').read_text().splitlines())
        self.assertIn(RESOURCE, SOURCE_FILES)
        self.assertIn(RESOURCE, BOOTSTRAP_FILES)
        self.assertEqual(HELPERS[SELECTOR], ('hia_program_execution_native', 'NativeProgramExecution'))
        self.assertEqual(NATIVE_OWNERS[SELECTOR], ('hia_program_execution_native', 'installed_program_execution'))
        self.assertIn('hia_program_execution_native.py', CORE_SOURCE_FILES)


CHILD = r'''
import sys
sys.path.insert(0, sys.argv[1])
import importlib.abc
import json
from pathlib import Path
from hashlib import sha256

class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('tools', 'tests'):
            raise AssertionError('installed execution imported authoring or test code')
sys.meta_path.insert(0, NoAuthoring())

from hepta import hia_program_runtime as runtime
from hepta.hia_program_execution_native import SOURCE, SELECTOR, installed_program_execution
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_checker_identity import checker_native_selection

def absent(*args, **kwargs):
    raise AssertionError('installed execution reached the retained Python VM')
runtime._Machine = absent
installed = Path(sys.argv[1]).resolve()
assert SOURCE.resolve().is_relative_to(installed), SOURCE
bundle, digest, mode = sys.argv[2:5]

if mode == 'drift':
    try:
        with native_helpers_scope(bundle, digest):
            raise AssertionError('changed installed source was admitted')
    except ValueError as exc:
        assert str(exc) == 'native helper source identity mismatch', str(exc)
        print(json.dumps({'refused': str(exc), 'installed_source': str(SOURCE)}, sort_keys=True))
else:
    cases = json.loads(Path(sys.argv[5]).read_bytes())
    with native_helpers_scope(bundle, digest) as binding:
        native = installed_program_execution(binding.selections[SELECTOR])
        assert native in binding.images.values()
        original_entry = native._entry
        entries = [0]
        def counted(*args):
            entries[0] += 1
            return original_entry(*args)
        native._entry = counted
        reports = [runtime.execute_program(case['program'], case['function'], case['arguments'])
                   for case in cases]
        assert entries[0] > 0
        identity = checker_native_selection()[SELECTOR]
        assert identity['images']['image']['image_sha256'] == native.image_sha256
        assert not any(name.split('.')[0] in ('tools', 'tests') for name in sys.modules)
        binding.check()
        print(json.dumps({'reports': reports, 'native_entries': entries[0],
            'installed_source': str(SOURCE), 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'helpers_sha256': binding.sha256, 'checker': identity}, sort_keys=True))
'''


class InstalledExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import through a local name: unittest module discovery must not run a
        # second copy of all the independent VM controls in this integration file.
        import tests.test_hia_program_execution_native as fixture_module
        if not (os.environ.get(fixture_module.COLD_REPORT)
                or os.environ.get(fixture_module.DEVELOPMENT_COMPILER)):
            raise unittest.SkipTest('an explicit cold report or retained development compiler is required')
        evidence = os.environ.get(fixture_module.EVIDENCE)
        cls.folder = Path(evidence) / 'installed' if evidence else Path(tempfile.mkdtemp(prefix='hia-execution-installed-'))
        cls.folder.mkdir(parents=True, exist_ok=not bool(evidence))
        cls.fixture = type('InstalledExecutionFixture', (fixture_module.ProgramExecutionNativeTests,), {})
        with patch.dict(os.environ, {fixture_module.EVIDENCE: str(cls.folder / 'native')}):
            cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.tearDownClass)
        cls.source = cls.folder / 'source'
        cls.source.mkdir()
        shutil.copytree(ROOT / 'hepta', cls.source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = cls.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        cls.resources = {name: (ROOT / name).read_bytes() for name in resources}

        def build(label, args):
            log = cls.folder / (label + '.log')
            with log.open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, args)], cwd=cls.source,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, stdout=output,
                    stderr=subprocess.STDOUT, timeout=180)
            if result.returncode:
                raise AssertionError(label + ': ' + log.read_text())
        build('sdist', ['setup.py', 'sdist', '--dist-dir', cls.folder / 'sdist'])
        archive, = (cls.folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as source_archive:
            prefix = source_archive.getnames()[0].split('/')[0] + '/'
            for name, raw in cls.resources.items():
                assert source_archive.extractfile(prefix + name).read() == raw, name
        build('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                        '--wheel-dir', cls.folder / 'wheels', archive])
        cls.wheel, = (cls.folder / 'wheels').glob('*.whl')
        cls.wheel_bytes = cls.wheel.read_bytes()
        with zipfile.ZipFile(cls.wheel) as wheel:
            assert wheel.read('hepta/_data/' + RESOURCE) == cls.resources[RESOURCE]
        cls.installed = cls.folder / 'installed'
        build('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', cls.installed, cls.wheel])
        cls.installed_source = cls.installed / 'hepta/_data' / RESOURCE
        assert cls.installed_source.read_bytes() == cls.resources[RESOURCE]

        from hepta.hia_native_helpers import SCHEMA, TARGET, ABI
        cls.bundle = cls.folder / 'worker-helpers.json'
        cls.bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
            'selector': SELECTOR, 'manifest_path': str(cls.fixture.manifest_path),
            'manifest_sha256': sha256(cls.fixture.manifest_bytes).hexdigest()}]}, sort_keys=True) + '\n')
        cls.bundle_bytes = cls.bundle.read_bytes()
        cls.bundle_sha = sha256(cls.bundle_bytes).hexdigest()
        from hepta import hia_program_runtime as runtime
        from tests.test_hia_program import resource_program
        cls.cases = [
            {'program': fixture_module.constant_program([('i64', -7), ('u64', (1 << 64) - 1), ('bool', True)]),
             'function': 'constant', 'arguments': []},
            {'program': resource_program(), 'function': 'owned', 'arguments': [2, 7]},
        ]
        with fixture_module.select(None):
            cls.expected = [runtime.execute_program(case['program'], case['function'], case['arguments'])
                            for case in cls.cases]
        cls.inputs = cls.folder / 'cases.json'
        cls.inputs.write_text(json.dumps(cls.cases, sort_keys=True) + '\n')
        (cls.folder / 'reference.json').write_text(json.dumps(cls.expected, sort_keys=True) + '\n')
        (cls.folder / 'installed-child.py').write_text(CHILD)
        cls.child_cwd = cls.folder / 'unrelated-working-directory'
        cls.child_cwd.mkdir()

    @classmethod
    def tearDownClass(cls):
        assert cls.wheel.read_bytes() == cls.wheel_bytes
        assert cls.bundle.read_bytes() == cls.bundle_bytes
        assert cls.installed_source.read_bytes() == cls.resources[RESOURCE]
        assert all((ROOT / name).read_bytes() == raw for name, raw in cls.resources.items())

    def child(self, mode):
        env = {key: value for key, value in os.environ.items()
               if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        command = [sys.executable, '-I', '-B', '-c', CHILD, str(self.installed), str(self.bundle),
                   self.bundle_sha, mode, str(self.inputs)]
        result = subprocess.run(command, cwd=self.child_cwd, env=env, capture_output=True, timeout=120)
        (self.folder / (mode + '.stdout')).write_bytes(result.stdout)
        (self.folder / (mode + '.stderr')).write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_wheel_executes_native_scalar_and_resource_programs_through_pinned_worker(self):
        value = self.child('execute')
        self.assertEqual(value['reports'], self.expected)
        self.assertGreater(value['native_entries'], 0)
        self.assertEqual(Path(value['installed_source']), self.installed_source)
        self.assertEqual(value['source_sha256'], sha256(self.resources[RESOURCE]).hexdigest())
        self.assertEqual(value['helpers_sha256'], self.bundle_sha)
        self.assertEqual(value['checker']['images']['image']['image_sha256'],
                         sha256(self.fixture.image_bytes).hexdigest())

    def test_changed_installed_hia_source_refuses_before_reference_or_native_execution(self):
        self.installed_source.write_bytes(self.resources[RESOURCE] + b'\n# controlled installed source drift\n')
        try:
            value = self.child('drift')
            self.assertEqual(value['refused'], 'native helper source identity mismatch')
        finally:
            self.installed_source.write_bytes(self.resources[RESOURCE])


if __name__ == '__main__':
    unittest.main()
