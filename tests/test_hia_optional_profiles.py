"""Explicit optional packaging and resource-origin controls; no native execution."""
from __future__ import annotations

import ast
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROLES = ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES',
    'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES',
    'EMITTER_BUILD_FILES', 'BYTE_WRAPPER_BUILD_FILES', 'MACHINE_OBJECT_BUILD_FILES',
    'EXECUTION_OBSERVATION_BUILD_FILES', 'CONTINUATION_BUILD_FILES', 'ENTRY_BUILD_FILES')


def literals(path, names):
    tree = ast.parse(Path(path).read_text())
    result = {}
    for name in names:
        nodes = [node for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if len(nodes) != 1:
            raise AssertionError('one explicit declaration required: ' + name)
        result[name] = ast.literal_eval(nodes[0].value)
    return result


def default_resources():
    values = literals(ROOT / 'hepta/hia_agent_contract.py', DEFAULT_ROLES)
    return tuple('docs/' + name for name in values['DISCOVERY_FILES']) + tuple(
        name for role in DEFAULT_ROLES[1:] for name in values[role])


def copy_resources(destination, names):
    for name in names:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)


@contextmanager
def setup_functions():
    # Run the real static build hook with setup registration intercepted. Any
    # attempt to import product code during declaration is a concrete failure.
    import setuptools
    class NoProduct:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == 'hepta' or fullname.startswith('hepta.'):
                raise AssertionError('setup imported product code: ' + fullname)
            return None
    finder = NoProduct()
    before = {name for name in sys.modules if name == 'hepta' or name.startswith('hepta.')}
    sys.meta_path.insert(0, finder)
    try:
        with patch.object(setuptools, 'setup') as registered:
            values = runpy.run_path(str(ROOT / 'setup.py'))
        registered.assert_called_once()
        if {name for name in sys.modules if name == 'hepta' or name.startswith('hepta.')} != before:
            raise AssertionError('setup loaded product modules')
        yield values
    finally:
        sys.meta_path.remove(finder)


class OptionalProfileSourceTests(unittest.TestCase):
    def test_default_twelve_roles_and_210_resources_are_independent_of_optional_profiles(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, OPTIONAL_RESOURCE_PINS
        values = literals(ROOT / 'hepta/hia_agent_contract.py', DEFAULT_ROLES)
        tree = ast.parse((ROOT / 'hepta/hia_agent_contract.py').read_text())
        declared = [target.id for node in tree.body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)
                    and (target.id.endswith('_BUILD_FILES') or target.id in DEFAULT_ROLES[:2])]
        self.assertEqual(set(declared), set(DEFAULT_ROLES))
        self.assertEqual(len(declared), 12)
        self.assertEqual(len(values['ENTRY_BUILD_FILES']), 19)
        self.assertEqual(len(values['NATIVE_SOURCE_FILES']), 92)
        original = default_resources()
        self.assertEqual(len(original), len(set(original)))
        self.assertEqual(len(original), 210)
        optional = tuple(dict.fromkeys(name for names in OPTIONAL_PROFILE_FILES.values() for name in names))
        self.assertEqual(len(optional), 8)
        self.assertEqual(set(optional), set(OPTIONAL_RESOURCE_PINS))
        self.assertTrue(set(original).isdisjoint(optional))
        manifest = (ROOT / 'MANIFEST.in').read_text().splitlines()
        for name in optional:
            self.assertIn('include ' + name, manifest)

    def test_packager_is_static_and_requires_an_exact_explicit_profile_selection(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
        tree = ast.parse((ROOT / 'setup.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name != 'hepta' and not alias.name.startswith('hepta.')
                                    for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or '').startswith('hepta'))
        with setup_functions() as values:
            self.assertEqual(values['agent_resources'](), default_resources())
            selected = values['optional_profile_resources']
            self.assertEqual(selected(''), ())
            for profile, names in OPTIONAL_PROFILE_FILES.items():
                self.assertEqual(selected(profile), names)
            union = tuple(dict.fromkeys(name for names in OPTIONAL_PROFILE_FILES.values() for name in names))
            self.assertEqual(selected(','.join(OPTIONAL_PROFILE_FILES)), union)
            for bad in (None, True, 'unknown', ' ' + next(iter(OPTIONAL_PROFILE_FILES)),
                        next(iter(OPTIONAL_PROFILE_FILES)) + ',',
                        ','.join([next(iter(OPTIONAL_PROFILE_FILES))] * 2)):
                with self.subTest(selection=bad), self.assertRaises(ValueError):
                    selected(bad)

    def test_every_optional_asset_is_fresh_and_missing_drift_and_symlinks_refuse(self):
        from hepta.hia_optional_profiles import (
            OPTIONAL_PROFILE_FILES, OPTIONAL_RESOURCE_PINS, fresh_profile_identity, guard_profile_identity)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            copy_resources(root, OPTIONAL_RESOURCE_PINS)
            records = {p: fresh_profile_identity(p, resource_root=root) for p in OPTIONAL_PROFILE_FILES}
            for name in OPTIONAL_RESOURCE_PINS:
                profile = next(p for p, names in OPTIONAL_PROFILE_FILES.items() if name in names)
                target = root / name
                raw = target.read_bytes()
                for defect in ('missing', 'same-length-change', 'symlink', 'fifo'):
                    with self.subTest(name=name, defect=defect):
                        target.unlink()
                        if defect == 'same-length-change':
                            target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                        elif defect == 'symlink':
                            target.symlink_to(ROOT / name)
                        elif defect == 'fifo':
                            os.mkfifo(target)
                        with self.assertRaises((OSError, ValueError)):
                            guard_profile_identity(profile, records[profile], resource_root=root)
                        if target.exists() or target.is_symlink():
                            target.unlink()
                        target.write_bytes(raw)
                        self.assertEqual(fresh_profile_identity(profile, resource_root=root), records[profile])

    def test_installed_target_must_match_the_captured_pin_even_if_source_changes_to_match_it(self):
        from setuptools import Distribution
        from setuptools.command.build_py import build_py
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
        profile = 'hepta.hia.cli-verified-report-bundle.v2'
        name, = OPTIONAL_PROFILE_FILES[profile]
        with tempfile.TemporaryDirectory() as folder, setup_functions() as values:
            root = Path(folder) / 'source'
            root.mkdir()
            copy_resources(root, (*default_resources(), name, 'hepta/hia_agent_contract.py',
                                  'hepta/hia_optional_profiles.py'))
            globals_ = values['_optional_profile_plan'].__globals__
            previous_root = globals_['ROOT']
            actual_plan = globals_['_optional_profile_plan']
            command = values['AgentResourceBuild'](Distribution({'packages': []}))
            command.build_lib = str(Path(folder) / 'installed')
            source = root / name
            target = Path(command.build_lib) / 'hepta/_data' / name
            raw = source.read_bytes()
            calls = []
            def simultaneous_drift(selection):
                result = actual_plan(selection)
                calls.append(selection)
                if len(calls) == 2:
                    changed = bytes([raw[0] ^ 1]) + raw[1:]
                    source.write_bytes(changed)
                    target.write_bytes(changed)
                return result
            try:
                globals_['ROOT'] = root
                globals_['_optional_profile_plan'] = simultaneous_drift
                with patch.object(build_py, 'run'), patch.dict(os.environ, {'HEPTA_HIA_BUILD_PROFILES': profile}):
                    with self.assertRaises(ValueError):
                        command.run()
                self.assertEqual(len(calls), 2)
                self.assertEqual(source.read_bytes(), target.read_bytes())
                self.assertNotEqual(source.read_bytes(), raw)
            finally:
                globals_['ROOT'] = previous_root
                globals_['_optional_profile_plan'] = actual_plan

    def test_explicit_missing_origin_does_not_fall_back_and_paths_are_closed(self):
        from hepta.hia_optional_profiles import (
            OPTIONAL_PROFILE_FILES, fresh_profile_identity, optional_profile_resource_path)
        profile, names = next(iter(OPTIONAL_PROFILE_FILES.items()))
        self.assertTrue(optional_profile_resource_path(profile, names[0]).is_file())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises((OSError, ValueError)):
                fresh_profile_identity(profile, resource_root=root)
            for name in ('../' + names[0], '/tmp/outside', 'examples/hia_bootstrap/unregistered.hepta', True):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    optional_profile_resource_path(profile, name, resource_root=root)
            link = root / 'link'
            link.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaises(ValueError):
                fresh_profile_identity(profile, resource_root=link)
        for profile in ('', 'unknown', None, True):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                fresh_profile_identity(profile)

    def test_bundle_source_origin_and_fixed_host_compatibility_are_independently_checked(self):
        from hepta import hia_cli_verified_report_native as owner
        from hepta.hia_optional_profiles import fresh_profile_identity
        source = 'examples/hia_bootstrap/verified_report.hepta'
        with tempfile.TemporaryDirectory() as folder:
            component = Path(folder)
            resources = component / 'profile-resources'
            copy_resources(resources, (source,))
            value = {'schema': owner.RESOURCE_SCHEMA, 'profile': owner.RESOURCE_PROFILE,
                'source_root': 'profile-resources', 'source_relative': source,
                'source_sha256': sha256((ROOT / source).read_bytes()).hexdigest(),
                'identity': fresh_profile_identity(owner.RESOURCE_PROFILE, resource_root=resources),
                'host_sources': owner.host_compatibility_sources()}
            self.assertEqual(owner._resource_binding(component, value)[0], resources)
            for key, replacement in (('source_root', '../outside'), ('source_root', '/tmp/outside'),
                    ('source_root', 'missing'), ('source_relative', '../verified_report.hepta'),
                    ('source_sha256', '0' * 64), ('identity', {}), ('host_sources', {})):
                bad = {**value, key: replacement}
                with self.subTest(key=key, replacement=replacement), self.assertRaises((OSError, ValueError)):
                    owner._resource_binding(component, bad)
            # Rewriting both a host file and its manifest hash does not override
            # the separately frozen source-to-host compatibility anchor.
            host_root = component / 'installed-host'
            copy_resources(host_root, owner.HOST_SOURCE_FILES)
            changed = host_root / 'hepta/hia_verified_report_ports.py'
            changed.write_bytes(changed.read_bytes() + b'\n# changed installed ports\n')
            with patch.object(owner, '__file__', str(host_root / 'hepta/hia_cli_verified_report_native.py')):
                self_consistent = {**value, 'host_sources': owner.host_compatibility_sources()}
                with self.assertRaises(ValueError):
                    owner._resource_binding(component, self_consistent)

    def test_bundle_resource_changes_and_root_symlinks_never_use_package_sources(self):
        from hepta import hia_cli_verified_report_native as owner
        from hepta.hia_optional_profiles import fresh_profile_identity
        source = 'examples/hia_bootstrap/verified_report.hepta'
        with tempfile.TemporaryDirectory() as folder:
            component = Path(folder)
            resources = component / 'resources'
            copy_resources(resources, (source,))
            value = {'schema': owner.RESOURCE_SCHEMA, 'profile': owner.RESOURCE_PROFILE,
                'source_root': 'resources', 'source_relative': source,
                'source_sha256': sha256((ROOT / source).read_bytes()).hexdigest(),
                'identity': fresh_profile_identity(owner.RESOURCE_PROFILE, resource_root=resources),
                'host_sources': owner.host_compatibility_sources()}
            target = resources / source
            original = target.read_bytes()
            target.write_bytes(original + b'changed')
            with self.assertRaises(ValueError):
                owner._resource_binding(component, value)
            target.unlink()
            with self.assertRaises((OSError, ValueError)):
                owner._resource_binding(component, value)
            target.write_bytes(original)
            link = component / 'link'
            link.symlink_to(resources, target_is_directory=True)
            with self.assertRaises(ValueError):
                owner._resource_binding(component, {**value, 'source_root': 'link'})

    def test_profile_registry_and_report_hosts_remain_in_current_source_closure(self):
        from tools.hia_selfhost_contract import SOURCE_FILES
        from tools.hia_cli_verified_report_custody import OWNER_FILES, owner_sources
        from hepta.hia_cli_verified_report_native import HOST_SOURCE_FILES
        self.assertIn('hepta/hia_optional_profiles.py', SOURCE_FILES)
        self.assertIn('tests/test_hia_optional_profiles.py', SOURCE_FILES)
        self.assertTrue(set(HOST_SOURCE_FILES).issubset(OWNER_FILES))
        self.assertTrue(set(OWNER_FILES).issubset(SOURCE_FILES))
        self.assertEqual(set(owner_sources()), set(OWNER_FILES))

    def test_real_sdist_default_and_selected_wheels_install_exact_resource_origins(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, OPTIONAL_RESOURCE_PINS
        from hepta.hia_cli_verified_report_native import RESOURCE_PROFILE
        with tempfile.TemporaryDirectory(prefix='hia-optional-wheel-') as folder:
            case = Path(folder)
            source = case / 'source'
            source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            names = (*default_resources(), *OPTIONAL_RESOURCE_PINS, 'setup.py', 'pyproject.toml', 'MANIFEST.in')
            copy_resources(source, names)
            environment = {key: val for key, val in os.environ.items()
                           if not key.startswith('HEPTA_') and key != 'PYTHONPATH'}
            environment['PYTHONDONTWRITEBYTECODE'] = '1'
            records = []
            def command(arguments, label, env=environment):
                process = subprocess.run(arguments, cwd=source, env=env, capture_output=True, timeout=120)
                record = {'label': label, 'arguments': arguments, 'returncode': process.returncode,
                          'stdout': process.stdout.decode('utf-8', 'backslashreplace'),
                          'stderr': process.stderr.decode('utf-8', 'backslashreplace')}
                records.append(record)
                print('OPTIONAL_PROFILE_PACKAGING_OBSERVATION ' + json.dumps(record, sort_keys=True), flush=True)
                self.assertEqual(process.returncode, 0, record)
            dist = case / 'sdist'
            command([sys.executable, '-B', 'setup.py', 'sdist', '--dist-dir', str(dist)], 'actual-sdist')
            archive, = dist.glob('*.tar.gz')
            with tarfile.open(archive, 'r:gz') as stream:
                members = stream.getmembers()
                prefix = PurePosixPath(members[0].name).parts[0]
                for name in OPTIONAL_RESOURCE_PINS:
                    self.assertEqual(stream.extractfile(prefix + '/' + name).read(), (ROOT / name).read_bytes())
            wheels = {}
            for label, selected in (('default', ''), ('selected', ','.join(OPTIONAL_PROFILE_FILES))):
                output = case / (label + '-wheels')
                output.mkdir()
                env = {**environment, 'HEPTA_HIA_BUILD_PROFILES': selected}
                command([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps',
                         '--no-index', '--no-build-isolation', '--wheel-dir', str(output), str(archive)],
                        label + '-wheel', env)
                wheel, = output.glob('*.whl')
                wheels[label] = wheel
                with zipfile.ZipFile(wheel) as stream:
                    resources = {name.removeprefix('hepta/_data/') for name in stream.namelist()
                                 if name.startswith('hepta/_data/') and not name.endswith('/')}
                    expected = set(default_resources()) | (set(OPTIONAL_RESOURCE_PINS) if selected else set())
                    self.assertEqual(resources, expected)
                    for name in expected:
                        self.assertEqual(stream.read('hepta/_data/' + name), (ROOT / name).read_bytes())
            installed = case / 'installed'
            command([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
                     '--target', str(installed), str(wheels['selected'])], 'selected-install')
            probe = r'''
import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES,OPTIONAL_RESOURCE_PINS,fresh_profile_identity,optional_profile_resource_path
from hepta.hia_agent_contract import NATIVE_SOURCE_FILES,ENTRY_BUILD_FILES
assert len(NATIVE_SOURCE_FILES)==92 and len(ENTRY_BUILD_FILES)==19
installed=pathlib.Path(sys.argv[1]); observed=[]
for profile,names in OPTIONAL_PROFILE_FILES.items():
 original=fresh_profile_identity(profile)
 for name in names:
  path=optional_profile_resource_path(profile,name)
  assert path==installed/'hepta/_data'/name
  raw=path.read_bytes()
  path.write_bytes(bytes([raw[0]^1])+raw[1:])
  try:fresh_profile_identity(profile)
  except (OSError,ValueError):pass
  else:raise AssertionError('changed optional installed source accepted')
  path.unlink()
  try:fresh_profile_identity(profile)
  except (OSError,ValueError):pass
  else:raise AssertionError('missing optional installed source fell back')
  path.write_bytes(raw)
  assert fresh_profile_identity(profile)==original
  observed.append(name)
assert set(observed)==set(OPTIONAL_RESOURCE_PINS)
print(json.dumps({'status':'PASS','unique_optional_sources':len(set(observed)),'default_entry':len(ENTRY_BUILD_FILES),'default_native':len(NATIVE_SOURCE_FILES),'native_executed':False},sort_keys=True))
'''
            command([sys.executable, '-I', '-S', '-B', '-c', probe, str(installed)], 'isolated-installed-profiles')
            self.assertIn('"unique_optional_sources": 8', records[-1]['stdout'])


    def test_z_sdist_support_is_the_explicit_optional_profile_union(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, OPTIONAL_RESOURCE_PINS
        support = literals(ROOT / 'tests/test_hia_agent_installed_resources.py',
                           ('SDIST_SUPPORT_FILES',))['SDIST_SUPPORT_FILES']
        retained = ('tests/fixtures/hia_compiler_rename_reference.json.gz',
                    'tests/fixtures/hia_reference_compiler_v64.json.xz')
        optional = tuple(sorted({name for names in OPTIONAL_PROFILE_FILES.values() for name in names}))
        self.assertEqual(support, (*retained, *optional))
        self.assertEqual(set(optional), set(OPTIONAL_RESOURCE_PINS))
        self.assertEqual(len(support), len(set(support)))
        self.assertTrue(set(default_resources()).isdisjoint(support))
        self.assertEqual(len(default_resources()), 210)
        self.assertTrue(all((ROOT / name).is_file() for name in support))




    def test_zz_process_caller_sdist_support_has_exact_two_byte_admission(self):
        from tools import qualify_hia_linux_process as qualifier
        name = 'tests/test_hia_agent_installed_resources.py'
        self.assertEqual(len(qualifier.TEST_SOURCE_PINS), 14)
        self.assertEqual(qualifier.TEST_SOURCE_PINS[name],
                         '28281f2ba1ba11c735b7a88db599aa1baae7614a9cb19d3e59c3cd196a67e511')
        actual = (ROOT / name).read_bytes()
        self.assertEqual(len(actual), 52246)
        self.assertEqual(sha256(actual).hexdigest(),
                         'fd0324146e29b41537325d08fb667d145bb4a5146d312b84990465c0716a81b4')
        retained = actual.replace(qualifier.SDIST_CALLER_SUCCESSOR_BLOCK,
                                  qualifier.SDIST_CALLER_RETAINED_BLOCK, 1)
        self.assertEqual(len(retained), 51716)
        self.assertEqual(sha256(retained).hexdigest(), qualifier.TEST_SOURCE_PINS[name])
        self.assertEqual(qualifier._sdist_caller_admission(retained)['role'], 'EXACT_RETAINED_ORIGINAL')
        self.assertEqual(qualifier._sdist_caller_admission(actual)['role'],
                         'EXACT_SDIST_SUPPORT_DECLARATION_SUCCESSOR')
        self.assertEqual(retained.replace(qualifier.SDIST_CALLER_RETAINED_BLOCK,
                                          qualifier.SDIST_CALLER_SUCCESSOR_BLOCK, 1), actual)
        for raw in (actual + b'\n', retained + b'\n', actual.replace(b'self.assertEqual', b'self.assertNotEqual', 1),
                    actual.replace(b'verified_report.hepta', b'verified_report.other', 1),
                    bytearray(actual), memoryview(actual)):
            with self.subTest(rejected_type=type(raw).__name__, length=len(raw)), self.assertRaises(ValueError):
                qualifier._sdist_caller_admission(raw)
        admission = qualifier._check_test_sources()
        self.assertEqual(admission['retained_test_source_pins'], qualifier.TEST_SOURCE_PINS)
        self.assertEqual(set(admission['actual_test_source_pins']), set(qualifier.TEST_SOURCE_PINS))
        self.assertEqual(admission['actual_test_source_pins'][name], sha256(actual).hexdigest())
        for other, expected in qualifier.TEST_SOURCE_PINS.items():
            if other != name:
                self.assertEqual(admission['actual_test_source_pins'][other], expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            originals = {path: (ROOT / path).read_bytes() for path in qualifier.TEST_SOURCE_PINS}
            for path, raw in originals.items():
                target = root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            with patch.object(qualifier, 'ROOT', root):
                self.assertEqual(qualifier._check_test_sources(), admission)
                for other, raw in originals.items():
                    if other == name:
                        continue
                    (root / other).write_bytes(raw + b'\n')
                    with self.subTest(other_original_pin=other), self.assertRaises(ValueError):
                        qualifier._check_test_sources()
                    (root / other).write_bytes(raw)
        with tempfile.TemporaryDirectory() as directory:
            fixture = {'schema': qualifier.FIXTURE_SCHEMA, 'status': qualifier.FIXTURE_STATUS,
                       'profile': qualifier.PROFILE, 'authority': {}, 'toolchain': {}, 'programs': {},
                       'compiler_image': {}, 'packer_image': {}, 'cold_compiler': {},
                       'matching_cold': True, 'qualification_complete': False, 'whole_native': False,
                       'test_source_pins': dict(qualifier.TEST_SOURCE_PINS)}
            path = Path(directory) / 'fixture.json'
            refusal = ValueError('structural-only authority sentinel; never positive cold')
            with patch.object(qualifier, 're_admit_authority', side_effect=refusal) as authority:
                path.write_text(json.dumps(fixture))
                with self.assertRaisesRegex(ValueError, 'complete current caller pins differ'):
                    qualifier.admit_fixture(path)
                authority.assert_not_called()
                fixture['test_source_pins'] = admission['actual_test_source_pins']
                path.write_text(json.dumps(fixture))
                with self.assertRaises(ValueError) as caught:
                    qualifier.admit_fixture(path)
                self.assertIs(caught.exception, refusal)
                authority.assert_called_once_with({})


if __name__ == '__main__':
    unittest.main()
