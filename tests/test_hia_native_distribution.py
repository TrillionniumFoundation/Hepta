"""Native production archives and independently observed installed behavior.

Hosted API controls explicitly select the reference wheel. These gates inspect
the ordinary artifact itself and execute its installed ELF commands with no PATH.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import build_hia_default_release as release

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_NATIVE_DISTRIBUTION_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_NATIVE_DISTRIBUTION_EVIDENCE'


def _small_executable():
    """A real exit(0) ELF for archive admission controls, never build evidence."""
    code = bytes.fromhex('b83c00000031ff0f05')
    size = 176 + len(code)
    header = b'\x7fELF\x02\x01\x01' + bytes(9)
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    header += struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    header += struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return header + code


def _small_static_executable():
    code = bytes.fromhex('b83c00000031ff0f05')
    data = b'HIA-static-data'
    rx_size = 232 + len(code)
    offset = (rx_size + 4095) // 4096 * 4096
    header = b'\x7fELF\x02\x01\x01' + bytes(9)
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x400000 + 232, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    header += struct.pack('<II6Q', 1, 5, 0, 0x400000, 0x400000, rx_size, rx_size, 4096)
    header += struct.pack('<II6Q', 1, 6, offset, 0x400000 + offset, 0x400000 + offset, len(data), len(data), 4096)
    header += struct.pack('<II6Q', 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return header + code + bytes(offset - rx_size) + data


def _member_fixture():
    from hepta.hia_program_selfhost import SOURCE_FILES
    from tools.build_hia_core_edit import PROGRAMS
    from tools.qualify_hia_selfhost_cli import inspect_executable

    distribution = 'hia_core-0.3.0.dist-info'
    prefix = 'hia_core-0.3.0.data/scripts/'
    binary = _small_executable()
    cli = {prefix + name: binary for kind, (name, _) in PROGRAMS.items() if kind != 'emit_object'}
    cli[prefix + 'hia-nominal-constructor'] = _small_static_executable()
    cli[prefix + 'hia-safe-core-prove'] = binary
    cli.update({prefix + Path(name).name: b'required resource' for name in SOURCE_FILES})
    receipt = {'implementation': 'HIA', 'scope': 'MATCHING_SOURCE_COLD_COMPONENT',
               'executable_path': 'hia-ndu-scalar', 'executable_sha256': sha256(binary).hexdigest(),
               'executable': inspect_executable(binary)}
    auxiliary = {prefix + 'hia-ndu-scalar': binary,
                 'hepta/_hia_ndu_scalar_build.json': release.encoded(receipt),
                 'hepta/__init__.py': b'raise AssertionError("reference only")',
                 'hepta/_data/authoring.py': b'reference authoring input'}
    auxiliary.update({prefix + name: binary for name in release.MCP_PROGRAMS})
    mcp = {'schema': 'hepta.hia.mcp-service-source-build.v1', 'matching_source_cold_build': True,
           'products': {name: {'bytes': len(binary), 'sha256': sha256(binary).hexdigest()}
                        for name in release.MCP_PROGRAMS}}
    auxiliary[distribution + '/native-components/mcp-build.json'] = release.encoded(mcp)
    auxiliary[prefix + release.JOBCTL_PROGRAM] = binary
    jobctl = {'schema': 'hepta.hia.system-jobctl-source-build.v1', 'matching_source_cold_build': True,
              'scope': 'MATCHING_SOURCE_COLD_COMPONENT', 'executable_path': release.JOBCTL_PROGRAM,
              'executable_sha256': sha256(binary).hexdigest(), 'executable': inspect_executable(binary),
              'products': {release.JOBCTL_PROGRAM: {'bytes': len(binary), 'sha256': sha256(binary).hexdigest()}},
              'build_inputs_unchanged': True}
    auxiliary[distribution + '/native-components/jobctl-build.json'] = release.encoded(jobctl)
    return distribution, prefix, cli, auxiliary


def _package_fixture():
    """Mechanical receipt controls only; this fixture is never a native build."""
    from tools import build_hia_native_distribution_package as package
    names = set(package.MANDATORY_PROGRAMS) | set(package.ENTRY_PROGRAMS)
    binary = _small_executable()
    members = {name: (0o500, binary) for name in names}
    wire = bytearray(struct.pack('<8s2Q', b'HIAREL01', len(members), 0))
    for name, (mode, raw) in sorted(members.items()):
        encoded = name.encode('ascii')
        wire += struct.pack('<3Q', len(encoded), mode, len(raw)) + encoded + raw
    raw = bytes(wire)
    compiler, cold = b'fixture compiler', b'fixture cold report'
    sources = {'examples/hia_bootstrap/' + name + '.hepta': 'a' * 64
               for name in package.BOOTSTRAP_ROLES}
    inventory = {name: {'bytes': len(data), 'sha256': sha256(data).hexdigest(), 'mode': mode}
                 for name, (mode, data) in sorted(members.items())}
    identity = {'name': 'store.hiapack', 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                'files': len(members)}
    report = {'schema': package.SCHEMA, 'matching_source_cold_build': True,
              'build_inputs_unchanged': True, 'native_install_and_verify_completed': True,
              'source_manifest': sources, 'compiler_sha256': sha256(compiler).hexdigest(),
              'cold_report_sha256': sha256(cold).hexdigest(), 'package': identity,
              'members': inventory,
              'native_final_receipt': {'schema': 'hepta.hia.release-finalize.v1',
                  'sha256': identity['sha256'], 'bytes': len(raw), 'files': len(members),
                  'published': True, 'source_attested': True},
              'bootstrap': {'source_sha256': sources,
                  'compiler_sha256': sha256(compiler).hexdigest(), 'cold_report_sha256': sha256(cold).hexdigest(),
                  'programs': {name: {'bytes': len(binary), 'sha256': sha256(binary).hexdigest()}
                               for name in package.ENTRY_PROGRAMS}}}
    return raw, report, sources, compiler, cold, members


class NativeDistributionSourceTests(unittest.TestCase):
    def test_native_metadata_has_no_python_runtime_or_optional_solver_requirement(self):
        from email.parser import BytesParser

        distribution, files = release.native_distribution_metadata((ROOT / 'pyproject.toml').read_bytes())
        metadata = BytesParser().parsebytes(files[distribution + '/METADATA'])
        self.assertEqual(metadata['Name'], 'hia-core')
        self.assertEqual(metadata['Version'], '0.3.0')
        self.assertIsNone(metadata['Requires-Python'])
        self.assertIsNone(metadata['Requires-Dist'])
        self.assertIsNone(metadata['Provides-Extra'])
        self.assertIn(b'Root-Is-Purelib: false\n', files[distribution + '/WHEEL'])

    def test_project_metadata_cannot_inject_headers_or_member_paths(self):
        for name, version, summary in (
            ('../hia', '0.3.0', 'HIA'), ('hia', '0.3.0/../x', 'HIA'),
            ('hia', '0.3.0', 'HIA\nRequires-Dist: external'),
        ):
            raw = ('[project]\nname=' + json.dumps(name) + '\nversion=' + json.dumps(version)
                   + '\ndescription=' + json.dumps(summary) + '\n').encode()
            with self.subTest(name=name, version=version, summary=summary), self.assertRaises(ValueError):
                release.native_distribution_metadata(raw)

    def test_default_builder_cannot_enter_the_reference_base_wheel(self):
        marker = object()
        with (patch.object(release, '_build_native_distribution', return_value=marker) as native,
              patch.object(release, '_base_wheel', side_effect=AssertionError('reference base wheel')),
              patch.object(release, '_inputs', side_effect=AssertionError('reference Python inventory'))):
            self.assertIs(release.build('output', 'compiler', 'cold'), marker)
            native.assert_called_once_with('output', 'compiler', 'cold')
        for arguments in ({}, {'development': False, 'reference': True},
                          {'development': True, 'reference': True}, {'reference': 1}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                release.build('output', 'compiler', **arguments)

    def test_reference_wheel_requires_explicit_exact_backend_selection(self):
        from tools.hia_wheel_backend import _reference_distribution

        self.assertFalse(_reference_distribution(None))
        self.assertFalse(_reference_distribution({}))
        self.assertFalse(_reference_distribution({'hia.reference-wheel': 'false'}))
        self.assertTrue(_reference_distribution({'hia.reference-wheel': 'true'}))
        self.assertTrue(_reference_distribution({'hia.reference-wheel': ['true']}))
        for value in (True, 1, '', 'TRUE', ['true', 'false'], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _reference_distribution({'hia.reference-wheel': value})

    def test_invalid_profile_refuses_before_any_cold_compiler_work(self):
        from tools import hia_wheel_backend as backend

        with (patch.object(backend, '_cold_inputs', side_effect=AssertionError('cold work')),
              self.assertRaises(ValueError)):
            backend.build_wheel('absent-output', {'hia.reference-wheel': 'TRUE'})

    def test_default_pep517_metadata_never_invokes_the_hosted_packager(self):
        from tools import hia_wheel_backend as backend

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(backend, 'prepare_python_metadata_for_build_wheel',
                              side_effect=AssertionError('hosted metadata')):
                distribution = backend.prepare_metadata_for_build_wheel(temporary)
            metadata = (Path(temporary) / distribution / 'METADATA').read_bytes()
            self.assertNotIn(b'Requires-Python:', metadata)
            self.assertEqual(sorted(path.name for path in (Path(temporary) / distribution).iterdir()),
                             ['METADATA', 'WHEEL'])

    def test_native_closure_drops_reference_members_and_retains_bound_ndu_receipt(self):
        distribution, prefix, cli, auxiliary = _member_fixture()
        actual = release.native_runtime_members(distribution, cli, auxiliary)
        self.assertFalse(any(name.startswith('hepta/') for name in actual))
        self.assertEqual(actual[distribution + '/native-components/ndu-build.json'],
                         auxiliary['hepta/_hia_ndu_scalar_build.json'])
        self.assertEqual({name for name in actual if name.startswith(prefix)},
                         set(cli) | {prefix + name for name in ('hia-ndu-scalar', *release.MCP_PROGRAMS, release.JOBCTL_PROGRAM)})

    def test_missing_substituted_duplicate_and_unlisted_programs_are_refused(self):
        distribution, prefix, cli, auxiliary = _member_fixture()
        mutations = []
        missing = dict(cli); missing.pop(prefix + 'hia'); mutations.append((missing, auxiliary))
        for raw in (b'#!/usr/bin/python3\n', b'\x7fELF\x02\x01\x01', _small_executable()[:-1], _small_static_executable()):
            changed = dict(cli); changed[prefix + 'hia'] = raw; mutations.append((changed, auxiliary))
        for name in ('python', '../hia', 'nested/hia'):
            changed = dict(cli); changed[prefix + name] = _small_executable(); mutations.append((changed, auxiliary))
        duplicate = dict(auxiliary); duplicate[prefix + 'hia'] = cli[prefix + 'hia']
        mutations.append((cli, duplicate))
        for left, right in mutations:
            with self.subTest(names=sorted(set(left) - set(cli))), self.assertRaises(ValueError):
                release.native_runtime_members(distribution, left, right)

    def test_ndu_receipt_must_bind_the_actual_matching_cold_hia_executable(self):
        distribution, _, cli, auxiliary = _member_fixture()
        name = 'hepta/_hia_ndu_scalar_build.json'
        original = json.loads(auxiliary[name])
        for key, value in (('executable_sha256', '0' * 64), ('implementation', 'Rust'),
                           ('scope', 'DEVELOPMENT_COMPONENT'), ('executable', {})):
            changed = dict(auxiliary)
            receipt = deepcopy(original); receipt[key] = value
            changed[name] = release.encoded(receipt)
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.native_runtime_members(distribution, cli, changed)

    def test_mcp_receipt_requires_all_three_current_native_programs(self):
        distribution, _, cli, auxiliary = _member_fixture()
        name = distribution + '/native-components/mcp-build.json'
        original = json.loads(auxiliary[name])
        variants = []
        changed = deepcopy(original); changed['matching_source_cold_build'] = False; variants.append(changed)
        changed = deepcopy(original); del changed['products']['hia-mcp-request-audit']; variants.append(changed)
        changed = deepcopy(original); changed['products']['hia-mcp-service']['sha256'] = '0' * 64; variants.append(changed)
        for receipt in variants:
            members = dict(auxiliary); members[name] = release.encoded(receipt)
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                release.native_runtime_members(distribution, cli, members)

    def test_jobctl_receipt_requires_actual_cold_native_system_owner(self):
        distribution, _, cli, auxiliary = _member_fixture()
        name = distribution + '/native-components/jobctl-build.json'
        original = json.loads(auxiliary[name])
        for key, value in (('matching_source_cold_build', False), ('scope', 'DEVELOPMENT_COMPONENT'),
                           ('products', {}), ('executable_sha256', '0' * 64), ('executable', {}),
                           ('executable_path', 'python'), ('build_inputs_unchanged', False)):
            changed = dict(auxiliary)
            receipt = deepcopy(original); receipt[key] = value
            changed[name] = release.encoded(receipt)
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.native_runtime_members(distribution, cli, changed)

    def test_native_package_file_capture_accepts_fresh_regular_files_and_refuses_links(self):
        from tools.build_hia_native_distribution_package import regular_bytes

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'fresh.hiapack'
            path.write_bytes(b'fresh captured data')
            os.utime(path, ns=(1, path.stat().st_mtime_ns))
            self.assertEqual(regular_bytes(path), b'fresh captured data')
            link = root / 'substituted'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                regular_bytes(link)
            with self.assertRaises((ValueError, OSError)):
                regular_bytes(root)

    def test_full_native_package_receipt_refuses_wrong_source_cold_compiler_or_bootstrap(self):
        from tools import build_hia_native_distribution_package as package

        raw, original, sources, compiler, cold, members = _package_fixture()
        with patch.object(package, 'expected_member_names', return_value=set(members)):
            self.assertEqual(package.validate_build(raw, original, sources, compiler, cold), members)
            changes = [
                ('matching_source_cold_build', False), ('build_inputs_unchanged', False),
                ('native_install_and_verify_completed', False), ('source_manifest', {}),
                ('compiler_sha256', '0' * 64), ('cold_report_sha256', '0' * 64),
            ]
            for key, value in changes:
                report = deepcopy(original); report[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    package.validate_build(raw, report, sources, compiler, cold)
            for field in ('source_sha256', 'programs'):
                report = deepcopy(original); report['bootstrap'][field] = {}
                with self.subTest(field=field), self.assertRaises(ValueError):
                    package.validate_build(raw, report, sources, compiler, cold)
            report = deepcopy(original); report['bootstrap']['programs']['hia-release-owner']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                package.validate_build(raw, report, sources, compiler, cold)

    def test_full_native_package_cannot_substitute_payload_receipt_or_member_set(self):
        from tools import build_hia_native_distribution_package as package

        raw, original, sources, compiler, cold, members = _package_fixture()
        with patch.object(package, 'expected_member_names', return_value=set(members)):
            for area, key, value in (
                ('package', 'sha256', '0' * 64), ('package', 'files', 1),
                ('native_final_receipt', 'source_attested', False), ('native_final_receipt', 'published', 1),
                ('native_final_receipt', 'bytes', 1),
            ):
                report = deepcopy(original); report[area][key] = value
                with self.subTest(area=area, key=key), self.assertRaises(ValueError):
                    package.validate_build(raw, report, sources, compiler, cold)
            report = deepcopy(original); del report['members']['hia-controller-install']
            with self.assertRaises(ValueError):
                package.validate_build(raw, report, sources, compiler, cold)
            damaged = bytearray(raw); damaged[-1] ^= 1
            with self.assertRaises(ValueError):
                package.validate_build(bytes(damaged), original, sources, compiler, cold)
            smaller = dict(members); del smaller['hia-worker-install']
            with self.assertRaises(ValueError):
                package.member_inventory(smaller, sources)
            wrong_mode = dict(members); wrong_mode['hia-release'] = (0o400, wrong_mode['hia-release'][1])
            with self.assertRaises(ValueError):
                package.member_inventory(wrong_mode, sources)

    def test_full_native_package_framing_refuses_trailing_duplicate_path_and_mode(self):
        from tools.build_hia_native_distribution_package import unpack_package

        def frame(rows):
            raw = bytearray(struct.pack('<8s2Q', b'HIAREL01', len(rows), 0))
            for name, mode, payload in rows:
                raw += struct.pack('<3Q', len(name), mode, len(payload)) + name + payload
            return bytes(raw)
        valid = frame([(b'first', 0o400, b'one'), (b'second', 0o400, b'two')])
        self.assertEqual(unpack_package(valid), {'first': (0o400, b'one'), 'second': (0o400, b'two')})
        variants = [valid[:-1], valid + b'unbound', b'HIAREL02' + valid[8:],
                    frame([(b'first', 0o400, b'one'), (b'first', 0o400, b'two')]),
                    frame([(b'second', 0o400, b'one'), (b'first', 0o400, b'two')]),
                    frame([(b'../escape', 0o400, b'data')]), frame([(b'entry', 0o755, b'data')])]
        for raw in variants:
            with self.subTest(sha256=sha256(raw).hexdigest()), self.assertRaises(ValueError):
                unpack_package(raw)

    def test_reference_profile_adaptation_keeps_exact_original_test_bytes(self):
        from tests.hia_installed_distribution_history import REFERENCE_FIXTURE, reference_predecessor

        rows = json.loads((ROOT / REFERENCE_FIXTURE).read_bytes())['files']
        self.assertEqual(len(rows), 4)
        for name, record in rows.items():
            current = (ROOT / name).read_bytes()
            original = reference_predecessor(name, current)
            self.assertEqual({'bytes': len(original), 'sha256': sha256(original).hexdigest()},
                             record['original'], name)
            damaged = current + b'# unreviewed change\n'
            self.assertEqual(reference_predecessor(name, damaged), damaged)

    def test_nominal_static_profile_keeps_original_linker_and_image_guards(self):
        from tools.build_hia_sqlite_pager import verify_executable
        raw = _small_static_executable()
        image = bytes.fromhex('b83c00000031ff0f05')
        inspection = release.inspect_native_runtime_executable('hia-nominal-constructor', raw)
        self.assertEqual(inspection['program_headers'], ['PT_LOAD_RX', 'PT_LOAD_RW', 'PT_GNU_STACK_RW'])
        self.assertIsNone(verify_executable(raw, image))
        with self.assertRaises(ValueError):
            release.inspect_native_runtime_executable('hia', raw)
        for offset, fmt, value in ((124, '<I', 7), (120, '<I', 3), (24, '<Q', 0x401000),
                                   (104, '<Q', len(raw) + 1), (136, '<Q', 0x900000),
                                   (180, '<I', 7)):
            changed = bytearray(raw)
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError):
                    release.inspect_native_runtime_executable('hia-nominal-constructor', bytes(changed))
                with self.assertRaises(ValueError):
                    verify_executable(bytes(changed), image)
        for changed in (raw[:-1], raw + b'x'):
            with self.assertRaises(ValueError):
                release.inspect_native_runtime_executable('hia-nominal-constructor', changed)
        for changed_image in (b'', image + b'x', raw[-15:]):
            with self.assertRaises(ValueError):
                verify_executable(raw, changed_image)


class NativeDistributionInstalledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get(COLD)
        if not cold:
            raise ValueError('native production installation requires the matching current cold report')
        target = os.environ.get(EVIDENCE)
        if target:
            cls.root = Path(target).absolute()
            cls.root.mkdir(mode=0o700, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-native-distribution-')
            cls.root = Path(temporary.name)
            cls.addClassCleanup(temporary.cleanup)
        cls.sources = release.current_sources()
        report = json.loads(Path(cold).read_bytes())
        nested = json.loads(Path(report['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        cls.compiler, cls.cold_report = compiler, Path(cold)
        cls.wheel = release.build(cls.root / 'build', compiler, cold)
        cls.build = json.loads((cls.root / 'build/build.json').read_bytes())
        cls.installed = cls.root / 'installed'
        env = {key: value for key, value in os.environ.items()
               if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        install = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps',
                                  '--no-index', '--no-compile', '--target', str(cls.installed), str(cls.wheel)],
                                 cwd=cls.root, env=env, capture_output=True, timeout=60)
        (cls.root / 'pip-install.stdout').write_bytes(install.stdout)
        (cls.root / 'pip-install.stderr').write_bytes(install.stderr)
        if install.returncode:
            raise AssertionError(('native wheel installation', install.returncode, install.stderr))
        cls.bin = cls.installed / 'bin'
        cls.original_inventory = cls.inventory()
        cls.observations = {}

    @classmethod
    def inventory(cls):
        return {str(path.relative_to(cls.installed)): sha256(path.read_bytes()).hexdigest()
                for path in cls.installed.rglob('*') if path.is_file()}

    @classmethod
    def tearDownClass(cls):
        after = cls.inventory()
        result = {'schema': 'hepta.hia.native-distribution-installed.v1',
                  'distribution_profile': 'native-production',
                  'wheel_sha256': sha256(cls.wheel.read_bytes()).hexdigest(),
                  'source_manifest': cls.sources,
                  'source_inputs_unchanged': release.current_sources() == cls.sources,
                  'installed_inputs_unchanged': after == cls.original_inventory,
                  'installed_members': after, 'observations': cls.observations,
                  'whole_native_delivery_qualified': False, 'production_activated': False}
        (cls.root / 'installed-report.json').write_bytes(release.encoded(result))
        if not result['source_inputs_unchanged'] or not result['installed_inputs_unchanged']:
            raise AssertionError('native production qualification inputs changed')

    def test_archive_inventory_records_and_installed_executable_modes(self):
        from tools.qualify_hia_selfhost_cli import inspect_executable

        with zipfile.ZipFile(self.wheel) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), len(set(names)))
            self.assertFalse(any(name.startswith('hepta/') for name in names))
            self.assertFalse(any(Path(name).suffix in {'.py', '.pyc', '.pyo', '.pth', '.rs', '.c', '.so', '.sh'}
                                 for name in names))
            record, = [name for name in names if name.endswith('.dist-info/RECORD')]
            distribution = record.removesuffix('/RECORD')
            rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
            self.assertEqual({row[0] for row in rows}, set(names))
            for name, digest, length in rows:
                if name != record:
                    raw = archive.read(name)
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode())
                    self.assertEqual(int(length), len(raw))
            provenance = json.loads(archive.read(distribution + '/native-runtime.json'))
            self.assertEqual(provenance['source_manifest'], self.sources)
            self.assertEqual(provenance['python_runtime_members'], [])
            self.assertTrue(provenance['retained_reference_bodies_removed'])
            self.assertEqual(provenance['distribution_profile'], 'native-production')
            for name, identity in provenance['runtime_members'].items():
                raw = archive.read(name)
                self.assertEqual(identity, {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})
                if raw.startswith(b'\x7fELF'):
                    release.inspect_native_runtime_executable(Path(name).name, raw)
                    self.assertEqual(archive.getinfo(name).external_attr >> 16, 0o100755)
                    installed = self.bin / Path(name).name
                    self.assertTrue(os.access(installed, os.X_OK))
                    self.assertEqual(installed.read_bytes(), raw)
        self.assertFalse((self.installed / 'hepta').exists())
        self.assertEqual(self.build['schema'], release.NATIVE_BUILD_SCHEMA)
        self.assertIsNone(self.build['python_library_wheel_command'])
        self.assertTrue(self.build['ordinary_source_default_changed'])

    def test_contained_complete_package_installs_exact_original_private_release(self):
        from tools import build_hia_native_distribution_package as package

        distribution, = self.installed.glob('*.dist-info')
        report = json.loads((distribution / 'native-components/release-build.json').read_bytes())
        payload = self.installed / 'share/hia/store.hiapack'
        raw = payload.read_bytes()
        members = package.validate_build(raw, report, self.sources,
                                         self.compiler.read_bytes(), self.cold_report.read_bytes())
        self.assertEqual(self.build['complete_native_package'], report['package'])
        self.assertTrue(self.build['complete_native_package_source_attested'])
        installer = self.bin / 'hia-release'
        self.assertEqual(installer.read_bytes(), members['hia-release'][1])
        depot = self.root / 'installed-native-depot'
        depot.mkdir(mode=0o700)
        digest = report['package']['sha256']
        for action in ('install', 'verify'):
            result = subprocess.run([installer, action, depot, digest], input=raw, cwd=self.root,
                                    env={'PATH': ''}, capture_output=True, timeout=180)
            (self.root / ('contained-package-' + action + '.stdout')).write_bytes(result.stdout)
            (self.root / ('contained-package-' + action + '.stderr')).write_bytes(result.stderr)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertEqual(json.loads(result.stdout), {
                'schema': 'hepta.hia.release-install.v1', 'sha256': digest, 'bytes': len(raw),
                'files': len(members), 'published': action == 'install'})
        private = depot / digest
        self.assertEqual({path.name for path in private.iterdir()}, set(members))
        for name, (mode, content) in members.items():
            self.assertEqual((private / name).read_bytes(), content, name)
            self.assertEqual((private / name).stat().st_mode & 0o7777, mode, name)
        for name in ('hia-worker-install', 'hia-controller-install', 'hia-mcp-service', 'hepta-runtime-jobctl'):
            self.assertTrue(os.access(private / name, os.X_OK), name)
        self.observations['contained_native_package'] = {
            'sha256': digest, 'files': len(members), 'bytes': len(raw), 'private_depot': str(private),
            'native_install_and_verify': True, 'every_original_member_and_mode_equal': True}

    def test_original_complete_edit_and_impact_observations_with_empty_path(self):
        from tests.test_hia_core_edit_runtime import check_release

        count = check_release(self.bin)
        self.assertEqual(count, 56)
        self.observations['original_edit_impact_cases'] = count

    def test_original_object_bytes_publication_and_file_refusals(self):
        from tests.test_hia_core_edit_runtime import check_object_builds, check_build_input_diagnostics

        objects = check_object_builds(self.bin)
        refused = check_build_input_diagnostics(self.bin)
        self.assertEqual(objects, 19)
        self.assertEqual(refused, 10)
        self.observations['original_object_build_cases'] = objects
        self.observations['original_file_refusals'] = refused

    def test_original_public_checked_and_register_build_gates_on_installed_commands(self):
        environment = dict(os.environ)
        environment['HIA_TEST_NATIVE_FILTER_RELEASE'] = str(self.bin)
        environment['HEPTA_HIA_TEST_INSTALLED_CHECKED_CLI'] = str(self.bin / 'hia')
        selectors = ['tests.test_hia_checked_build_public_cli',
                     'tests.test_hia_verified_checked_public_cli',
                     'tests.test_hia_register_build_public_cli']
        run = subprocess.run([sys.executable, '-B', 'tools/run_hia_unittest_gate.py', *selectors],
                             cwd=ROOT, env=environment, capture_output=True, timeout=600)
        (self.root / 'original-public-build.stdout').write_bytes(run.stdout)
        (self.root / 'original-public-build.stderr').write_bytes(run.stderr)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
        self.observations['original_public_build_selectors'] = selectors

    def test_installed_ndu_preserves_every_original_rust_stdout_and_digest(self):
        from tests.test_hia_ndu_scalar_native import original_pairs

        pairs = list(original_pairs())
        self.assertGreaterEqual(len(pairs), 64)
        for supplied, expected in pairs:
            with self.subTest(input_sha256=sha256(supplied).hexdigest()):
                actual = subprocess.run([self.bin / 'hia-ndu-scalar'], input=supplied,
                                        cwd=self.root, env={'PATH': ''}, capture_output=True, timeout=15)
                self.assertEqual((actual.returncode, actual.stderr, actual.stdout), (0, b'', expected))
        self.observations['original_ndu_stdout_cases'] = len(pairs)


if __name__ == '__main__':
    unittest.main()
