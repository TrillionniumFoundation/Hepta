"""Physical HIA suffixes and whole-program admission, with immutable history."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.check_hia_core_only import ROOT, check


@contextmanager
def source_tree():
    with tempfile.TemporaryDirectory(prefix='hia-source-suffix-') as temporary:
        root = Path(temporary)
        for name in ('pyproject.toml', 'docs/HIA_CORE_ONLY_SCOPE.json'):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        (root / 'examples').mkdir()
        yield root


def scalar_document(version, *, composite=False):
    schema = ('hepta.hia.composite.v' if composite else 'hepta.hia.program.v') + str(version)
    document = dict(schema=schema, module='suffix_gate', functions=[
        dict(name='main', params=[], returns=['u32'], effects=[], entry='entry',
             blocks=[dict(id='entry', params=[], ops=[
                 dict(op='const', args=[], out=[dict(name='answer', type='u32')], attrs=dict(value=7))],
                 term=dict(op='ret', values=['answer']))])])
    if composite:
        document['types'] = []
    return document


def scalar_assembly(version=8):
    return (
        'hia-asm.v1 hepta.hia.program.v' + str(version) + ' suffix_gate\n'
        'fn main() -> (u32) effects() entry(entry)\n'
        'block entry()\n'
        '  answer:u32 = const() {"value":7}\n'
        '  ret(answer)\n'
        'end\n'
    ).encode()


class HiaSourceSuffixTests(unittest.TestCase):
    def test_all_current_assembly_versions_are_fully_checked_without_rewriting(self):
        with source_tree() as root:
            frozen = {}
            for version in (6, 7, 8):
                path = root / 'examples' / ('assembly_v' + str(version) + '.hepta')
                raw = scalar_assembly(version)
                path.write_bytes(raw)
                frozen[path.relative_to(root).as_posix()] = sha256(raw).hexdigest()
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_suffix'], '.hepta')
            self.assertEqual(result['hia_source_files'], 3)
            self.assertEqual(result['hia_source_manifest_sha256'],
                             sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest())
            for name, digest in frozen.items():
                self.assertEqual(sha256((root / name).read_bytes()).hexdigest(), digest)

    def test_all_primitive_and_composite_json_versions_remain_supported(self):
        with source_tree() as root:
            for composite, versions in ((False, range(1, 9)), (True, range(1, 5))):
                for version in versions:
                    name = ('composite' if composite else 'primitive') + str(version) + '.hepta'
                    (root / 'examples' / name).write_text(json.dumps(
                        scalar_document(version, composite=composite)))
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_files'], 12)

    def test_legacy_and_noncanonical_case_suffixes_are_refused_as_real_files(self):
        with source_tree() as root:
            for suffix in ('.hia', '.HIA', '.hiaasm', '.HiaAsm', '.hia.json', '.HIA.JSON',
                           '.HEPTA', '.Hepta'):
                path = root / 'examples' / ('source' + suffix)
                path.write_bytes(scalar_assembly())
                with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, 'HIA source suffix'):
                    check(root)
                path.unlink()

    def test_current_structured_sources_cannot_bypass_suffix_check_as_json(self):
        with source_tree() as root:
            for directory in ('examples', 'tests/fixtures', 'formal', 'benchmarks'):
                parent = root / directory
                parent.mkdir(parents=True, exist_ok=True)
                for composite, version in ((False, 8), (True, 4)):
                    for suffix in ('.json', '.JSON'):
                        path = parent / ('source' + suffix)
                        path.write_text(json.dumps(scalar_document(version, composite=composite)))
                        with self.subTest(directory=directory, composite=composite, suffix=suffix):
                            with self.assertRaisesRegex(ValueError, 'noncanonical HIA source suffix'):
                                check(root)
                        path.unlink()

    def test_source_suffix_does_not_reclassify_data_or_frozen_experiment_programs(self):
        with source_tree() as root:
            records = {
                'examples/request.json': {'schema': 'hepta.hia.patch.v1', 'edits': []},
                'tests/fixtures/manifest.json': {'sources': ['source.hepta']},
                'formal/report.json': {'schema': 'hepta.hia.proof-result.v1'},
                'benchmarks/workload.json': {'cases': []},
                'experiments/original/baseline.json': scalar_document(8),
                'review-evidence/original/candidate.core.json': scalar_document(4, composite=True),
            }
            original = {}
            for name, document in records.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                original[name] = json.dumps(document).encode()
                path.write_bytes(original[name])
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_files'], 0)
            for name, raw in original.items():
                self.assertEqual((root / name).read_bytes(), raw)

    def test_canonical_suffix_does_not_admit_header_only_receipts_or_removed_source(self):
        # Runtime concatenation keeps this a used negative case rather than a
        # retained source-language fixture in the authored Core-only tree.
        removed = 'module retired;' + '\n' + 'export "C" ' + 'fn gone() -> u32 { return 1; }'
        cases = (
            b'hia-asm.v1 hepta.hia.program.v8 header_only\n',
            b'{"schema":"hepta.hia.program.v8","status":"PASS"}',
            b'{"schema":',
            b'\xff' + scalar_assembly(),
            removed.encode(),
        )
        with source_tree() as root:
            path = root / 'examples' / 'invalid.hepta'
            for index, raw in enumerate(cases):
                path.write_bytes(raw)
                with self.subTest(case=index), self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                    check(root)
                self.assertEqual(path.read_bytes(), raw)

    def test_valid_syntax_still_reaches_full_ssa_and_nominal_type_verification(self):
        bad_primitive = scalar_document(8)
        bad_primitive['functions'][0]['blocks'][0]['term']['values'] = ['missing']
        bad_nominal = scalar_document(4, composite=True)
        bad_nominal['functions'][0]['returns'] = ['MissingType']
        cases = (
            scalar_assembly().replace(b'ret(answer)', b'ret(missing)'),
            json.dumps(bad_primitive).encode(),
            json.dumps(bad_nominal).encode(),
        )
        with source_tree() as root:
            path = root / 'examples' / 'invalid.hepta'
            for index, raw in enumerate(cases):
                path.write_bytes(raw)
                with self.subTest(case=index), self.assertRaisesRegex(ValueError, 'invalid HIA source content') as caught:
                    check(root)
                self.assertRegex(str(caught.exception), 'E_HIA_(SSA|TYPE)')
                self.assertEqual(path.read_bytes(), raw)

    def test_historical_receipt_paths_and_hashes_remain_byte_identical(self):
        with source_tree() as root:
            historical = root / 'docs' / 'historical-receipt.json'
            record = {
                'schema': 'hepta.hia.program.v8',
                'original_sources': {
                    'examples/old.hiaasm': 'a' * 64,
                    'examples/old.HIA': 'b' * 64,
                    'examples/old.hia.json': 'c' * 64,
                },
                'status': 'HISTORICAL_RECORD_ONLY',
            }
            raw = json.dumps(record, indent=2, sort_keys=True).encode() + b'\n'
            historical.write_bytes(raw)
            note = root / 'docs' / 'HISTORY.md'
            note_bytes = b'Archived paths: old.hiaasm, old.HIA, old.hia.json.\n'
            note.write_bytes(note_bytes)
            (root / 'examples' / 'current.hepta').write_bytes(scalar_assembly())
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_files'], 1)
            self.assertEqual(historical.read_bytes(), raw)
            self.assertEqual(sha256(historical.read_bytes()).hexdigest(), sha256(raw).hexdigest())
            self.assertEqual(note.read_bytes(), note_bytes)

    def test_canonical_source_must_be_an_actual_regular_file(self):
        with source_tree() as root:
            target = root / 'examples' / 'target.txt'
            target.write_bytes(scalar_assembly())
            link = root / 'examples' / 'linked.hepta'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                check(root)
            link.unlink()
            directory = root / 'examples' / 'directory.hepta'
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                check(root)


    def test_linux_stdio_source_roles_are_explicit_and_fully_verified(self):
        from unittest.mock import patch
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_linux_stdio import PROFILE
        from tools.check_hia_core_only import EXPLICIT_SOURCE_PROFILES
        names = (
            'tests/fixtures/hia_linux_stdio_bounded-copy.hepta',
            'tests/fixtures/hia_linux_stdio_out-of-bounds.hepta',
            'tests/fixtures/hia_linux_stdio_read-ebadf-exact.hepta',
            'tests/fixtures/hia_linux_stdio_write-ebadf-exact.hepta',
            'tests/fixtures/hia_linux_stdio_zero-transfer.hepta',
        )
        expected_profiles = {name: PROFILE for name in names}
        expected_profiles['examples/hia_bootstrap/native_cli_process.hepta'] = 'hepta.hia.linux-cli-process.v1'
        expected_profiles['examples/hia_bootstrap/native_file_read.hepta'] = 'hepta.hia.linux-file.v1'
        expected_profiles['examples/hia_bootstrap/native_file_render.hepta'] = 'hepta.hia.linux-file-render.v3'
        self.assertEqual(EXPLICIT_SOURCE_PROFILES, expected_profiles)
        source = {name: (ROOT / name).read_bytes() for name in names}
        structured = {}
        for name, raw in source.items():
            with self.subTest(default_assembly=name), self.assertRaises(ValueError):
                assemble_program(raw)
            structured[name] = assemble_program(raw, profile=PROFILE).canonical_bytes
            with self.subTest(default_json=name), self.assertRaises(ValueError):
                verify_program(structured[name])
        with source_tree() as root:
            for name, raw in source.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            with patch('hepta.hia_agent_assembly.assemble_program', wraps=assemble_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 5)
            self.assertEqual([call.args for call in calls.call_args_list],
                             [(source[name],) for name in sorted(names)])
            self.assertEqual([call.kwargs for call in calls.call_args_list],
                             [{'profile': PROFILE}] * 5)
            for name, raw in structured.items():
                (root / name).write_bytes(raw)
            with patch('hepta.hia_program.verify_program', wraps=verify_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 5)
            self.assertEqual([call.args for call in calls.call_args_list],
                             [(structured[name],) for name in sorted(names)])
            self.assertEqual([call.kwargs for call in calls.call_args_list],
                             [{'profile': PROFILE}] * 5)
            unregistered = root / 'examples' / 'unregistered_stdio.hepta'
            for raw in (source[names[0]], structured[names[0]]):
                unregistered.write_bytes(raw)
                with self.subTest(unregistered_format=raw[:1]), self.assertRaisesRegex(
                        ValueError, 'invalid HIA source content: examples/unregistered_stdio'):
                    check(root)
                self.assertEqual(unregistered.read_bytes(), raw)
                unregistered.unlink()
            selected = root / names[0]
            self.assertIn(b'linux_io', source[names[0]])
            selected.write_bytes(source[names[0]].replace(b'linux_io', b'unregistered_io'))
            with self.assertRaisesRegex(ValueError, 'E_HIA_EFFECT'):
                check(root)
            broken = json.loads(structured[names[0]])
            broken['functions'][0]['blocks'][0]['ops'][0]['out'][0]['name'] = 'invalid value name'
            selected.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                check(root)
            selected.unlink()
            selected.symlink_to(ROOT / names[0])
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                check(root)
            selected.unlink()
            for name, raw in source.items():
                (root / name).write_bytes(raw)
            self.assertEqual(check(root)['hia_source_files'], 5)
            for name, raw in source.items():
                self.assertEqual((root / name).read_bytes(), raw)

    def test_native_cli_process_source_role_is_explicit_and_fully_verified(self):
        from unittest.mock import patch
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_linux_cli_process import PROFILE
        from tools.check_hia_core_only import EXPLICIT_SOURCE_PROFILES
        name = 'examples/hia_bootstrap/native_cli_process.hepta'
        self.assertEqual(EXPLICIT_SOURCE_PROFILES[name], PROFILE)
        raw = (ROOT / name).read_bytes()
        with self.assertRaises(ValueError):
            assemble_program(raw)
        structured = assemble_program(raw, profile=PROFILE).canonical_bytes
        with self.assertRaises(ValueError):
            verify_program(structured)
        with source_tree() as root:
            selected = root / name
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.write_bytes(raw)
            with patch('hepta.hia_agent_assembly.assemble_program', wraps=assemble_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(raw,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), raw)
            selected.write_bytes(structured)
            with patch('hepta.hia_program.verify_program', wraps=verify_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(structured,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), structured)
            unregistered = root / 'examples' / 'unregistered_cli_process.hepta'
            for content in (raw, structured):
                unregistered.write_bytes(content)
                with self.subTest(unregistered_format=content[:1]), self.assertRaisesRegex(
                        ValueError, 'invalid HIA source content: examples/unregistered_cli_process'):
                    check(root)
                self.assertEqual(unregistered.read_bytes(), content)
                unregistered.unlink()
            broken = json.loads(structured)
            output = next(operation['out'][0]
                          for function in broken['functions']
                          for block in function['blocks']
                          for operation in block['ops'] if operation['out'])
            output['name'] = 'invalid value name'
            selected.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                check(root)
            selected.unlink()
            selected.symlink_to(ROOT / name)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                check(root)
            selected.unlink()
            selected.write_bytes(raw)
            self.assertEqual(check(root)['hia_source_files'], 1)
            self.assertEqual(selected.read_bytes(), raw)

    def test_native_file_source_role_is_explicit_and_fully_verified(self):
        from unittest.mock import patch
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_linux_file import PROFILE
        from tools.check_hia_core_only import EXPLICIT_SOURCE_PROFILES
        name = 'examples/hia_bootstrap/native_file_read.hepta'
        self.assertEqual(EXPLICIT_SOURCE_PROFILES[name], PROFILE)
        raw = (ROOT / name).read_bytes()
        with self.assertRaises(ValueError):
            assemble_program(raw)
        structured = assemble_program(raw, profile=PROFILE).canonical_bytes
        with self.assertRaises(ValueError):
            verify_program(structured)
        with source_tree() as root:
            selected = root / name
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.write_bytes(raw)
            with patch('hepta.hia_agent_assembly.assemble_program', wraps=assemble_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(raw,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), raw)
            selected.write_bytes(structured)
            with patch('hepta.hia_program.verify_program', wraps=verify_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(structured,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), structured)
            unregistered = root / 'examples' / 'unregistered_file.hepta'
            for content in (raw, structured):
                unregistered.write_bytes(content)
                with self.subTest(unregistered_format=content[:1]), self.assertRaisesRegex(
                        ValueError, 'invalid HIA source content: examples/unregistered_file'):
                    check(root)
                self.assertEqual(unregistered.read_bytes(), content)
                unregistered.unlink()
            broken = json.loads(structured)
            output = next(operation['out'][0]
                          for function in broken['functions']
                          for block in function['blocks']
                          for operation in block['ops'] if operation['out'])
            output['name'] = 'invalid value name'
            selected.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                check(root)
            selected.unlink()
            selected.symlink_to(ROOT / name)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                check(root)
            selected.unlink()
            selected.write_bytes(raw)
            self.assertEqual(check(root)['hia_source_files'], 1)
            self.assertEqual(selected.read_bytes(), raw)

    def test_native_file_render_source_role_is_explicit_and_fully_verified(self):
        from unittest.mock import patch
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_linux_file_render import PROFILE
        from tools.check_hia_core_only import EXPLICIT_SOURCE_PROFILES
        name = 'examples/hia_bootstrap/native_file_render.hepta'
        self.assertEqual(EXPLICIT_SOURCE_PROFILES[name], PROFILE)
        raw = (ROOT / name).read_bytes()
        with self.assertRaises(ValueError):
            assemble_program(raw)
        structured = assemble_program(raw, profile=PROFILE).canonical_bytes
        with self.assertRaises(ValueError):
            verify_program(structured)
        with source_tree() as root:
            selected = root / name
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.write_bytes(raw)
            with patch('hepta.hia_agent_assembly.assemble_program', wraps=assemble_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(raw,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), raw)
            selected.write_bytes(structured)
            with patch('hepta.hia_program.verify_program', wraps=verify_program) as calls:
                report = check(root)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['hia_source_files'], 1)
            self.assertEqual([call.args for call in calls.call_args_list], [(structured,)])
            self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
            self.assertEqual(selected.read_bytes(), structured)
            unregistered = root / 'examples' / 'unregistered_file_render.hepta'
            for content in (raw, structured):
                unregistered.write_bytes(content)
                with self.subTest(unregistered_format=content[:1]), self.assertRaisesRegex(
                        ValueError, 'invalid HIA source content: examples/unregistered_file_render'):
                    check(root)
                self.assertEqual(unregistered.read_bytes(), content)
                unregistered.unlink()
            broken = json.loads(structured)
            output = next(operation['out'][0]
                          for function in broken['functions']
                          for block in function['blocks']
                          for operation in block['ops'] if operation['out'])
            output['name'] = 'invalid value name'
            selected.write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                check(root)
            selected.unlink()
            selected.symlink_to(ROOT / name)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink'):
                check(root)
            selected.unlink()
            selected.write_bytes(raw)
            self.assertEqual(check(root)['hia_source_files'], 1)
            self.assertEqual(selected.read_bytes(), raw)



if __name__ == '__main__':
    unittest.main()
