"""Finite source/IO controls: synthetic originals only, no network or product.

The 460-file positive fixture exercises the real unchanged ZIP reader and
new custody mover. It is labelled SYNTHETIC and cannot qualify the historical
artifact or resolve the interrupted local R4 owner's state.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from hashlib import sha256
import ast
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import time
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('new_diagnostic_controller_source_only', ROOT / 'candidate/controller.py')
D = load('unchanged_original_diagnostics_source_only', ROOT / 'candidate/diagnostics.py')
H = load('unchanged_original_receiver_source_only', ROOT / 'candidate/original_receiver.py')
W = load('new_diagnostic_worker_source_only', ROOT / 'candidate/worker.py')
OLD = load('old_recovery_bug_oracle_source_only', ROOT / 'reference/remote-r1/controller.py')
POLICY = json.loads((ROOT / 'candidate/policy.json').read_bytes())


def save(path, raw):
    path = Path(path)
    if isinstance(raw, dict):
        raw = C.wire(raw)
    C.create(path, raw)


def rewrite(path, raw):
    """Controlled fixture damage, never used against any original artifact."""
    if isinstance(raw, dict):
        raw = C.wire(raw)
    os.chmod(path, 0o600)
    path.write_bytes(raw)
    os.chmod(path, 0o400)


def body_fixture(base, *, selected_count=9, selected_bytes=None, corrupt_unselected=False):
    base.mkdir(mode=0o700)
    root, public = base / 'private', base / 'public'
    root.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    for child in ('control', 'original'):
        (root / child).mkdir(mode=0o700)
    for child in ('small', 'small/originals', 'small/controls'):
        (public / child).mkdir(mode=0o700)
    raw = (ROOT / 'candidate/diagnostics.py').read_bytes()
    save(root / 'control/diagnostics.py', raw)
    missing = POLICY['expected_diagnostics']['missing_expected']
    available = [name for name in D.EXPECTED if name not in missing]
    assert len(available) == 7 and selected_count >= 7
    names = available + [D.PREFIX + 'synthetic/case-%04d.json' % index
                         for index in range(selected_count - len(available))]
    bodies = {name: ('SYNTHETIC_DIAGNOSTIC_ONLY:%04d\n' % index).encode()
              for index, name in enumerate(names)}
    if selected_bytes is not None:
        deficit = selected_bytes - sum(map(len, bodies.values()))
        assert deficit >= 0
        bodies[names[-1]] += b'x' * deficit
    bodies['unselected/source.bin'] = b'SYNTHETIC_NONSELECTED_SOURCE_BODY\n'
    bodies['unselected/image.bin'] = b'SYNTHETIC_NONSELECTED_IMAGE_BODY\n'
    original = root / 'original/fixture.zip'
    with zipfile.ZipFile(original, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name, body in bodies.items():
            info = zipfile.ZipInfo(name, (2026, 11, 13, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o400) << 16
            archive.writestr(info, body)
    if corrupt_unselected:
        with zipfile.ZipFile(original) as archive:
            info = archive.getinfo('unselected/image.bin')
            offset = info.header_offset
        damaged = bytearray(original.read_bytes())
        length, extra = struct.unpack_from('<HH', damaged, offset + 26)
        damaged[offset + 30 + length + extra] ^= 1
        original.write_bytes(damaged)
    os.chmod(original, 0o400)
    original_raw = original.read_bytes()
    pin = {**POLICY['artifact'], 'bytes': len(original_raw), 'sha256': sha256(original_raw).hexdigest(),
           'synthetic_source_control_only': True}
    policy = copy.deepcopy(POLICY)
    policy['artifact'] = pin
    policy['expected_diagnostics'] = {
        'members': len(bodies), 'expanded_bytes': sum(map(len, bodies.values())),
        'selected_count': len(names), 'selected_bytes': sum(len(bodies[n]) for n in names),
        'missing_expected': missing, 'metadata_files': 3}
    return {'base': base, 'root': root, 'public': public, 'original': original,
            'pin': pin, 'policy': policy, 'bodies': bodies, 'selected_names': names}


def inspect(fixture):
    record = D.inspect_zip(fixture['original'], fixture['pin'], fixture['root'],
                           time.monotonic_ns() + 20_000_000_000, H, D.LIMITS)
    fixture['report'] = {'diagnostics': record}
    fixture['index'] = json.loads((fixture['root'] / 'diagnostics/INDEX.json').read_bytes())
    return fixture


def capture(fixture):
    return C.retain_diagnostics(fixture['root'], fixture['public'], fixture['policy'], fixture.get('report'))


class DiagnosticCustodySourceIOTests(unittest.TestCase):
    def case(self, suffix=''):
        assert OUTPUT is not None
        return Path(OUTPUT) / (self._testMethodName + suffix)

    def test_01_all460_originals_three_lists_and_missing5_relocate_exactly(self):
        fixture = inspect(body_fixture(self.case(), selected_count=460, selected_bytes=3012789))
        root, public, index = fixture['root'], fixture['public'], fixture['index']
        self.assertEqual(index['missing_expected'], POLICY['expected_diagnostics']['missing_expected'])
        self.assertFalse(index['expected_originals_all_present'])
        self.assertTrue(index['all_members_fully_read'])
        self.assertEqual(index['members'], 462)
        names = sorted(p.name for p in (root / 'diagnostics').iterdir())
        self.assertEqual(len(names), 463)
        before = {name: C.file_record(root / 'diagnostics' / name, 64 << 20) for name in names}
        original_zip = C.file_record(fixture['original'])
        # The original actual bug is demonstrated against a real diagnostic
        # file, before calling the corrected mover. The old source is unmodified.
        sample = next(n for n in names if n.startswith('member-'))
        with self.assertRaisesRegex(OLD.Refusal, 'only a fixed private slice'):
            OLD.relocate_slice(root / 'diagnostics' / sample,
                               public / 'small/originals' / sample, before[sample])
        result = capture(fixture)
        self.assertTrue(result['complete'])
        self.assertEqual(result['status'], 'AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION')
        self.assertEqual(result['selected_count'], 460)
        self.assertEqual(result['selected_bytes'], 3012789)
        self.assertEqual(result['missing_expected'], POLICY['expected_diagnostics']['missing_expected'])
        self.assertFalse(result['original_failure_reclassified'])
        self.assertFalse(result['qualification_executed'])
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(result['files']), 463)
        self.assertEqual({row['name'] for row in result['files']}, set(names))
        self.assertEqual(list((root / 'diagnostics').iterdir()), [])
        for row in result['files']:
            source, target = before[row['name']], row['retained']
            self.assertEqual(row['original'], source)
            self.assertEqual(target, C.file_record(public / 'small/originals' / row['name'], 64 << 20))
            self.assertEqual((source['bytes'], source['sha256']), (target['bytes'], target['sha256']))
            self.assertEqual(source['identity'][:2], target['identity'][:2])
            self.assertEqual(target['identity'][5], 1)
            self.assertEqual(stat.S_IMODE(target['identity'][2]), 0o400)
            self.assertTrue(row['accepted_complete_original'])
            self.assertFalse(row['partial_not_promoted'])
        for row in index['selected']:
            self.assertEqual((public / 'small/originals' / row['retained_name']).read_bytes(), fixture['bodies'][row['name']])
        self.assertEqual(C.file_record(fixture['original']), original_zip)
        self.assertFalse((root / 'parts').exists())
        self.assertFalse(any(p.name.startswith('part-') for p in public.iterdir()))

    def test_02_missing_report_claim_is_rejected_but_all_real_bytes_survive(self):
        fixture = inspect(body_fixture(self.case()))
        index_path = fixture['root'] / 'diagnostics/INDEX.json'
        index = fixture['index']
        index['missing_expected'] = []
        index['expected_originals_all_present'] = True
        rewrite(index_path, index)
        fixture['report']['diagnostics'] = H.read_file_hash(index_path)
        result = capture(fixture)
        self.assertFalse(result['complete'])
        self.assertEqual(result['status'], 'HOLD')
        self.assertEqual(len(result['files']), 12)
        self.assertTrue(any(e['refusal'] == 'original missing report inventory is inaccurate' for e in result['errors']))
        self.assertTrue(all(row['partial_not_promoted'] for row in result['files']))
        self.assertFalse(result['original_failure_reclassified'])

    def test_03_changed_selected_body_is_preserved_without_acceptance(self):
        fixture = inspect(body_fixture(self.case()))
        row = fixture['index']['selected'][0]
        path = fixture['root'] / 'diagnostics' / row['retained_name']
        replacement = b'SYNTHETIC_CHANGED_ACTUAL_BYTES\n'
        rewrite(path, replacement)
        result = capture(fixture)
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['files']), 12)
        self.assertEqual((fixture['public'] / 'small/originals' / row['retained_name']).read_bytes(), replacement)
        self.assertTrue(all(row['partial_not_promoted'] for row in result['files']))
        self.assertTrue(result['errors'])

    def test_04_truncated_inventory_is_preserved_as_a_whole_hold_original(self):
        fixture = inspect(body_fixture(self.case()))
        path = fixture['root'] / 'diagnostics/FULL-INVENTORY.jsonl'
        partial = path.read_bytes()[:-1]
        rewrite(path, partial)
        result = capture(fixture)
        self.assertFalse(result['complete'])
        self.assertEqual((fixture['public'] / 'small/originals/FULL-INVENTORY.jsonl').read_bytes(), partial)
        self.assertEqual(len(result['files']), 12)
        self.assertTrue(any(e['refusal'] == 'complete original metadata final newline missing' for e in result['errors']))

    def test_05_duplicate_inventory_rows_cannot_be_folded_into_acceptance(self):
        fixture = inspect(body_fixture(self.case()))
        path = fixture['root'] / 'diagnostics/FULL-INVENTORY.jsonl'
        rows = path.read_bytes().splitlines(keepends=True)
        rows[1] = rows[0]
        rewrite(path, b''.join(rows))
        result = capture(fixture)
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['files']), 12)
        self.assertTrue(result['errors'])

    def test_06_namespace_links_and_existing_targets_refuse_without_overwrite(self):
        for variant in ('traversal', 'unapproved', 'leaf_symlink', 'hardlink', 'source_dir_symlink',
                        'target_dir_symlink', 'occupied', 'wrong_record_path'):
            with self.subTest(variant=variant):
                fixture = inspect(body_fixture(self.case('-' + variant), selected_count=7))
                root, public = fixture['root'], fixture['public']
                name = fixture['index']['selected'][0]['retained_name']
                source = root / 'diagnostics' / name
                target = public / 'small/originals' / name
                expected = C.file_record(source)
                if variant == 'traversal':
                    name = '../' + name
                elif variant == 'unapproved':
                    name = 'part-00.bin'
                elif variant == 'leaf_symlink':
                    preserved = source.with_name('preserved-original.bin')
                    source.rename(preserved)
                    source.symlink_to(preserved)
                elif variant == 'hardlink':
                    os.link(source, root / 'second-name.bin')
                elif variant == 'source_dir_symlink':
                    source.parent.rename(root / 'original-diagnostics')
                    (root / 'diagnostics').symlink_to(root / 'original-diagnostics', target_is_directory=True)
                elif variant == 'target_dir_symlink':
                    target.parent.rename(public / 'small/preserved-originals')
                    target.parent.symlink_to(public / 'small/preserved-originals', target_is_directory=True)
                elif variant == 'occupied':
                    save(target, b'EXISTING_TARGET_MUST_NOT_CHANGE')
                else:
                    expected['path'] = str(root / 'different' / name)
                with self.assertRaises((C.Refusal, OSError)):
                    C.relocate_diagnostic(root, public, name, expected)
                if variant == 'occupied':
                    self.assertEqual(target.read_bytes(), b'EXISTING_TARGET_MUST_NOT_CHANGE')
                elif variant != 'target_dir_symlink':
                    self.assertFalse(target.exists())

    def test_07_interrupted_link_unlink_preserves_two_names_and_never_returns_pin(self):
        fixture = inspect(body_fixture(self.case()))
        root, public = fixture['root'], fixture['public']
        name = fixture['index']['selected'][0]['retained_name']
        source = root / 'diagnostics' / name
        expected = C.file_record(source)
        original_error = OSError(5, 'synthetic unlink error')
        with mock.patch.object(C.os, 'unlink', side_effect=original_error):
            with self.assertRaises(OSError) as caught:
                C.relocate_diagnostic(root, public, name, expected)
        self.assertIs(caught.exception, original_error)
        target = public / 'small/originals' / name
        self.assertEqual(source.read_bytes(), target.read_bytes())
        self.assertEqual(source.stat().st_ino, target.stat().st_ino)
        self.assertEqual(source.stat().st_nlink, 2)
        with self.assertRaises(C.Refusal):
            C.file_record(source)
        with self.assertRaises(C.Refusal):
            C.file_record(target)

    def test_08_unselected_corrupt_zip_body_is_read_and_refused(self):
        fixture = body_fixture(self.case(), corrupt_unselected=True)
        with self.assertRaises(zipfile.BadZipFile):
            inspect(fixture)
        index = json.loads((fixture['root'] / 'diagnostics/INDEX.json').read_bytes())
        self.assertEqual(index['status'], 'HOLD')
        self.assertFalse(index['all_members_fully_read'])
        self.assertFalse(index['complete_selection_of_available_originals'])
        self.assertEqual(index['errors'][0]['type'], 'BadZipFile')
        self.assertTrue(fixture['original'].exists())

    def guardian_fixture(self, *, closed=True, wrong_command=False):
        fixture = inspect(body_fixture(self.case(), selected_count=7))
        root, public = fixture['root'], fixture['public']
        # finalize must create the new public root itself, so remove only these
        # newly created empty synthetic directories. No existing output is reset.
        (public / 'small/originals').rmdir()
        (public / 'small/controls').rmdir()
        (public / 'small').rmdir()
        public.rmdir()
        (root / 'guard').mkdir(mode=0o700)
        policy = copy.deepcopy(POLICY)
        context = {'control_sources': {}, 'policy_sha256': sha256(C.wire(policy)).hexdigest(),
                   'python': {'resolved': str(root / 'synthetic-interpreter.bin'),
                              'binary': {'sha256': sha256(b'NOT_EXECUTABLE').hexdigest()}}}
        save(root / 'synthetic-interpreter.bin', b'NOT_EXECUTABLE')
        command = [context['python']['resolved'], '-I', '-S', '-B', str(root / 'control/worker.py'),
                   '--root', str(root), '--policy-sha256', context['policy_sha256']]
        setup = {'schema': 'hia.actions.v92-ci-diagnostics-only-setup.v2',
                 'status': 'PREPARED_NOT_EXECUTED', 'context': context, 'command': command,
                 'controller_seconds': 900, 'cleanup_seconds': 3,
                 'source_identities': C.expected_setup_identities(context, policy, root)}
        request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
                   'command': command, 'cwd': str(root), 'source_identities': setup['source_identities']}
        request_raw = C.wire(request)
        setup['guardian_config_sha256'] = sha256(request_raw).hexdigest()
        save(root / 'guard/request.json', request_raw)
        save(root / 'setup.json', setup)
        save(root / 'context.json', context)
        life = {'schema': 'hepta.hia.external-qualification-guardian.v1.lifecycle',
                'subreaper_enabled': True, 'qualification_started': True,
                'qualification_seconds': 900, 'cleanup_seconds': 3,
                'status': 'QUALIFICATION_FAILED', 'returncode': 1,
                'cleanup': {'attempted': True, 'complete': closed, 'observed_echild': closed,
                            'leader_reaped': closed, 'deadline_exceeded': False,
                            'errors': [], 'remaining_direct_children': [] if closed else [424242]}}
        guardian = {'schema': 'hepta.hia.external-qualification-guardian.v1', 'status': 'HOLD',
                    'command': ['WRONG'] if wrong_command else command, 'cwd': str(root),
                    'external_controller_seconds': 900, 'cold_180_second_gate_modified': False,
                    'lifecycle_implementation_sha256': policy['control_files']['process_owner_impl.py']['sha256'],
                    'source_identities_before': setup['source_identities'], 'lifecycle': life}
        save(root / 'guard/guardian.json', guardian)
        for name in ('guard/child.stdout.log', 'guard/child.stderr.log',
                     'supervisor.stdout.log', 'supervisor.stderr.log'):
            save(root / name, b'SYNTHETIC_CLOSED_FAILURE_LOG\n')
        save(root / 'recovery-terminal.json', {'status': 'DIAGNOSTIC_CUSTODY_HOLD', 'synthetic': True})
        return fixture, policy, context

    def test_09_unknown_owner_never_reads_or_enumerates_child_outputs(self):
        fixture, policy, context = self.guardian_fixture(closed=False)
        root, public = fixture['root'], fixture['public']
        allowed = {root / 'setup.json', root / 'guard/request.json', root / 'guard/guardian.json'}
        original_read, original_record = C.read, C.file_record
        calls = []
        def guarded_read(path, *args, **kwargs):
            path = Path(path)
            self.assertTrue(path in allowed or path.is_relative_to(public), str(path))
            calls.append(str(path))
            return original_read(path, *args, **kwargs)
        def guarded_record(path, *args, **kwargs):
            self.assertTrue(Path(path).is_relative_to(public), str(path))
            return original_record(path, *args, **kwargs)
        with mock.patch.object(C, 'policy_and_context', return_value=(None, policy, None, root, public, context)), \
             mock.patch.object(C, 'read', side_effect=guarded_read), \
             mock.patch.object(C, 'file_record', side_effect=guarded_record), \
             mock.patch.object(C, 'retain_diagnostics', side_effect=AssertionError('child read prohibited')), \
             mock.patch.object(C, 'closed_storage_observation', side_effect=AssertionError('child walk prohibited')), \
             redirect_stdout(io.StringIO()):
            code = C.finalize(types.SimpleNamespace())
        self.assertEqual(code, 1)
        result = json.loads((public / 'small/FINAL.json').read_bytes())
        self.assertEqual(result['status'], 'DIAGNOSTIC_CUSTODY_HOLD')
        self.assertFalse(result['complete_local_diagnostic_readback'])
        self.assertNotIn('closed_echild', result)
        self.assertNotIn('diagnostic_capture', result)
        self.assertEqual(len(list((root / 'diagnostics').iterdir())), 10)

    def test_10_closed_nonzero_preserves_child_originals_and_cannot_pass(self):
        fixture, policy, context = self.guardian_fixture(closed=True)
        root, public = fixture['root'], fixture['public']
        with mock.patch.object(C, 'policy_and_context', return_value=(None, policy, None, root, public, context)), \
             redirect_stdout(io.StringIO()):
            code = C.finalize(types.SimpleNamespace())
        self.assertEqual(code, 1)
        result = json.loads((public / 'small/FINAL.json').read_bytes())
        self.assertTrue(result['closed_echild'])
        self.assertEqual(result['status'], 'DIAGNOSTIC_CUSTODY_HOLD')
        self.assertFalse(result['complete_local_diagnostic_readback'])
        self.assertEqual(len(result['diagnostic_capture']['files']), 10)
        self.assertTrue(any(row['name'] == 'guard/child.stdout.log' for row in result['small_controls']))
        self.assertEqual((public / 'small/controls/guard--child.stdout.log').read_bytes(), b'SYNTHETIC_CLOSED_FAILURE_LOG\n')
        self.assertTrue(any(e['stage'] == 'NATURAL_GUARDIAN' for e in result['errors']))
        self.assertEqual(result['old_local_R4_owner_status'], 'UNKNOWN_NOT_RECLASSIFIED')

    def test_11_wrong_operation_guardian_is_not_a_closed_read_boundary(self):
        fixture, policy, context = self.guardian_fixture(closed=True, wrong_command=True)
        root, public = fixture['root'], fixture['public']
        with mock.patch.object(C, 'policy_and_context', return_value=(None, policy, None, root, public, context)), \
             mock.patch.object(C, 'retain_diagnostics', side_effect=AssertionError('foreign ECHILD cannot authorize read')), \
             redirect_stdout(io.StringIO()):
            code = C.finalize(types.SimpleNamespace())
        self.assertEqual(code, 1)
        result = json.loads((public / 'small/FINAL.json').read_bytes())
        self.assertNotIn('closed_echild', result)
        self.assertNotIn('diagnostic_capture', result)
        self.assertEqual(len(list((root / 'diagnostics').iterdir())), 10)

    def test_12_fixed_policy_network_and_original_reader_projection(self):
        old = json.loads((ROOT / 'reference/remote-r1/policy.json').read_bytes())
        self.assertEqual(POLICY['limits'], old['limits'])
        self.assertEqual(POLICY['diagnostics'], old['diagnostics'])
        self.assertEqual(POLICY['artifact'], old['artifact'])
        self.assertEqual(POLICY['source'], old['source'])
        self.assertEqual(POLICY['unchanged_original_workflows'], old['unchanged_original_workflows'])
        self.assertEqual(C.fixed_policy(POLICY), POLICY['artifact'])
        self.assertEqual(W.fixed_policy(POLICY), POLICY['artifact'])
        for key, replacement in (('parts', [{'ordinal': 0}]), ('partition_files_created', True),
                                 ('expected_diagnostics', {**POLICY['expected_diagnostics'], 'selected_count': 459})):
            with self.subTest(key=key):
                invalid = copy.deepcopy(POLICY)
                invalid[key] = replacement
                with self.assertRaises(C.Refusal):
                    C.fixed_policy(invalid)
                with self.assertRaises(W.Refusal):
                    W.fixed_policy(invalid)
        def bodies(path):
            raw = path.read_text()
            lines = raw.splitlines(keepends=True)
            return {n.name: ''.join(lines[n.lineno - 1:n.end_lineno]) for n in ast.parse(raw).body
                    if isinstance(n, ast.FunctionDef)}
        for file, names in (
                ('worker.py', ('new_client', 'deadline_check', 'api_request', 'bounded_response',
                               'metadata', 'official_location', 'storage_download')),
                ('controller.py', ('closed_guardian', 'natural_guardian', 'run', 'copy_original', 'final_input_records'))):
            old_functions, new_functions = bodies(ROOT / 'reference/remote-r1' / file), bodies(ROOT / 'candidate' / file)
            for name in names:
                self.assertEqual(new_functions[name], old_functions[name])
        for file in ('diagnostics.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py'):
            self.assertEqual((ROOT / 'candidate' / file).read_bytes(), (ROOT / 'reference/remote-r1' / file).read_bytes())
        self.assertNotIn('split_original', bodies(ROOT / 'candidate/worker.py'))
        self.assertNotIn('relocate_slice', bodies(ROOT / 'candidate/controller.py'))
        template = (ROOT / 'candidate/workflow-template.yml').read_text()
        self.assertEqual(template.count('uses: actions/upload-artifact@'), 1)
        self.assertNotIn('UPLOAD_STEPS_PENDING_ACTUAL_COUNT', template)
        self.assertNotIn('original-part-', template)


EXPECTED_IDS = [
    'DiagnosticCustodySourceIOTests.' + name for name in (
        'test_01_all460_originals_three_lists_and_missing5_relocate_exactly',
        'test_02_missing_report_claim_is_rejected_but_all_real_bytes_survive',
        'test_03_changed_selected_body_is_preserved_without_acceptance',
        'test_04_truncated_inventory_is_preserved_as_a_whole_hold_original',
        'test_05_duplicate_inventory_rows_cannot_be_folded_into_acceptance',
        'test_06_namespace_links_and_existing_targets_refuse_without_overwrite',
        'test_07_interrupted_link_unlink_preserves_two_names_and_never_returns_pin',
        'test_08_unselected_corrupt_zip_body_is_read_and_refused',
        'test_09_unknown_owner_never_reads_or_enumerates_child_outputs',
        'test_10_closed_nonzero_preserves_child_originals_and_cannot_pass',
        'test_11_wrong_operation_guardian_is_not_a_closed_read_boundary',
        'test_12_fixed_policy_network_and_original_reader_projection')]
