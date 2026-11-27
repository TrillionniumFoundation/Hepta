"""Source-only closure and dispatch controls for the explicit op13 adapter.

The separately bound Source context has no component manifests. These tests
do not construct an owner, generate/compile HIA, or invoke an import port.
Original Source10/Source8/CLI43/retained3 files and selectors are retained.
"""
from __future__ import annotations

import ast
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import unittest

from tests.hia_patch_cli_support import context


def identity(raw, mode='100644'):
    return {'bytes': len(raw), 'mode': mode, 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def authority(name):
    row = context()['authority_files'][name]
    path = Path(row['path'])
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != row['posix_mode']:
        raise AssertionError('bound Source authority mode differs: ' + name)
    raw = path.read_bytes()
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    if (identity(raw, row['pin']['mode']) != row['pin'] or
            tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields)):
        raise AssertionError('bound Source authority changed: ' + name)
    return raw


def functions(raw):
    text = raw.decode('utf-8')
    return {node.name: ast.get_source_segment(text, node)
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


class PatchCliSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = context()
        if cfg['phase'] != 'source':
            raise AssertionError('Source controls require an explicit non-Native context')
        cls.root = Path(cfg['source'])
        cls.expected = json.loads(authority('projected_source_map'))
        cls.r5 = json.loads(authority('r5_source_map'))
        cls.patch = json.loads(authority('patch14_map'))
        cls.matrix = json.loads(authority('control_matrix'))

    def test_complete_union_binds_every_added_file_without_worker_expansion(self):
        additions = set(self.expected) - set(self.r5)
        self.assertEqual(additions, set(self.patch) | {
            'hepta/hia_cli_patch_result_native.py', 'hepta/hia_patch_cli_records.py',
            'tests/hia_patch_cli_support.py', 'tests/test_hia_patch_cli_source.py',
            'tests/test_hia_patch_cli_native.py'})
        self.assertEqual(len(self.r5), 3191)
        self.assertEqual(len(self.patch), 14)
        self.assertEqual(len(self.expected), 3210)
        self.assertTrue(all(self.expected[name] == row for name, row in self.r5.items()))
        self.assertTrue(all(self.expected[name] == row for name, row in self.patch.items()))
        actual = {}
        def visit(directory, prefix=''):
            for item in sorted(os.scandir(directory), key=lambda value: value.name):
                info = item.stat(follow_symlinks=False)
                self.assertFalse(stat.S_ISLNK(info.st_mode))
                name = prefix + item.name
                if stat.S_ISDIR(info.st_mode):
                    visit(Path(item.path), name + '/')
                else:
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    mode = '100755' if stat.S_IMODE(info.st_mode) & 0o111 else '100644'
                    raw = Path(item.path).read_bytes()
                    self.assertEqual(len(raw), info.st_size)
                    after = os.stat(item.path, follow_symlinks=False)
                    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size',
                              'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
                    self.assertEqual(tuple(getattr(after, key) for key in fields),
                                     tuple(getattr(info, key) for key in fields))
                    actual[name] = identity(raw, mode)
        visit(self.root)
        self.assertEqual(actual, self.expected)
        # Default registries/worker closure are inherited unchanged through
        # the complete R5 map. New host files require this explicit outer map.

    def test_original_r5_operand_records_and_cli_bodies_are_exact(self):
        for name in ('hia_cli_native.py', 'hia_cli_inspect_native.py',
                     'hia_inspect_cli_operand.py', 'hia_inspect_cli_records.py'):
            relative = 'hepta/' + name
            raw = (self.root / relative).read_bytes()
            self.assertEqual(identity(raw), self.r5[relative])
        record = ast.parse((self.root / 'hepta/hia_inspect_cli_records.py').read_bytes())
        self.assertTrue(any(isinstance(node, ast.Import) and
            any(alias.name == 'copy' for alias in node.names) for node in record.body))
        operand = (self.root / 'hepta/hia_inspect_cli_operand.py').read_bytes()
        self.assertEqual(sha1(b'blob ' + str(len(operand)).encode() + b'\0' + operand).hexdigest(),
                         'e2738c9ea58362f31eaddd1e6ac194317e80e367')
        self.assertIn(b'co_positions', operand)
        original = authority('original_cli')
        self.assertEqual((self.root / 'hepta/hia_cli_native.py').read_bytes(), original)

    def test_original_patch_policy_and_selected_prepare_are_not_rewritten(self):
        original = authority('original_program_tools')
        current = (self.root / 'hepta/hia_program_tools.py').read_bytes()
        self.assertEqual(current, original)
        before, after = functions(original), functions(current)
        for name in ('apply_program_patch', '_check_patch_interface', '_prepare_program_patch'):
            self.assertEqual(after[name], before[name])
        for relative, pin in self.patch.items():
            self.assertEqual(identity((self.root / relative).read_bytes()), pin)
        policy = ast.parse(after['apply_program_patch'])
        self.assertEqual(sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'verify_program' for node in ast.walk(policy)), 2)

    def test_op13_call_keeps_provider_document_request_and_register_order(self):
        text = (self.root / 'hepta/hia_cli_patch_result_native.py').read_text()
        tree = ast.parse(text)
        effect = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef) and node.name == 'patch_effect')
        provider = next(node for node in effect.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'provider' for target in node.targets))
        self.assertEqual(ast.dump(provider.value, include_attributes=False),
            ast.dump(ast.parse("current.common['apply_program_patch']", mode='eval').body,
                     include_attributes=False))
        call = next(node for node in ast.walk(effect) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Name) and node.func.id == 'invoke_captured_patch')
        self.assertEqual(len(call.args), 6)
        self.assertEqual(ast.dump(call.args[-2], include_attributes=False),
                         ast.dump(ast.parse('value(a)', mode='eval').body, include_attributes=False))
        self.assertEqual(ast.dump(call.args[-1], include_attributes=False),
                         ast.dump(ast.parse('argument(b, 1)', mode='eval').body, include_attributes=False))
        self.assertEqual(ast.dump(effect.body[-1].value, include_attributes=False),
            ast.dump(ast.parse('(register(revised), register(receipt), 0)', mode='eval').body,
                     include_attributes=False))
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(effect)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == 'entry' for node in ast.walk(effect)))

    def test_opaque_tokens_reject_unknown_receipts_without_mapping(self):
        from hepta import hia_patch_cli_records as records
        serial, existing = records._NEXT_SERIAL, dict(records._RECORDS)
        with self.assertRaises(TypeError):
            records.PatchDefinitionRecord()
        fake = object.__new__(records.PatchDefinitionRecord)
        for value in (None, object(), {}, {'current': True}, fake):
            with self.subTest(type=type(value).__name__):
                self.assertIsNone(records._state(value))
                self.assertIsNone(records.selected_record(value))
        self.assertEqual(records._RECORDS, existing)
        self.assertEqual(records._NEXT_SERIAL, serial)

    def test_issuer_uses_actual_admission_and_closes_only_failed_new_owner(self):
        tree = ast.parse((self.root / 'hepta/hia_patch_cli_records.py').read_bytes())
        issue = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'issue_preselected_patch_record')
        self.assertEqual([arg.arg for arg in issue.args.args], ['absolute_manifest'])
        self.assertEqual([arg.arg for arg in issue.args.kwonlyargs], ['inspect_manifest'])
        admits = [node for node in ast.walk(issue) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == 'admit_patch_result']
        self.assertEqual(len(admits), 1)
        capture = [node for node in ast.walk(issue) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == 'capture_definitions']
        self.assertEqual(len(capture), 1)
        protected = issue.body[-1]
        self.assertIsInstance(protected, ast.Try)
        self.assertEqual(len(protected.handlers), 1)
        handler = protected.handlers[0]
        self.assertEqual(ast.dump(handler.type, include_attributes=False), "Name(id='BaseException', ctx=Load())")
        self.assertEqual(ast.dump(handler.body[0], include_attributes=False),
            ast.dump(ast.parse('_close_failed_admission(admission.owner)').body[0], include_attributes=False))
        self.assertIsInstance(handler.body[-1], ast.Raise)

    def test_original_observers_are_consumed_and_each_frame_is_reloaded(self):
        cfg = context()
        expected = {'retained_support': 'b65cdbd5be3890e7d4bb424504a2a7ff4e70a371',
                    'original_observer': 'f6d59fd0caef181064c5b77adca2b7e9216ac332'}
        for name, git_blob in expected.items():
            row = cfg[name]
            raw = Path(row['path']).read_bytes()
            self.assertEqual(identity(raw)['git_blob'], git_blob)
        source = (self.root / 'tests/hia_patch_cli_support.py').read_text()
        tree = ast.parse(source)
        close = next(node for cls in tree.body if isinstance(cls, ast.ClassDef)
            and cls.name == 'ActualPatchCli' for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name == 'close')
        getters = [node for node in ast.walk(close) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
                   and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 'buffers']
        self.assertEqual(len(getters), 2)
        self.assertFalse(any(isinstance(node, ast.Return) for node in ast.walk(close)))
        self.assertNotIn('validated', ast.get_source_segment(source, close))
        self.assertIn('self.base.close()', ast.get_source_segment(source, close))

    def test_exact_new_matrix_keeps_original_failure_and_limits(self):
        native = ast.parse((self.root / 'tests/test_hia_patch_cli_native.py').read_bytes())
        declared = ['tests.test_hia_patch_cli_native.PatchCliNativeTests.' + node.name
            for cls in native.body if isinstance(cls, ast.ClassDef) and cls.name == 'PatchCliNativeTests'
            for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
        self.assertEqual(declared, [row['id'] for row in self.matrix['native_groups']])
        self.assertEqual(len(declared), 12)
        self.assertEqual([row['signature_native'] for row in self.matrix['native_groups']],
                         [False] * 9 + [True, False, False])
        self.assertEqual(self.matrix['limits'], {'owner_seconds': 180, 'cleanup_seconds': 3,
            'compile_seconds': 20, 'native_capacity': 1048576,
            'vm_steps': 10000000, 'vm_heap': 8388608, 'vm_call_depth': 128})
        self.assertEqual(self.matrix['retained_r5_witness10'], 'FAIL_UNCHANGED_NOT_REQUALIFIED')
        self.assertFalse(self.matrix['apply_contract_proposal'])
        self.assertFalse(self.matrix['default_selection_changed'])
        self.assertFalse(self.matrix['current_cold'])


if __name__ == '__main__':
    unittest.main()
