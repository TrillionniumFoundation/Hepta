"""Source and physical-capture controls for the complete historical replay."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import types
import tempfile
import unittest
from unittest import mock

from tests import hia_service_describe_current_replay as replay

ROOT = Path(__file__).resolve().parents[1]


def imported_copy(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ServiceDescribeCurrentReplaySourceTests(unittest.TestCase):
    def copied_root(self, base, *, full_inputs=False):
        target = Path(base) / 'source'
        target.mkdir()
        names = (replay.SELF, replay.TEST, replay.CORPUS, 'pyproject.toml')
        if full_inputs:
            raw = (ROOT / 'tools/build_hia_service_discovery.py').read_bytes()
            tree = ast.parse(raw)
            declarations = [
                ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'INPUTS' for t in node.targets)
            ]
            self.assertEqual(len(declarations), 1)
            names = tuple(set(names) | set(declarations[0]))
        for name in names:
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        return target

    def test_all_complete_originals_keep_frozen_291_order(self):
        files = replay.corpus(ROOT)
        self.assertEqual(set(files), replay.HISTORICAL_PATHS)
        self.assertEqual(len(files), 13)
        with tempfile.TemporaryDirectory() as work:
            historical = Path(work) / 'history'
            self.assertEqual(replay.materialize(ROOT, historical), files)
            for name, raw in files.items():
                self.assertEqual((historical / name).read_bytes(), raw)
                self.assertEqual((historical / name).stat().st_mode & 0o777, 0o444)
            oracle = replay.load_oracle(historical)
            values = oracle.original_inputs()
            freeze = json.loads(files[
                'tests/fixtures/hia_service_describe_original_3424/freeze.json'])
            self.assertEqual(len(values), 291)
            self.assertEqual([case['id'] for case in values], freeze['ordered_ids'])
            self.assertEqual(len({case['id'] for case in values}), 291)

    def test_current_full_reference_and_thirteen_ports(self):
        relation = replay.check_current_relation(ROOT, replay.corpus(ROOT))
        self.assertEqual(relation['mode'], 1)
        self.assertEqual([row['original'] for row in relation['ports']],
                         list(replay.OLD_PORTS))
        self.assertEqual([row['current'] for row in relation['ports']],
                         list(replay.CURRENT_PORTS))
        self.assertEqual([row['number'] for row in relation['ports']], list(range(1, 14)))

    def test_all_original_fault_source_has_exact_roundtrip(self):
        original = replay.corpus(ROOT)[replay.FAULTS]
        projected, edits = replay.adapted_fault_source(original)
        restored = projected.decode()
        for edit in reversed(edits):
            self.assertEqual(restored.count(edit['new']), edit['count'])
            restored = restored.replace(edit['new'], edit['old'])
        self.assertEqual(restored.encode(), original)
        forward = original.decode()
        for edit in edits:
            self.assertEqual(forward.count(edit['old']), edit['count'])
            forward = forward.replace(edit['old'], edit['new'])
        self.assertEqual(forward.encode(), projected)
        namespace = {'__name__': 'fixed_describe_fault_source_control'}
        exec(compile(projected, '<complete-reviewed-describe-faults>', 'exec',
                     dont_inherit=True), namespace)
        self.assertEqual(len(namespace['MODE_PORTS']), 13)
        self.assertEqual(len(namespace['ERROR_TYPES']), 5)
        self.assertEqual(len(namespace['ABI_MUTATIONS']), 18)
        self.assertEqual(1 + 13 * 5 + 13 * 2 + 4 * 18 + 6, 170)

    def test_unknown_old_fault_bytes_are_rejected(self):
        old = replay.corpus(ROOT)[replay.FAULTS]
        with self.assertRaisesRegex(ValueError, 'complete fault source differs'):
            replay.adapted_fault_source(old + b'\n')

    def test_missing_selected_root_helper_does_not_use_ambient(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            (root / replay.SELF).unlink()
            with self.assertRaises(FileNotFoundError):
                replay.corpus(root)

    def test_missing_selected_fixture_does_not_use_ambient(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            (root / replay.CORPUS).unlink()
            with self.assertRaises(FileNotFoundError):
                replay.corpus(root)

    def test_changed_selected_root_helper_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            with (root / replay.SELF).open('ab') as stream:
                stream.write(b'\n# independent physical root change\n')
            with self.assertRaisesRegex(ValueError, 'executed source'):
                replay.corpus(root)

    def test_executed_module_changed_after_import_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            module = imported_copy(root / replay.SELF, 'describe_import_snapshot_control')
            self.assertEqual(module.corpus(root), replay.corpus(ROOT))
            with (root / replay.SELF).open('ab') as stream:
                stream.write(b'\n# changed after actual module import\n')
            with self.assertRaisesRegex(ValueError, 'executed source'):
                module.corpus(root)

    def test_changed_fixed_corpus_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            path = root / replay.CORPUS
            original = path.read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'complete Describe corpus differs'):
                replay.corpus(root)

    def test_corpus_late_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work)
            path = root / replay.CORPUS
            decompress = replay.gzip.decompress
            def late_change(raw):
                result = decompress(raw)
                path.write_bytes(path.read_bytes() + b'\n')
                return result
            with mock.patch.object(replay.gzip, 'decompress', side_effect=late_change):
                with self.assertRaisesRegex(ValueError, 'changed during capture'):
                    replay.corpus(root)

    def test_source_late_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work, full_inputs=True)
            before = replay.inputs(root)
            path = root / 'hepta/hia_service_discovery_protocol.py'
            path.write_bytes(path.read_bytes() + b'\n# physical late protocol change\n')
            with self.assertRaisesRegex(ValueError, 'inputs changed'):
                replay.verify_inputs(root, before)

    def test_complete_capture_binds_current_and_qualification_inputs(self):
        before = replay.inputs(ROOT)
        for name in (replay.SELF, replay.TEST, replay.CORPUS,
                     'examples/hia_bootstrap/service_discovery.hepta',
                     'hepta/hia_agent_service.py', 'hepta/hia_native_delivery.py'):
            self.assertEqual(before[name], replay.digest((ROOT / name).read_bytes()))
        replay.verify_inputs(ROOT, before)


    def test_real_foreign_preloaded_package_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as work:
            foreign = Path(work) / 'foreign'
            package = foreign / 'hepta'
            package.mkdir(parents=True)
            for name in ('__init__.py', 'hia_service_discovery_protocol.py'):
                shutil.copyfile(ROOT / 'hepta' / name, package / name)
            output = Path(work) / 'must-not-be-created'
            script = (
                'import importlib.util,pathlib,sys\n'
                'root=pathlib.Path(sys.argv[1]); foreign=pathlib.Path(sys.argv[2])\n'
                'spec=importlib.util.spec_from_file_location("replay",root/sys.argv[4])\n'
                'replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)\n'
                'sys.path.insert(0,str(foreign))\n'
                'import hepta.hia_service_discovery_protocol as protocol\n'
                'assert pathlib.Path(protocol.__file__).resolve().is_relative_to(foreign)\n'
                'try:replay.faults(root,pathlib.Path(sys.argv[3]),"never-opened-manifest")\n'
                'except ValueError as error:\n'
                ' assert "fresh process" in str(error),str(error)\n'
                'else:raise AssertionError("foreign preloaded candidate was accepted")\n'
                'assert not pathlib.Path(sys.argv[3]).exists()\n'
            )
            result = subprocess.run(
                [sys.executable, '-I', '-c', script, str(ROOT), str(foreign),
                 str(output), replay.SELF],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_unloaded_foreign_import_origin_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            foreign = Path(work) / 'foreign'
            package = foreign / 'hepta'
            package.mkdir(parents=True)
            shutil.copyfile(ROOT / 'hepta/__init__.py', package / '__init__.py')
            script = (
                'import importlib.util,pathlib,sys\n'
                'root=pathlib.Path(sys.argv[1]); foreign=pathlib.Path(sys.argv[2])\n'
                'spec=importlib.util.spec_from_file_location("replay",root/sys.argv[3])\n'
                'replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)\n'
                'sys.path.insert(0,str(foreign))\n'
                'assert "hepta" not in sys.modules\n'
                'try:replay.require_fresh_candidate(root)\n'
                'except ValueError as error:\n'
                ' assert "captured root" in str(error),str(error)\n'
                'else:raise AssertionError("foreign import origin was accepted")\n'
            )
            result = subprocess.run(
                [sys.executable, '-I', '-c', script, str(ROOT), str(foreign), replay.SELF],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_actual_loaded_module_must_remain_bound_to_capture(self):
        replay.check_current_relation(ROOT, replay.corpus(ROOT))
        before = replay.inputs(ROOT)
        replay.verify_loaded_candidate(ROOT, before)
        from hepta import hia_service_discovery_protocol as protocol
        with tempfile.TemporaryDirectory() as work:
            foreign = Path(work) / 'protocol.py'
            foreign.write_bytes(Path(protocol.__file__).read_bytes())
            with mock.patch.object(protocol, '__file__', str(foreign)):
                with self.assertRaisesRegex(ValueError, 'outside the captured root'):
                    replay.verify_loaded_candidate(ROOT, before)
        altered = dict(before)
        altered['hepta/hia_service_discovery_protocol.py'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'captured input bytes'):
            replay.verify_loaded_candidate(ROOT, altered)


    def test_checkout_marker_is_a_physical_captured_input(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.copied_root(work, full_inputs=True)
            before = replay.inputs(root)
            self.assertEqual(before['pyproject.toml'],
                             replay.digest((ROOT / 'pyproject.toml').read_bytes()))
            (root / 'pyproject.toml').unlink()
            with self.assertRaisesRegex(ValueError, 'captured source is not regular: pyproject.toml'):
                replay.verify_inputs(root, before)

    def test_equal_source_bytes_at_foreign_resource_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'service_discovery.hepta'
            path.write_bytes((ROOT / 'examples/hia_bootstrap/service_discovery.hepta').read_bytes())
            native = types.SimpleNamespace(SOURCE=path)
            with self.assertRaisesRegex(ValueError, 'resource path differs'):
                replay.selected_image(ROOT, 'vm', None, native)


if __name__ == '__main__':
    unittest.main()
