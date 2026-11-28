"""Physical carrier preparation controls without importing product code."""
from __future__ import annotations
import base64
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
import zlib

from tools import hia_bootstrap_carrier_predecessor as carrier
from tools import hia_bootstrap_source_history as history
from tools import hia_behavior_source_history as behavior

ROOT = Path(__file__).resolve().parents[1]


class BootstrapCarrierPredecessorTests(unittest.TestCase):
    def stage(self):
        _, _, actual = history.capture(ROOT)
        temporary = TemporaryDirectory(prefix='hia-bootstrap-carrier-control-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        for name, raw in actual.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
            p.chmod(stat.S_IMODE((ROOT / name).stat().st_mode))
        history.unchanged(ROOT, actual)
        return root

    def test_actual_group_and_complete_private_predecessor_remain_distinct(self):
        observed = []
        def take(path):
            raw = path.read_bytes()
            observed.append((path, raw))
            return raw
        with self.assertRaisesRegex(ValueError, 'unknown or partially reverted'):
            behavior.prepare(ROOT)
        view, admitted = carrier.prepare(ROOT, take=take)
        proof = admitted['preparation']
        self.assertEqual(carrier.identity(admitted['captures'][carrier.SOURCE][0]), carrier.CURRENT)
        self.assertEqual(proof['prepared_v7_physical'][carrier.SOURCE],
                         {**carrier.PRIOR, 'mode': admitted['captures'][carrier.SOURCE][1]})
        self.assertNotEqual(view[carrier.SOURCE], admitted['captures'][carrier.SOURCE][0])
        original = json.loads((ROOT / carrier.BEHAVIOR_FIXTURE).read_bytes())
        old = original['entries'][carrier.SOURCE]['old']
        self.assertEqual(sha256(view[carrier.SOURCE]).hexdigest(), old['sha256'])
        self.assertEqual(history.identity(view[history.SOURCE]), history.LIVE_CURRENT)
        self.assertEqual(admitted['entries'], tuple(original['entries']))
        self.assertEqual(len(admitted['entries']), 12)
        self.assertTrue(proof['complete_fixed_v7_group_admitted'])
        self.assertTrue(proof['private_view_terminal_verified'])
        self.assertFalse(proof['current_semantics_qualified'])
        self.assertFalse(proof['whole_native_stack_qualified'])
        self.assertTrue(all(path.is_relative_to(ROOT) and path.read_bytes() == raw
                            for path, raw in observed))
        self.assertFalse(set(carrier.RELATED_INPUTS) - set(admitted['captures']))
        carrier.verify_unchanged(admitted)

    def test_fixed_readers_fixtures_and_related_sources_are_required(self):
        root = self.stage()
        names = (carrier.SELF, carrier.FIXTURE, carrier.BEHAVIOR_READER,
                 carrier.BEHAVIOR_FIXTURE, carrier.BASE_READER,
                 'hepta/hia_cell_frame.py',
                 'examples/hia_bootstrap/carrier_cell_policy.hepta')
        for name in names:
            path = root / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            try:
                path.unlink()
                with self.subTest(name=name, action='missing'), self.assertRaises((ValueError, FileNotFoundError)):
                    carrier.prepare(root)
                path.write_bytes(raw)
                path.chmod(mode)
                if name in (carrier.SELF, carrier.FIXTURE, carrier.BEHAVIOR_READER,
                            carrier.BEHAVIOR_FIXTURE):
                    path.write_bytes(raw + b'\n')
                    with self.subTest(name=name, action='changed'), self.assertRaises(ValueError):
                        carrier.prepare(root)
            finally:
                path.write_bytes(raw)
                path.chmod(mode)
        carrier.prepare(root)

    def test_unknown_and_other_legal_domains_are_not_accepted_as_carrier(self):
        root = self.stage()
        path = root / carrier.SOURCE
        raw = path.read_bytes()
        relation = json.loads((root / carrier.FIXTURE).read_bytes())
        previous = carrier._record(raw, relation['record'])
        for offset in (0, len(raw) // 2, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] ^= 1
            path.write_bytes(changed)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'unreviewed'):
                carrier.prepare(root)
        path.write_bytes(previous)
        with self.assertRaisesRegex(ValueError, 'unreviewed'):
            carrier.prepare(root)
        path.write_bytes(raw)
        carrier.prepare(root)

    def test_complete_whole_inverse_and_original_v7_fixture_are_fixed(self):
        raw = (ROOT / carrier.FIXTURE).read_bytes()
        relation = json.loads(raw)
        self.assertEqual(carrier.identity(raw), carrier.FIXTURE_PIN)
        self.assertEqual(len(relation['record']['hunks']), 2)
        physical = (ROOT / carrier.SOURCE).read_bytes()
        prior = carrier._record(physical, relation['record'])
        v7 = (ROOT / carrier.BEHAVIOR_FIXTURE).read_bytes()
        self.assertEqual(carrier.identity(v7), carrier.BEHAVIOR_FIXTURE_PIN)
        old = json.loads(v7)['entries'][carrier.SOURCE]['current']
        self.assertEqual(prior, zlib.decompress(base64.b64decode(old['zlib_base64'], validate=True)))
        self.assertEqual(carrier.identity(prior), carrier.PRIOR)
        for position in ('old_offset', 'new_offset', 'old_hex', 'new_hex'):
            changed = json.loads(raw)
            hunk = changed['record']['hunks'][0]
            hunk[position] = hunk[position] + 1 if position.endswith('offset') else hunk[position] + '00'
            with self.subTest(position=position), self.assertRaises(ValueError):
                carrier._record(physical, changed['record'])
        self.assertEqual(carrier.identity((ROOT / carrier.BEHAVIOR_READER).read_bytes()), carrier.BEHAVIOR_READER_PIN)

    def test_actual_late_bytes_modes_and_cached_take_cannot_rebind_capture(self):
        root = self.stage()
        view, admitted = carrier.prepare(root)
        names = (carrier.SOURCE, carrier.SELF, carrier.FIXTURE, carrier.BEHAVIOR_READER,
                 carrier.BEHAVIOR_FIXTURE, 'hepta/hia_service_artifact_native.py',
                 'hepta/hia_native_helpers.py', 'hepta/hia_cell_frame.py',
                 'examples/hia_bootstrap/carrier_cell_policy.hepta')
        for name in names:
            path = root / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            try:
                path.write_bytes(raw + b'\n')
                with self.subTest(name=name, action='bytes'), self.assertRaises(ValueError):
                    carrier.verify_unchanged(admitted)
                path.write_bytes(raw)
                path.chmod(mode ^ 0o100)
                with self.subTest(name=name, action='mode'), self.assertRaises(ValueError):
                    carrier.verify_unchanged(admitted)
            finally:
                path.write_bytes(raw)
                path.chmod(mode)
        cached = {name: raw for name, (raw, mode) in admitted['captures'].items()}
        _, captured = carrier.prepare(root, take=lambda path: cached[path.relative_to(root).as_posix()])
        path = root / carrier.SOURCE
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b'\n')
            with self.assertRaises(ValueError):
                carrier.verify_unchanged(captured)
        finally:
            path.write_bytes(raw)
        carrier.verify_unchanged(admitted)

    def test_import_snapshot_cannot_be_refreshed_before_first_prepare(self):
        root = self.stage()
        spec = importlib.util.spec_from_file_location('bootstrap_carrier_import_control', root / carrier.SELF)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        path = root / carrier.SELF
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b'\n# after import\n')
            with self.assertRaisesRegex(ValueError, 'after import'):
                module.prepare(root)
        finally:
            path.write_bytes(raw)
        _, admitted = module.prepare(root)
        try:
            path.write_bytes(raw + b'\n# after complete preparation\n')
            with self.assertRaisesRegex(ValueError, 'after import'):
                module.verify_unchanged(admitted)
        finally:
            path.write_bytes(raw)
        module.verify_unchanged(admitted)

    def test_actual_mutation_after_complete_inner_v7_admission_is_refused(self):
        root = self.stage()
        original = behavior.prepare
        names = (carrier.SOURCE, 'hepta/hia_service_artifact_native.py',
                 'hepta/hia_native_helpers.py', 'hepta/hia_cell_frame.py')
        for name in names:
            path = root / name
            raw = path.read_bytes()
            reached = []
            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                reached.append(args[0])
                path.write_bytes(raw + b'\n')
                return result
            try:
                with self.subTest(name=name), mock.patch.object(behavior, 'prepare', changed), self.assertRaises(ValueError):
                    carrier.prepare(root)
                self.assertEqual(len(reached), 1)
                self.assertNotEqual(reached[0], root)
                self.assertFalse(reached[0].exists())
            finally:
                path.write_bytes(raw)
        carrier.prepare(root)

    def test_private_view_late_bytes_mode_and_link_changes_are_refused(self):
        root = self.stage()
        original = behavior.prepare
        for action in ('bytes', 'mode', 'symlink'):
            reached = []
            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                reached.append(args[0])
                path = args[0] / carrier.SOURCE
                if action == 'bytes':
                    path.write_bytes(path.read_bytes() + b'\n')
                elif action == 'mode':
                    path.chmod(stat.S_IMODE(path.stat().st_mode) ^ 0o100)
                else:
                    other = path.with_name('private-copy.py')
                    path.rename(other)
                    path.symlink_to(other.name)
                return result
            with self.subTest(action=action), mock.patch.object(behavior, 'prepare', changed), self.assertRaises(ValueError):
                carrier.prepare(root)
            self.assertEqual(len(reached), 1)
            self.assertFalse(reached[0].exists())
        carrier.prepare(root)

    def test_take_cannot_change_physical_bytes_during_initial_capture(self):
        root = self.stage()
        path = root / carrier.SOURCE
        raw = path.read_bytes()
        hit = []
        def take(p):
            value = p.read_bytes()
            if p == path and not hit:
                hit.append(True)
                p.write_bytes(raw + b'\n')
            return value
        try:
            with self.assertRaises(ValueError):
                carrier.prepare(root, take=take)
            self.assertEqual(hit, [True])
        finally:
            path.write_bytes(raw)

    def test_returned_actual_and_prior_inventories_cannot_be_truncated_or_swapped(self):
        root = self.stage()
        view, admitted = carrier.prepare(root)
        for name in (carrier.SELF, carrier.SOURCE, carrier.FIXTURE, 'hepta/hia_cell_frame.py'):
            row = admitted['captures'].pop(name)
            try:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    carrier.verify_unchanged(admitted)
            finally:
                admitted['captures'][name] = row
        prior = admitted['view'].pop(history.SOURCE)
        try:
            with self.assertRaises(ValueError):
                carrier.verify_unchanged(admitted)
        finally:
            admitted['view'][history.SOURCE] = prior
        admitted['root'] = ROOT
        try:
            with self.assertRaises(ValueError):
                carrier.verify_unchanged(admitted)
        finally:
            admitted['root'] = root
        with self.assertRaises(ValueError):
            carrier.verify_unchanged(dict(admitted))
        carrier.verify_unchanged(admitted)
        self.assertEqual(admitted['prior_take'](root / history.SOURCE), prior)
        with self.assertRaises(ValueError):
            admitted['prior_take'](root / '../outside.py')

    def test_complete_old_v7_domain_does_not_require_new_carrier_authority(self):
        root = self.stage()
        relation = json.loads((root / carrier.FIXTURE).read_bytes())
        path = root / carrier.SOURCE
        path.write_bytes(carrier._record(path.read_bytes(), relation['record']))
        (root / carrier.SELF).unlink()
        (root / carrier.FIXTURE).unlink()
        original, proof, saved = history.capture(root)
        self.assertEqual(history.identity(original), history.HISTORICAL)
        self.assertNotIn(carrier.SELF, saved)
        self.assertNotIn(carrier.FIXTURE, saved)
        self.assertNotIn('physical_predecessor_preparation', proof['current_source_preparation'])
        history.unchanged(root, saved)

    def test_preparation_is_data_only_in_a_fresh_import_blocked_process(self):
        code = (
            "import sys,importlib.abc,json\n"
            "from pathlib import Path\n"
            "class Block(importlib.abc.MetaPathFinder):\n"
            " def find_spec(self,name,path=None,target=None):\n"
            "  if name.split('.')[0] in ('hepta','tests'): raise RuntimeError('product import: '+name)\n"
            "sys.meta_path.insert(0,Block())\n"
            "sys.path.insert(0," + repr(str(ROOT)) + ")\n"
            "from tools import hia_bootstrap_carrier_predecessor as c\n"
            "view,h=c.prepare(Path(" + repr(str(ROOT)) + "))\n"
            "c.verify_unchanged(h)\n"
            "assert not any(n.split('.')[0] in ('hepta','tests') for n in sys.modules)\n"
            "print(json.dumps({'complete':True,'entries':len(h['entries']),'captured':len(h['captures'])}))\n"
        )
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        value = json.loads(result.stdout)
        self.assertTrue(value['complete'])
        self.assertEqual(value['entries'], 12)
        self.assertGreater(value['captured'], 500)


if __name__ == '__main__':
    unittest.main()
