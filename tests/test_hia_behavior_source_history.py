"""Actual current-source custody and complete predecessor preparation controls."""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import hia_behavior_source_history as history

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def isolated():
    with tempfile.TemporaryDirectory(prefix='behavior-history-control-') as name:
        root = Path(name) / 'root'
        root.mkdir()
        fixture = json.loads((ROOT / history.FIXTURE).read_bytes())
        for name in [history.SELF, history.FIXTURE, *fixture['stage_files']]:
            source, target = ROOT / name, root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        yield root, fixture


class BehaviorSourceHistoryTests(unittest.TestCase):
    def test_complete_old_and_current_whole_files_are_distinct(self):
        view, proof = history.prepare(ROOT)
        fixture = json.loads((ROOT / history.FIXTURE).read_bytes())
        self.assertEqual(proof['scope'], 'EXPLICIT_PREDECESSOR_446_PORT_9_METHOD_DOMAIN')
        for name, item in fixture['entries'].items():
            current, old = history._whole(item['current']), history._whole(item['old'])
            self.assertEqual((ROOT / name).read_bytes(), current)
            self.assertNotEqual(current, old)
            if old is None:
                self.assertNotIn(name, view)
            else:
                self.assertEqual(view[name], old)
                self.assertEqual(proof['prior_take'](ROOT / name), old)
        history.verify_unchanged(proof)

    def test_each_unknown_or_partially_reverted_group_member_is_refused(self):
        with isolated() as (root, fixture):
            for name, item in fixture['entries'].items():
                path = root / name
                before = path.read_bytes()
                with self.subTest(name=name, kind='unknown'):
                    path.write_bytes(before + b'\n')
                    with self.assertRaises(ValueError):
                        history.prepare(root)
                path.write_bytes(before)
                old = history._whole(item['old'])
                if old is not None:
                    with self.subTest(name=name, kind='partial-predecessor'):
                        path.write_bytes(old)
                        with self.assertRaises(ValueError):
                            history.prepare(root)
                    path.write_bytes(before)

    def test_missing_corrupt_or_rebound_fixture_and_reader_are_refused(self):
        with isolated() as (root, _):
            for name in (history.FIXTURE, history.SELF):
                path=root/name;raw=path.read_bytes()
                with self.subTest(name=name, kind='corrupt'):
                    path.write_bytes(raw+b'\n')
                    with self.assertRaises(ValueError):
                        history.prepare(root)
                path.write_bytes(raw)
                with self.subTest(name=name, kind='missing'):
                    path.unlink()
                    with self.assertRaises(FileNotFoundError):
                        history.prepare(root)
                path.write_bytes(raw)

    def test_supplied_and_callback_bytes_cannot_impersonate_physical_source(self):
        with isolated() as (root, fixture):
            name=next(iter(fixture['entries']))
            current=(root/name).read_bytes()
            with self.assertRaises(ValueError):
                history.prepare(root,{name:b'not actual bytes'})
            (root/name).write_bytes(current+b'\n')
            def take(path):
                return current if path==root/name else path.read_bytes()
            with self.assertRaises(ValueError):
                history.prepare(root,take=take)

    def test_each_actual_capture_is_reread_before_prior_handoff(self):
        with isolated() as (root, fixture):
            for name in fixture['entries']:
                _, proof=history.prepare(root)
                path=root/name;before=path.read_bytes()
                path.write_bytes(before+b'\n')
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        proof['prior_take'](path)
                    with self.assertRaises(ValueError):
                        history.verify_unchanged(proof)
                path.write_bytes(before)

    def test_actual_and_projected_late_changes_both_refuse_finalization(self):
        with isolated() as (root, fixture):
            name=next(name for name,row in fixture['entries'].items() if row['old'] is not None)
            with self.assertRaises(ValueError):
                with history.original_view(root,root.parent/'view-one') as (view, report, proof):
                    path=view/name;path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaises(ValueError):
                with history.original_view(root,root.parent/'view-two') as (view, report, proof):
                    path=root/name;path.write_bytes(path.read_bytes()+b'\n')

    def test_explicit_root_no_ambient_read_and_path_escape_refused(self):
        with isolated() as (root, _):
            seen=[]
            def take(path):
                self.assertTrue(path.is_relative_to(root))
                seen.append(path)
                return path.read_bytes()
            view, proof=history.prepare(root,take=take)
            self.assertGreater(len(seen),400)
            with self.assertRaises(ValueError):
                proof['prior_take'](root/'..'/'escape')
            with self.assertRaises(FileNotFoundError):
                proof['prior_take'](root/'not-in-closed-inventory')
            self.assertEqual(set(view),set(proof['view']))
            history.verify_unchanged(proof)
