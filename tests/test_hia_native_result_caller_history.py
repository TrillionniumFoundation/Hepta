"""Independent root, mutation and whole-file refusals for one language revision."""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from tools import hia_native_result_caller_history as history

ROOT = Path(__file__).resolve().parents[1]


class NativeResultCallerHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-result-history-')
        self.root = Path(self.temporary.name)
        self.fixture = (ROOT / history.FIXTURE).read_bytes()
        raw = (ROOT / history.PATH).read_bytes()
        old = history.unwrap(ROOT, history.PATH, raw)
        self.old = old
        # The location is itself fixed data, never a search-and-replace escape.
        import json
        at = json.loads(self.fixture)['splices'][0]['at']
        self.new = old[:at] + b'6' + old[at + 1:]
        self.assertEqual(history._pin(self.old), history.ORIGINAL)
        self.assertEqual(history._pin(self.new), history.CURRENT)
        for name, data in ((history.PATH, self.new), (history.FIXTURE, self.fixture)):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_successor_restores_the_exact_complete_predecessor(self):
        self.assertEqual(history.unwrap(self.root, history.PATH, self.new), self.old)

    def test_exact_predecessor_stays_exact(self):
        (self.root / history.PATH).write_bytes(self.old)
        self.assertEqual(history.unwrap(self.root, history.PATH, self.old), self.old)

    def test_independent_root_does_not_borrow_the_module_fixture(self):
        for content in (None, b'{}'):
            with self.subTest(content=content):
                p = self.root / history.FIXTURE
                if p.exists():
                    p.unlink()
                if content is not None:
                    p.write_bytes(content)
                with self.assertRaises((OSError, ValueError)):
                    history.unwrap(self.root, history.PATH, self.new)

    def test_unknown_whole_file_and_same_size_drift_are_refused(self):
        for raw in (self.new + b'\n', b'X' + self.new[1:]):
            with self.subTest(digest=sha256(raw).hexdigest()):
                (self.root / history.PATH).write_bytes(raw)
                with self.assertRaises(ValueError):
                    history.unwrap(self.root, history.PATH, raw)

    def test_caller_cannot_substitute_unread_current_bytes_for_physical_predecessor(self):
        (self.root / history.PATH).write_bytes(self.old)
        with self.assertRaises(ValueError):
            history.unwrap(self.root, history.PATH, self.new)

    def test_other_names_and_traversal_receive_no_source_exception(self):
        for name in ('tests/test_hia_agent_assembly.py', '../' + history.PATH, '', False):
            with self.subTest(name=name), self.assertRaises(ValueError):
                history.unwrap(self.root, name, self.new)

    def test_explicit_capture_reads_both_files_twice_from_the_given_root(self):
        paths = []
        def take(path):
            paths.append(path)
            return path.read_bytes()
        self.assertEqual(history.unwrap(self.root, history.PATH, self.new, take=take), self.old)
        self.assertEqual(paths, [self.root / history.PATH, self.root / history.FIXTURE,
                                 self.root / history.FIXTURE, self.root / history.PATH])

    def test_fixture_mutation_after_initial_capture_is_refused(self):
        count = 0
        def take(path):
            nonlocal count
            raw = path.read_bytes()
            if path == self.root / history.FIXTURE:
                count += 1
                if count == 1:
                    path.write_bytes(b'{}')
            return raw
        with self.assertRaises(ValueError):
            history.unwrap(self.root, history.PATH, self.new, take=take)

    def test_source_mutation_after_initial_capture_is_refused(self):
        count = 0
        def take(path):
            nonlocal count
            raw = path.read_bytes()
            if path == self.root / history.PATH:
                count += 1
                if count == 1:
                    path.write_bytes(self.old)
            return raw
        with self.assertRaises(ValueError):
            history.unwrap(self.root, history.PATH, self.new, take=take)


if __name__ == '__main__':
    unittest.main()
