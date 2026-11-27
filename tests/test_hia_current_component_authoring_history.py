"""Independent physical roots for current builder source-history composition."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from tests import hia_component_authoring_history as history
from tools import hia_frozen_component_sources as engine

ROOT = Path(__file__).resolve().parents[1]


class CurrentComponentAuthoringHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = set(history.CURRENT_INPUTS)
        names.update(spec['fixture'] for spec in history.CURRENT_INPUTS.values())
        names.update((history.FIXTURE, history.ENGINE))
        cls.files = {name: (ROOT / name).read_bytes() for name in names}
        cls.prior = {}
        for name, spec in history.CURRENT_INPUTS.items():
            raw = cls.files[name]
            if history._pin(raw) != spec['current']:
                raise ValueError('current builder source does not match its complete identity')
            row = json.loads(cls.files[spec['fixture']])['files'][name]
            cls.prior[name] = engine.history_inverse(raw, row,
                {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-current-component-authoring-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, raw in self.files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

    def test_all_six_current_builders_compose_the_unchanged_original_authoring_relation(self):
        for name in history.CURRENT_INPUTS:
            with self.subTest(path=name):
                actual = history.predecessor(name, self.files[name], root=self.root)
                prior = history.predecessor(name, self.prior[name], root=self.root)
                self.assertEqual(actual, prior)
                self.assertEqual((self.root / name).read_bytes(), self.files[name])

    def test_missing_or_changed_current_authorities_are_not_replaced_by_global_files(self):
        for name, spec in history.CURRENT_INPUTS.items():
            for selected in (name, spec['fixture'], history.ENGINE):
                path = self.root / selected
                for missing in (False, True):
                    with self.subTest(path=name, authority=selected, missing=missing):
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(self.files[selected] + b'\n')
                        try:
                            with self.assertRaises((ValueError, OSError)):
                                history.predecessor(name, self.files[name], root=self.root)
                        finally:
                            path.write_bytes(self.files[selected])

    def test_current_physical_inputs_are_reread_after_the_original_reader_returns(self):
        for name, spec in history.CURRENT_INPUTS.items():
            for selected in (name, spec['fixture'], history.ENGINE):
                late = [False]
                def take(path):
                    raw = path.read_bytes()
                    if path == self.root / history.FIXTURE:
                        late[0] = True
                    if late[0] and path == self.root / selected:
                        return raw + b'\n'
                    return raw
                with self.subTest(path=name, authority=selected):
                    with self.assertRaises(ValueError):
                        history.predecessor(name, self.files[name], root=self.root, take=take)

    def test_prior_domains_read_only_their_original_fixed_authority(self):
        with tempfile.TemporaryDirectory(prefix='hia-prior-component-authoring-') as folder:
            root = Path(folder)
            target = root / history.FIXTURE
            target.parent.mkdir(parents=True)
            target.write_bytes(self.files[history.FIXTURE])
            for name in history.CURRENT_INPUTS:
                reads = []
                def take(path):
                    reads.append(path)
                    return path.read_bytes()
                history.predecessor(name, self.prior[name], root=root, take=take)
                self.assertEqual(set(reads), {target})

    def test_unknown_whole_file_and_forged_fixture_cannot_borrow_current_admission(self):
        for name, spec in history.CURRENT_INPUTS.items():
            with self.subTest(path=name):
                raw = self.files[name] + b'\n'
                self.assertEqual(history.predecessor(name, raw, root=self.root), raw)
                path = self.root / spec['fixture']
                value = json.loads(self.files[spec['fixture']])
                value['historical_projection_is_physical_source'] = True
                path.write_text(json.dumps(value))
                try:
                    with self.assertRaises(ValueError):
                        history.predecessor(name, self.files[name], root=self.root)
                finally:
                    path.write_bytes(self.files[spec['fixture']])


if __name__ == '__main__':
    unittest.main()
