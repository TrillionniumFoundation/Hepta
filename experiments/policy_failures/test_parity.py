from pathlib import Path
import tempfile
import unittest

from hepta import packages
from hepta.ast import HeptaError
from experiments.package_copy.owner import Owner as PreviousOwner
from .owner import Owner, Rejected


class ParityTests(unittest.TestCase):
    def test_all_80_examples_match_previous_profile(self):
        graphs = diagnostics = 0
        paths = sorted(Path('examples').rglob('*.hepta'))
        self.assertEqual(len(paths), 80)
        for path in paths:
            with self.subTest(path=str(path)):
                previous, owner = PreviousOwner(), Owner()
                try:
                    expected = previous.load(path)
                except HeptaError as old:
                    with self.assertRaises(HeptaError) as new:
                        owner.load(path)
                    self.assertEqual(new.exception.diagnostic.to_dict(), old.diagnostic.to_dict())
                    self.assertEqual(owner.context.failure.category,
                                     'io' if old.diagnostic.code == 'E_MODULE_READ' else 'diagnostic')
                    first = owner.context.failure
                    with self.assertRaises(Rejected) as terminal:
                        owner.load(path)
                    self.assertIs(terminal.exception.failure, first)
                    diagnostics += 1
                else:
                    actual = owner.load(path)
                    self.assertEqual(actual.project.report(), expected.project.report())
                    self.assertEqual(actual.project.program, expected.project.program)
                    self.assertEqual(actual.project.source_bytes, expected.project.source_bytes)
                    self.assertTrue(expected.unchanged())
                    self.assertTrue(actual.unchanged())
                    self.assertIsNone(owner.context.failure)
                    self.assertEqual(owner.context.counts, previous.context.counts)
                    self.assertEqual(owner.context.reader.bytes_read, previous.context.reader.bytes_read)
                    self.assertEqual(owner.context.reader.reads, previous.context.reader.reads)
                    graphs += 1
        self.assertEqual((graphs, diagnostics), (68, 12))

    def test_real_locked_package_stale_diagnostic_and_inventory_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = root / 'main.hepta'
            entry.write_text('fn main()->Unit effects {} {}')
            (root / 'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
            packages.write_lock(root)
            previous, owner = PreviousOwner(), Owner()
            old, new = previous.load(entry, locked=True), owner.load(entry, locked=True)
            self.assertEqual(old.project.report(), new.project.report())
            (root / 'Hepta.lock').write_text('broken')
            self.assertTrue(new.unchanged())  # No late lock authentication claim.
            (root / 'extra.hepta').write_text('fn extra()->Unit effects {} {}')
            self.assertFalse(old.unchanged())
            self.assertFalse(new.unchanged())
            self.assertIsNone(owner.context.failure)  # Changed inventory is a normal False.
            packages.write_lock(root)
            entry.write_text(entry.read_text() + '\n')
            previous, owner = PreviousOwner(), Owner()
            with self.assertRaises(HeptaError) as expected:
                previous.load(entry, locked=True)
            with self.assertRaises(HeptaError) as actual:
                owner.load(entry, locked=True)
            self.assertEqual(actual.exception.diagnostic.to_dict(), expected.exception.diagnostic.to_dict())
            self.assertEqual(actual.exception.diagnostic.code, 'E_LOCK_STALE')
            self.assertEqual(owner.context.failure.category, 'diagnostic')


if __name__ == '__main__':
    unittest.main()
