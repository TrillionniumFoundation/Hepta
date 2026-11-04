"""Independent finite-binding and original-error regressions, not hostile-runtime isolation."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from experiments.loader_budget import prototype as reader
from experiments.request_load.context import Context, Limits, Rejected as LegacyRejected
from .owner import Owner, Policy, Rejected


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def test_callback_malformed_policy_drift_prevents_first_read(self):
        owner = None
        def checkpoint():
            object.__setattr__(owner.context.policy, 'limits', None)
        owner = Owner(Policy(), checkpoint=checkpoint)
        with self.assertRaises(Rejected) as caught:
            owner.load(self.entry)
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertEqual(owner.context.reader.reads, 0)
        self.assertEqual(owner._handles, [])

    def test_replaced_mapping_proxy_never_enters_foreign_mapping(self):
        class ForeignMapping:
            def __getitem__(self, key):
                raise AssertionError('foreign lookup')
            def __iter__(self):
                raise AssertionError('foreign iteration')
            def __len__(self):
                raise AssertionError('foreign length')
        for field in ('limits', 'units'):
            with self.subTest(field=field):
                owner = Owner(Policy())
                object.__setattr__(owner.context.policy, field, MappingProxyType(ForeignMapping()))
                with self.assertRaises(Rejected) as caught:
                    owner.load(self.entry)
                self.assertEqual(caught.exception.failure.category, 'policy_drift')
                self.assertEqual(owner.context.reader.reads, 0)

    def test_source_oserror_preserves_original_diagnostic_and_io_origin(self):
        owner = Owner()
        with patch.object(reader.os, 'open', side_effect=OSError('source unavailable')):
            with self.assertRaises(HeptaError) as caught:
                owner.load(self.entry)
        self.assertEqual(caught.exception.diagnostic.code, 'E_MODULE_READ')
        first = owner.context.failure
        self.assertEqual((first.category, first.phase), ('io', 'read'))
        with self.assertRaises(Rejected) as later:
            owner.load(self.entry)
        self.assertIs(later.exception.failure, first)

    def test_package_revalidation_inventory_io_false_is_terminal(self):
        (self.root / 'hepta.toml').write_text(
            '[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        owner = Owner()
        handle = owner.load(self.entry)
        with patch.object(reader.os, 'scandir', side_effect=OSError('inventory unavailable')):
            self.assertFalse(handle.unchanged())
        first = owner.context.failure
        self.assertEqual((first.category, first.phase), ('io', 'inventory'))
        self.assertTrue(owner.context.closed)
        with self.assertRaises(Rejected) as later:
            handle.unchanged()
        self.assertIs(later.exception.failure, first)

    def test_replaced_reader_checkpoint_rejected_before_callback(self):
        owner = Owner()
        owner.context.reader.checkpoint = lambda: self.fail('replacement callback executed')
        with self.assertRaises(Rejected) as caught:
            owner.load(self.entry)
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertEqual(owner.context.reader.reads, 0)

    def test_legacy_rejected_source_encodes_once(self):
        calls = []
        class Source(str):
            def encode(self, *args, **kwargs):
                calls.append(1)
                return super().encode(*args, **kwargs)
        context = Context(Limits(source=1))
        with self.assertRaises(LegacyRejected):
            context.tokenize(Source('long'))
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
