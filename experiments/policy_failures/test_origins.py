from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from experiments.loader_budget import prototype as reader
from experiments.package_copy import owner as package
from .owner import Owner, Policy, Rejected, Cancelled

TEXT = 'fn main()->Unit effects {} {}'


class OriginTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.entry = Path(tmp.name) / 'main.hepta'
        self.entry.write_text(TEXT)

    def test_read_stat_role_vs_aggregate_and_tie(self):
        for changes, dimension in (({'source': 1}, 'source'),
                                   ({'total_bytes': 1}, 'total_bytes'),
                                   ({'source': 1, 'total_bytes': 1}, 'total_bytes')):
            with self.subTest(changes=changes):
                owner = Owner(Policy(limits=changes))
                with self.assertRaises(Rejected):
                    owner.context.read(self.entry, 'source')
                f = owner.context.failure
                self.assertEqual((f.category, f.dimension, f.limit, f.admitted, f.attempted),
                                 ('budget', dimension, 1, 0, len(TEXT)))
                self.assertEqual((f.observed_bytes, f.observed_reads), (0, 1))

    def test_overflow_sentinel_is_observed_not_admitted(self):
        owner = Owner(Policy(limits={'source': len(TEXT)}))
        real = reader.os.read
        def grow(fd, size):
            return b'x' * size
        with patch.object(reader.os, 'read', grow):
            with self.assertRaises(Rejected):
                owner.context.read(self.entry, 'source')
        f = owner.context.failure
        self.assertEqual((f.dimension, f.limit, f.admitted, f.attempted),
                         ('source', len(TEXT), 0, len(TEXT) + 1))
        self.assertEqual(f.observed_bytes, len(TEXT) + 1)

    def test_exhausted_read_does_not_open(self):
        owner = Owner(Policy(limits={'reads': 1}))
        owner.context.read(self.entry, 'source')
        with patch.object(reader.os, 'open', side_effect=AssertionError('opened')):
            with self.assertRaises(Rejected):
                owner.context.read(self.entry, 'source')
        f = owner.context.failure
        self.assertEqual((f.dimension, f.limit, f.admitted, f.attempted), ('reads', 1, 1, 2))
        self.assertEqual((f.observed_bytes, f.observed_reads), (len(TEXT), 1))

    def test_first_budget_survives_close_io_and_lock_releases(self):
        owner = Owner(Policy(limits={'source': 1}))
        close = reader.os.close
        def failing_close(fd):
            close(fd)
            raise OSError('close failure')
        with patch.object(reader.os, 'close', failing_close):
            with self.assertRaisesRegex(OSError, 'close failure'):
                owner.context.read(self.entry, 'source')
        first = owner.context.failure
        self.assertEqual((first.category, first.dimension), ('budget', 'source'))
        self.assertTrue(owner.context.reader._active.acquire(False))
        owner.context.reader._active.release()
        with self.assertRaises(Rejected) as caught:
            owner.load(self.entry)
        self.assertIs(caught.exception.failure, first)

    def test_reader_io_origin_not_boundary_diagnostic(self):
        owner = Owner()
        with patch.object(reader.os, 'open', side_effect=OSError('open failure')):
            with self.assertRaises(OSError):
                owner.context.read(self.entry, 'source')
        self.assertEqual((owner.context.failure.category, owner.context.failure.phase), ('io', 'read'))

    def test_checkpoint_exception_categories_preserve_identity(self):
        for error, expected in ((Cancelled(), 'cancelled'), (KeyboardInterrupt(), 'interrupted'),
                                (SystemExit(), 'unexpected'), (ValueError(), 'unexpected'),
                                (TimeoutError(), 'unexpected'), (OSError(), 'unexpected'),
                                (MemoryError(), 'memory'), (RecursionError(), 'recursion')):
            with self.subTest(error=type(error)):
                def checkpoint():
                    raise error
                owner = Owner(checkpoint=checkpoint)
                with self.assertRaises(type(error)) as caught:
                    owner.load(self.entry)
                self.assertIs(caught.exception, error)
                f = owner.context.failure
                self.assertEqual((f.category, f.phase), (expected, 'checkpoint'))
                self.assertEqual((f.observed_bytes, f.observed_reads), (0, 0))
                with self.assertRaises(Rejected) as terminal:
                    owner.load(self.entry)
                self.assertIs(terminal.exception.failure, f)

    def test_unsupported_runtime_before_callback_and_fspath(self):
        class Entry:
            def __fspath__(self):
                raise AssertionError('path converted')
        with patch.object(package, '_SUPPORTED', False):
            with self.assertRaises(Rejected) as caught:
                Owner(checkpoint=lambda: self.fail('checkpoint invoked')).load(Entry())
        self.assertEqual(caught.exception.failure.category, 'unsupported_runtime')
        self.assertEqual(caught.exception.failure.observed_reads, 0)

    def test_wrong_thread_origin(self):
        owner = Owner()
        errors = []
        def run():
            try:
                owner.load(self.entry)
            except BaseException as e:
                errors.append(e)
        thread = threading.Thread(target=run)
        thread.start(); thread.join()
        self.assertEqual(len(errors), 1)
        self.assertEqual(owner.context.failure.category, 'thread')

    def test_package_schema_and_hook_have_distinct_origins(self):
        owner = Owner()
        with self.assertRaises(Rejected):
            package._preflight(object(), owner.context)
        self.assertEqual(owner.context.failure.category, 'schema')
        owner = Owner()
        with patch.object(package.copy, 'deepcopy', lambda value: value):
            with self.assertRaises(Rejected):
                package._hooks(owner.context)
        self.assertEqual(owner.context.failure.category, 'replacement_hook')

    def test_equal_depth_limits_keep_origin(self):
        for dimension in ('directory_depth', 'json_depth', 'parser_depth', 'module_depth', 'package_depth'):
            owner = Owner()
            with self.assertRaises(Rejected):
                owner.context.depth(2, 1, dimension=dimension)
            self.assertEqual(owner.context.failure.dimension, dimension)

    def test_foreign_drift_does_not_execute_protocols(self):
        class Foreign:
            def __iter__(self):
                raise AssertionError('iterated foreign policy')
            def __eq__(self, other):
                raise AssertionError('compared foreign policy')
        for target in ('limits', 'reader', 'policy', 'boolean', 'checkpoint', 'observer'):
            owner = Owner(Policy(limits={'source': 1}))
            if target == 'limits':
                owner.context.limits = Foreign()
            elif target == 'reader':
                owner.context.reader.limits = Foreign()
            elif target == 'policy':
                owner.context.policy.__dict__['limits'] = Foreign()
            elif target == 'boolean':
                owner.context.limits.__dict__['source'] = True
            elif target == 'checkpoint':
                owner.context.checkpoint = lambda: None
            else:
                owner.context.reader.on_failure = None
            with self.assertRaises(Rejected):
                owner.load(self.entry)
            self.assertEqual(owner.context.failure.category, 'policy_drift')
            self.assertEqual(owner.context.reader.reads, 0)

    def test_path_io_false_revalidation_retains_origin(self):
        owner = Owner()
        handle = owner.load(self.entry)
        with patch.object(Path, 'resolve', side_effect=OSError('resolve failure')):
            self.assertFalse(handle.unchanged())
        self.assertTrue(owner.context.closed)
        self.assertEqual(owner.context.failure.category, 'io')
        with self.assertRaises(Rejected):
            handle.unchanged()

    def test_lazy_inventory_io_retains_origin(self):
        owner = Owner()
        with patch.object(reader.os, 'scandir', side_effect=OSError('scan failure')):
            with self.assertRaises(OSError):
                list(owner._ops.inventory(self.entry.parent))
        self.assertEqual((owner.context.failure.category, owner.context.failure.phase),
                         ('io', 'inventory'))

    def test_growth_after_admitted_chunks_records_progress(self):
        size = 65536
        self.entry.write_bytes(b'x' * (size + 1))
        owner = Owner(Policy(limits={'source': size + 1}))
        with patch.object(reader.os, 'read', side_effect=[b'x' * size, b'xx']):
            with self.assertRaises(Rejected):
                owner.context.read(self.entry, 'source')
        f = owner.context.failure
        self.assertEqual((f.admitted, f.attempted, f.observed_bytes), (size, size + 2, size + 2))

    def test_strictest_previous_role_owns_effective_cap(self):
        for operation in ('read', 'digest'):
            with self.subTest(operation=operation):
                self.entry.write_bytes(b'x')
                owner = Owner(Policy(limits={'source': 1}))
                owner.context.read(self.entry, 'source')
                self.entry.write_bytes(b'xx')
                with self.assertRaises(Rejected):
                    getattr(owner.context, operation)(self.entry, 'header')
                f = owner.context.failure
                self.assertEqual((f.dimension, f.limit, f.attempted), ('source', 1, 2))

    def test_partial_path_is_schema_not_budget(self):
        path = Path('/partial')
        path.parts
        delattr(path, package._SLOT_NAMES[0])
        owner = Owner()
        with self.assertRaises(Rejected):
            package._slot(path, package._SLOT_NAMES[0], owner.context)
        self.assertEqual(owner.context.failure.category, 'schema')


if __name__ == '__main__':
    unittest.main()