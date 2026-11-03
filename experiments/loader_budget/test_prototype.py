import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .prototype import Limits, Reader, Rejected


class ReaderTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'source'
        self.path.write_bytes(b'12345678')

    def reader(self, **kwargs):
        return Reader(Limits(**{'per_file': 8, 'total_bytes': 16,
                               'reads': 3, 'chunk_bytes': 3, **kwargs}))

    def test_exact_boundary_and_empty_file(self):
        reader = self.reader()
        self.assertEqual(reader.read(self.path), b'12345678')
        self.path.write_bytes(b'')
        self.assertEqual(reader.read(self.path), b'')
        self.assertEqual((reader.bytes_read, reader.reads), (8, 2))

    def test_oversize_rejected_before_byte_read(self):
        reader = self.reader(per_file=7)
        with patch('os.read', side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(Rejected, 'quota'):
                reader.read(self.path)
        self.assertTrue(reader.closed)
        self.assertEqual(reader.bytes_read, 0)

    def test_repeated_reads_are_charged(self):
        reader = self.reader(total_bytes=15)
        reader.read(self.path)
        with self.assertRaisesRegex(Rejected, 'aggregate'):
            reader.read(self.path)
        self.assertEqual(reader.reads, 2)

    def test_invocation_quota_includes_empty_reads(self):
        self.path.write_bytes(b'')
        reader = self.reader(reads=1)
        reader.read(self.path)
        with self.assertRaisesRegex(Rejected, 'invocation'):
            reader.read(self.path)

    def test_digest_uses_same_budget(self):
        reader = self.reader()
        self.assertEqual(reader.digest(self.path), hashlib.sha256(b'12345678').hexdigest())
        self.assertEqual(reader.bytes_read, 8)

    def test_growth_after_fstat_is_bounded(self):
        reader = self.reader()
        original = os.fstat
        def grow(fd):
            result = original(fd)
            with self.path.open('ab') as stream:
                stream.write(b'x' * 1000)
            return result
        with patch('os.fstat', grow):
            with self.assertRaisesRegex(Rejected, 'grew'):
                reader.read(self.path)
        self.assertEqual(reader.bytes_read, 9)
        self.assertTrue(reader.closed)

    def test_aggregate_sentinel_is_at_most_one_byte(self):
        reader = self.reader(total_bytes=8)
        reader.read(self.path)
        self.path.write_bytes(b'')
        original = os.fstat
        def grow(fd):
            result = original(fd)
            self.path.write_bytes(b'x' * 1000)
            return result
        with patch('os.fstat', grow):
            with self.assertRaises(Rejected):
                reader.read(self.path)
        self.assertEqual(reader.bytes_read, 9)

    def test_path_replacement_cannot_change_opened_object(self):
        reader = self.reader()
        original = os.fstat
        def replace(fd):
            replacement = self.path.with_suffix('.new')
            replacement.write_bytes(b'x' * 1000)
            replacement.replace(self.path)
            return original(fd)
        with patch('os.fstat', replace):
            self.assertEqual(reader.read(self.path), b'12345678')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_fifo_rejected_without_waiting_for_writer(self):
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaisesRegex(Rejected, 'regular'):
            self.reader().read(self.path)

    def test_deadline_exception_closes_descriptor_and_reader(self):
        reader = self.reader()
        calls = 0
        def checkpoint():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise TimeoutError('expired')
        reader.checkpoint = checkpoint
        close = os.close
        with patch('os.close', wraps=close) as closed:
            with self.assertRaises(TimeoutError):
                reader.read(self.path)
            closed.assert_called_once()
        with self.assertRaisesRegex(Rejected, 'terminal'):
            reader.read(self.path)

    def test_failed_open_is_terminal(self):
        self.path.unlink()
        reader = self.reader()
        with self.assertRaises(FileNotFoundError):
            reader.read(self.path)
        self.assertTrue(reader.closed)

    def test_invalid_limits(self):
        for field in ('per_file', 'total_bytes', 'reads', 'chunk_bytes'):
            for value in (0, -1, True, 1.5):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        Limits(**{field: value})

    def test_reentrant_checkpoint_cannot_bypass_aggregate(self):
        reader = self.reader(total_bytes=8)
        other = self.path.with_suffix('.other')
        other.write_bytes(b'12345')
        calls = 0
        def checkpoint():
            nonlocal calls
            calls += 1
            if calls == 3:
                reader.read(other)
        reader.checkpoint = checkpoint
        with self.assertRaisesRegex(Rejected, 'overlapping'):
            reader.read(self.path)
        self.assertEqual(reader.bytes_read, 3)
        self.assertTrue(reader.closed)

    def test_close_failure_is_terminal_and_releases_guard(self):
        reader = self.reader()
        original = os.close
        def failing_close(fd):
            original(fd)
            raise OSError('close failed')
        with patch('os.close', failing_close):
            with self.assertRaisesRegex(OSError, 'close failed'):
                reader.read(self.path)
        self.assertTrue(reader.closed)
        self.assertFalse(reader._active.locked())
        with self.assertRaisesRegex(Rejected, 'terminal'):
            reader.read(self.path)
