"""Independent real-reader evidence: a matching stream is not an instant snapshot.

Only fixture files change. No reader, OS read, callback guard, or quota is patched.
The sole writer changes the already-read prefix before restoring the unread tail,
so even intermediate writes cannot produce the concatenated observed stream.
"""
import hashlib
from pathlib import Path
import tempfile
import unittest

from experiments.loader_budget.prototype import Limits, Reader


class ReviewRegressions(unittest.TestCase):
    def observe_torn_stream(self, operation):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'stream.bin'
            observed = b'AAAABBBB'
            path.write_bytes(b'AAAAXXXX')
            initial_inode = path.stat().st_ino
            states = [path.read_bytes()]
            changed = False

            def checkpoint():
                nonlocal changed
                if reader.bytes_read != 4 or changed:
                    return
                changed = True
                # The fd already opened by Reader remains bound to this inode.
                # Remove the matching prefix before installing the matching tail.
                with path.open('r+b', buffering=0) as writer:
                    self.assertEqual(writer.write(b'YYYY'), 4)
                    states.append(path.read_bytes())
                    writer.seek(4)
                    self.assertEqual(writer.write(b'BBBB'), 4)
                    states.append(path.read_bytes())
                self.assertEqual(path.stat().st_ino, initial_inode)

            reader = Reader(Limits(per_file=8, total_bytes=8, reads=1,
                                   chunk_bytes=4), checkpoint)
            result = getattr(reader, operation)(path)
            self.assertTrue(changed)
            self.assertEqual(states, [b'AAAAXXXX', b'YYYYXXXX', b'YYYYBBBB'])
            self.assertNotIn(observed, states)
            # Under a partial prefix write the tail remains XXXX; under a
            # partial tail write the prefix is already YYYY. No intermediate
            # state can equal AAAABBBB, not merely the recorded endpoints.
            self.assertEqual(path.read_bytes(), b'YYYYBBBB')
            self.assertEqual(reader.bytes_read, 8)
            self.assertEqual(reader.reads, 1)
            self.assertFalse(reader.closed)
            return result, observed

    def test_real_read_can_match_bytes_never_present_as_whole_file(self):
        result, observed = self.observe_torn_stream('read')
        self.assertEqual(result, observed)

    def test_real_digest_can_match_bytes_never_present_as_whole_file(self):
        result, observed = self.observe_torn_stream('digest')
        self.assertEqual(result, hashlib.sha256(observed).hexdigest())


if __name__ == '__main__':
    unittest.main()
