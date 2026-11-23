"""Exercise file descriptor ownership when stream construction rejects a capture."""
from pathlib import Path
import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def audit_case(capture, path):
    seen = []
    def veto_fd_open(event, args):
        if event == "open" and type(args[0]) is int:
            seen.append(args[0])
            raise PermissionError("declined descriptor stream")
    sys.addaudithook(veto_fd_open)
    try:
        capture(path, 4096)
    except PermissionError as error:
        if str(error) != "declined descriptor stream":
            raise
    else:
        raise AssertionError("the descriptor-open audit decision was lost")
    if len(seen) != 1:
        raise AssertionError("unexpected number of descriptor-open events")
    try:
        os.fstat(seen[0])
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return True
    os.close(seen[0])
    return False


class SlotResourceDescriptorTests(unittest.TestCase):
    def test_rejected_stream_releases_its_descriptor(self):
        # Audit hooks are permanent in a process.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"owned input")
            process = subprocess.run(
                [sys.executable, "-I", "-B", __file__, str(ROOT), str(path)],
                cwd=ROOT, capture_output=True, check=True, text=True)
            self.assertTrue(json.loads(process.stdout)["closed"])


if __name__ == "__main__":
    sys.path.insert(0, sys.argv[1])
    from hepta.hia_store_lifecycle_native import _regular_bytes
    print(json.dumps({"closed": audit_case(_regular_bytes, Path(sys.argv[2]))}))
