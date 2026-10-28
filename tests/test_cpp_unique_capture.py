"""Complete streamed AST framing must never accept an omitted suffix."""
import json
import os
from pathlib import Path
import select
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.cpp_unique_capture import _Objects, stream_ast


class UniqueCaptureTests(unittest.TestCase):
    def parse(self, raw, width):
        framing, nodes = _Objects(), []
        for offset in range(0, len(raw), width):
            nodes.extend(framing.feed(raw[offset:offset + width]))
        framing.close()
        return nodes

    def test_every_chunk_boundary_preserves_escaped_fields_and_full_census(self):
        nodes = [{"kind": "VarDecl", "name": 'quote\\"[]{}λ', "value": 7},
                 {"kind": "NamespaceDecl", "inner": [{"kind": "FunctionDecl", "name": "later"}]}]
        raw = json.dumps({"id": "0x1", "kind": "TranslationUnitDecl", "loc": {}, "range": {}, "inner": nodes}).encode()
        for width in range(1, len(raw) + 1):
            self.assertEqual(self.parse(raw, width), nodes)

    def test_truncation_extra_suffix_and_extra_array_separator_reject(self):
        raw = b'{"id":"0x1","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl"}]}'
        for bad in (raw[:-1], raw[:-2], raw + b'{}', raw.replace(b'}]}', b'},]}'),
                    raw.replace(b'}]}', b'}{"kind":"VarDecl"}]}')):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                self.parse(bad, 3)

    def test_duplicate_field_unknown_root_and_nonfinite_value_reject(self):
        for raw in (b'{"id":"x","kind":"TranslationUnitDecl","kind":"TranslationUnitDecl","inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","unaccounted":1,"inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","kind":"FunctionDecl"}]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","x":1e999}]}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw, 5)

    def test_oversized_header_and_nonfinite_metadata_reject(self):
        for bad in (b'{"id":"' + b"x" * 65536 + b'","kind":"TranslationUnitDecl","inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","loc":{"offset":1e999},"inner":[]}',
                    b'{"id":"x","kind":"TranslationUnitDecl","loc":{"offset":NaN},"inner":[]}'):
            for width in (11, len(bad)):
                with self.subTest(width=width), self.assertRaises(ValueError):
                    self.parse(bad, width)

    def test_total_value_and_subtree_budgets_fail_closed(self):
        raw = b'{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"X","name":"a"},{"kind":"Y","name":"b"}]}'
        with patch("hepta.cpp_unique_capture.MAX_AST_VALUES", 4), self.assertRaisesRegex(ValueError, "value/depth"):
            self.parse(raw, 8)
        with patch("hepta.cpp_unique_capture.MAX_OBJECT_BYTES", 10), self.assertRaisesRegex(ValueError, "subtree"):
            self.parse(raw, 8)

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "fork") and hasattr(os, "pidfd_open"),
                         "Actual Linux pidfd/process-group cleanup required")
    def test_timeout_cleans_descendant_after_parent_exits(self):
        script = '''import os, sys, time
from pathlib import Path
child = os.fork()
if child == 0:
    Path("child.pid").write_text(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
while not Path("child.pid").exists():
    time.sleep(0.001)
sys.stdout.write('{"id":"x","kind":"TranslationUnitDecl","inner":[{"kind":"VarDecl","name":"probe"}]}')
sys.stdout.flush()
Path("parent-exited").write_text("yes")
os._exit(0)
'''
        with tempfile.TemporaryDirectory(prefix="hepta-ast-child-") as directory:
            receipt, handles = {}, []
            try:
                with patch("hepta.cpp_unique_capture.MAX_AST_SECONDS", 1), self.assertRaisesRegex(ValueError, "timeout"):
                    for node in stream_ast([sys.executable, "-c", script], cwd=directory, source=None, receipt=receipt):
                        self.assertEqual(node["name"], "probe")
                        child = int((Path(directory) / "child.pid").read_text())
                        handles.append(os.pidfd_open(child))
                self.assertEqual(receipt, {})
                self.assertTrue((Path(directory) / "parent-exited").exists())
                self.assertEqual(len(handles), 1)
                # A pidfd observes this exact namespace-local child even when
                # /proc is mounted from a different PID namespace. Readability
                # indicates termination regardless of asynchronous reaping.
                poller = select.poll()
                poller.register(handles[0], select.POLLIN)
                self.assertTrue(poller.poll(2000), "Owned capture descendant remains live")
            finally:
                for handle in handles:
                    os.close(handle)


if __name__ == "__main__":
    unittest.main()
