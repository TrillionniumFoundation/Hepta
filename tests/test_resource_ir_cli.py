"""Source export and data-only verification retain distinct qualification scopes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import resource_ir as resource_module
from hepta.resource_ir import ResourceIRError

from hepta.checker import check
from hepta.parser import parse
from hepta.resource_lowering import lower_resource_ir


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fn main()->Unit effects {alloc,block,panic} {let b=buffer(4);drop(move b);}"


class ResourceIRCommandTests(unittest.TestCase):
    def source_command(self, source=SOURCE, *options):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "main.hepta"
            path.write_text(source, encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta", "resource-ir", str(path), *options],
                                     cwd=ROOT, capture_output=True, text=True, timeout=30)
            return process.returncode, json.loads(process.stdout)

    def test_native_source_export_has_both_native_and_resource_checks(self):
        code, report = self.source_command()
        self.assertEqual(code, 0, report)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rustc_checked")
        self.assertTrue(report["verifier"]["ok"])
        self.assertFalse(report["verifier"]["claims"]["source_to_ir_refinement_proved"])

    def test_frontend_only_export_does_not_claim_native_qualification(self):
        code, report = self.source_command(SOURCE, "--frontend-only")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["status"], "frontend_only")
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "not_run")

    def test_unsupported_pointer_source_is_machine_readable_rejection(self):
        code, report = self.source_command('extern "C" fn value(p:raw const u8)->u8 effects {ffi,unsafe};', "--frontend-only")
        self.assertEqual(code, 1, report)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_LOWER_UNSUPPORTED")

    def test_data_only_cli_accepts_graph_and_rejects_removed_release(self):
        program = parse(SOURCE)
        graph = lower_resource_ir(program, check(program))
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "graph.json"
            for tampered in (False, True):
                if tampered:
                    for block in graph["functions"][0]["blocks"]:
                        block["ops"] = [op for op in block["ops"] if op["op"] != "drop"]
                path.write_text(json.dumps(graph), encoding="utf-8")
                process = subprocess.run([sys.executable, "-m", "hepta.resource_ir", str(path)],
                                         cwd=ROOT, capture_output=True, text=True, timeout=10)
                report = json.loads(process.stdout)
                self.assertEqual(process.returncode, int(tampered), report)
                self.assertFalse(report["source_binding_verified"])
                if tampered:
                    self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_LEAK")

    def test_resource_json_regular_file_and_bounded_intake(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-intake-") as tmp:
            base = Path(tmp)
            path = base / "graph.json"
            sample = {"schema": "hepta.resource-ir.v3", "types": [], "functions": []}
            path.write_text(json.dumps(sample))
            self.assertEqual(resource_module.read_resource_ir(path), sample)
            alias = base / "alias.json"
            alias.symlink_to(path)
            with self.assertRaisesRegex(ResourceIRError, "ordinary file"):
                resource_module.read_resource_ir(alias)
            empty = base / "empty.json"
            empty.touch()
            with self.assertRaisesRegex(ResourceIRError, "Empty"):
                resource_module.read_resource_ir(empty)
            huge = base / "huge.json"
            with huge.open("wb") as stream:
                stream.truncate(resource_module.MAX_RESOURCE_JSON_BYTES + 1)
            with patch.object(resource_module.os, "open",
                              side_effect=AssertionError("must refuse before open")):
                with self.assertRaisesRegex(ResourceIRError, "16 MiB"):
                    resource_module.read_resource_ir(huge)
            if hasattr(os, "mkfifo"):
                fifo = base / "graph.fifo"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(ResourceIRError, "ordinary file"):
                    resource_module.read_resource_ir(fifo)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK")
                         and hasattr(os, "mkfifo"),
                         "requires Linux/POSIX nonblocking no-follow file descriptors")
    def test_lstat_open_fifo_substitution_refuses_before_read(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-fifo-") as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text('{"schema":"sample"}')
            real_open = os.open
            def swap_to_fifo(name, flags, *args, **kwargs):
                # Fail test before a potentially blocking read if the
                # nonblocking flag is ever removed.
                self.assertTrue(flags & os.O_NONBLOCK)
                self.assertTrue(flags & os.O_NOFOLLOW)
                path.unlink()
                os.mkfifo(path)
                return real_open(name, flags, *args, **kwargs)
            with patch.object(resource_module.os, "open", side_effect=swap_to_fifo):
                with self.assertRaisesRegex(ResourceIRError, "replaced"):
                    resource_module.read_resource_ir(path)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"),
                         "requires Linux/POSIX nonblocking no-follow file descriptors")
    def test_path_rebinding_and_symlink_retarget_refuse(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-symlink-") as tmp:
            base = Path(tmp)
            path, target = base / "graph.json", base / "secret.json"
            path.write_text('{"schema":"sample"}')
            target.write_text('{"secret":true}')
            real_open = os.open
            def swap_to_symlink(name, flags, *args, **kwargs):
                self.assertTrue(flags & os.O_NOFOLLOW)
                path.unlink()
                path.symlink_to(target)
                return real_open(name, flags, *args, **kwargs)
            with patch.object(resource_module.os, "open", side_effect=swap_to_symlink):
                with self.assertRaises(OSError):
                    resource_module.read_resource_ir(path)
            self.assertEqual(target.read_text(), '{"secret":true}')

            path.unlink()
            path.write_text('{"schema":"sample"}')
            saved = base / "saved.json"
            real_fstat = os.fstat
            calls = 0
            def change_path_on_second_fstat(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.rename(saved)
                    path.write_text('{"schema":"another"}')
                return real_fstat(fd)
            with patch.object(resource_module.os, "fstat",
                              side_effect=change_path_on_second_fstat):
                with self.assertRaisesRegex(ResourceIRError, "changed"):
                    resource_module.read_resource_ir(path)

    def test_ambiguous_json_is_rejected_before_graph_validation(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "graph.json"
            path.write_text('{"schema":"bad","schema":"hepta.resource-ir.v1"}', encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta.resource_ir", str(path)],
                                     cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(json.loads(process.stdout)["diagnostics"][0]["code"], "E_RIR_JSON")


if __name__ == "__main__":
    unittest.main()
