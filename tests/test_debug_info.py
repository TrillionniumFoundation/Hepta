import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.debug_info import retain_debug_source

ROOT = Path(__file__).resolve().parents[1]


class DebugInfoTests(unittest.TestCase):
    def test_both_cli_backends_retain_real_debug_sources(self):
        source = ROOT / "examples/debug/main.hepta"
        with tempfile.TemporaryDirectory() as td:
            for backend in ("rust", "c"):
                with self.subTest(backend=backend):
                    dest = Path(td) / backend
                    proc = subprocess.run([sys.executable, "-m", "hepta", "build", str(source), "--backend", backend,
                                           "--debug", "-o", str(dest)], cwd=ROOT, text=True, capture_output=True, timeout=120)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    report = json.loads(proc.stdout)
                    build = report["build"]
                    info = build["debug_info"]
                    generated = Path(info["source"])
                    self.assertTrue(generated.is_file())
                    self.assertEqual(hashlib.sha256(generated.read_bytes()).hexdigest(), info["source_sha256"])
                    manifest = json.loads(Path(info["manifest"]).read_text())
                    self.assertEqual(manifest["generated_sha256"], info["source_sha256"])
                    self.assertIn("debuginfo=2" if backend == "rust" else "-g3", build["flags"])
                    self.assertIn("opt-level=0" if backend == "rust" else "-O0", build["flags"])
                    execution = subprocess.run([str(dest)], text=True, capture_output=True, timeout=10)
                    self.assertEqual((execution.returncode, execution.stdout), (0, "36\n"))

    def test_debug_profiles_require_an_explicit_retained_destination(self):
        with self.assertRaises(HeptaError) as error:
            compile_rust("fn main() {}", crate_type="bin", debug_info=True)
        self.assertEqual(error.exception.diagnostic.code, "E_DEBUG_OUTPUT")
        with self.assertRaises(HeptaError) as error:
            compile_c("int main(void) {return 0;}", debug_info=True)
        self.assertEqual(error.exception.diagnostic.code, "E_DEBUG_OUTPUT")

    def test_retained_source_identity_is_immutable(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "out"
            source, metadata = retain_debug_source("fn main() {}\n", artifact, "rust")
            again, repeated = retain_debug_source("fn main() {}\n", artifact, "rust")
            self.assertEqual((source, metadata), (again, repeated))
            source.write_text("changed")
            with self.assertRaises(HeptaError) as error:
                retain_debug_source("fn main() {}\n", artifact, "rust")
            self.assertEqual(error.exception.diagnostic.code, "E_DEBUG_SOURCE")

    def test_debug_and_unroll_reject_before_build(self):
        proc = subprocess.run([sys.executable, "-m", "hepta", "build", str(ROOT / "examples/debug/main.hepta"),
                               "--backend", "c", "--debug", "--c-opt", "unroll"], cwd=ROOT,
                              text=True, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot use --c-opt unroll", proc.stdout)


if __name__ == "__main__":
    unittest.main()
