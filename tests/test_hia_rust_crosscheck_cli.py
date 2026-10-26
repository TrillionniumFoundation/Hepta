"""CLI-level opt-in Rust crosscheck selection and refusal tests."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from tests.test_hia_rust_crosscheck import scalar_program


class HIARustCrosscheckCliTests(unittest.TestCase):
    def test_rust_crosscheck_only_for_explicit_hia_verify(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scalar.hia"
            path.write_text(json.dumps(scalar_program()), encoding="utf-8")
            with patch("hepta.hia_rust_crosscheck.crosscheck_rust_shadow",
                       return_value={"schema": "hepta.hia.rust-crosscheck.v1",
                                     "status": "shadow_corroborated_not_authority"}) as checked:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main(["hia", "verify", str(path),
                                 "--rust-shadow-bin", "/usr/bin/rust-shadow",
                                 "--rust-shadow-sha256", "f" * 64,
                                 "--rust-shadow-profile", "scalar"])
                self.assertEqual(code, 0)
                value = json.loads(output.getvalue())
                self.assertEqual(value["rust_crosscheck"]["status"],
                                 "shadow_corroborated_not_authority")
                self.assertFalse(value["native_executed"])
                checked.assert_called_once()
                self.assertEqual(checked.call_args.kwargs["profile"], "scalar")

    def test_partial_and_inert_shadow_requests_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scalar.hia"
            path.write_text(json.dumps(scalar_program()), encoding="utf-8")
            for extra in (["--rust-shadow-bin", "/some/path"],
                          ["--rust-shadow-sha256", "a" * 64],
                          ["--rust-shadow-profile", "owned"]):
                with self.subTest(extra=extra), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["hia", "verify", str(path), *extra]), 2)
                    self.assertEqual(json.loads(output.getvalue())["status"], "error")

    def test_baseline_verification_remains_rust_independent(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scalar.hia"
            path.write_text(json.dumps(scalar_program()), encoding="utf-8")
            with patch("hepta.hia_rust_crosscheck.crosscheck_rust_shadow") as shadow:
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["hia", "verify", str(path)]), 0)
                self.assertEqual(json.loads(output.getvalue())["status"],
                                 "standalone_core_checked")
                shadow.assert_not_called()


if __name__ == "__main__":
    unittest.main()
