"""HIA checked-source CLI must forward explicit finite resource requirements."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from tools.build_checked_hia_source import main


class HIAStaticBudgetCLITests(unittest.TestCase):
    def test_explicit_policy_is_passed_to_one_native_builder(self):
        arguments = ["example.hepta", "--output", "out.o", "--kind", "object",
                     "--profile", "owned", "--max-allocator-interactions", "0",
                     "--max-vm-ticks", "17", "--max-call-depth", "2"]
        out = io.StringIO()
        with patch("tools.build_checked_hia_source.build_checked_hepta_hia_native",
                   return_value={"ok": False, "status": "rejected"}) as builder:
            with redirect_stdout(out):
                code = main(arguments)
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out.getvalue())["ok"])
        self.assertEqual(builder.call_count, 1)
        self.assertEqual(builder.call_args.kwargs["static_resource_limits"],
                         {"max_allocator_interactions": 0,
                          "max_vm_ticks": 17, "max_call_depth": 2})
        self.assertEqual(builder.call_args.kwargs["profile"], "owned")

    def test_unset_policy_does_not_change_original_builder_request(self):
        with patch("tools.build_checked_hia_source.build_checked_hepta_hia_native",
                   return_value={"ok": True}) as builder:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["example.hepta", "-o", "out.so"]), 0)
        self.assertNotIn("static_resource_limits", builder.call_args.kwargs)

    def test_invalid_cli_integer_never_reaches_native_builder(self):
        with patch("tools.build_checked_hia_source.build_checked_hepta_hia_native") as builder:
            for invalid in ("three", "1.5", "false"):
                with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                    main(["example.hepta", "-o", "out.so", "--max-vm-ticks", invalid])
            builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
