"""P6 CLI exposure is pinned, read-only, and cannot launder proof claims."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta import agent_contract_diff, agent_semantics
from hepta.workspace import WorkspaceError


class PinnedWorkspaceQueryCLITests(unittest.TestCase):
    BEFORE = "a" * 64
    AFTER = "b" * 64

    def run_cli(self, arguments):
        stream = io.StringIO()
        with redirect_stdout(stream):
            status = main(arguments)
        return status, json.loads(stream.getvalue())

    def test_semantics_requires_exact_version_and_only_reads(self):
        expected = {"schema": "hepta.agent-semantics.v1",
                    "ok": True, "status": "published_native_prevalidated_read_only",
                    "workspace_version": self.BEFORE}
        with patch.object(agent_semantics, "inspect_pinned_semantics",
                          return_value=expected) as query:
            code, response = self.run_cli([
                "workspace", "semantics", "/pinned/store", "--version", self.BEFORE])
            self.assertEqual(code, 0)
            self.assertEqual(response, expected)
            query.assert_called_once_with("/pinned/store", expected_version=self.BEFORE)

    def test_diff_requires_both_exact_pins_and_never_calls_patch(self):
        expected = {"schema": "hepta.agent-contract-diff.v1",
                    "status": "read_only_contract_diff_not_equivalence",
                    "claims": {"functional_equivalence_proved": False}}
        with patch.object(agent_contract_diff, "compare_pinned_contracts",
                          return_value=expected) as query:
            code, response = self.run_cli([
                "workspace", "diff", "/pinned/before", "/pinned/after",
                "--before-version", self.BEFORE, "--after-version", self.AFTER])
            self.assertEqual(code, 0)
            self.assertEqual(response, expected)
            self.assertFalse(response["claims"]["functional_equivalence_proved"])
            query.assert_called_once_with(
                "/pinned/before", "/pinned/after",
                expected_before_version=self.BEFORE,
                expected_after_version=self.AFTER)

    def test_stale_semantic_pin_cannot_be_called_success(self):
        with patch.object(agent_semantics, "inspect_pinned_semantics",
                          side_effect=WorkspaceError("E_STALE_PROJECT", "stale version")):
            code, response = self.run_cli([
                "workspace", "semantics", "/pinned/store", "--version", self.BEFORE])
            self.assertNotEqual(code, 0)
            self.assertFalse(response.get("ok", False))

    def test_diff_has_no_implicit_truthy_success_for_wrong_schema(self):
        with patch.object(agent_contract_diff, "compare_pinned_contracts",
                          return_value={"schema": "unknown", "status": "passed"}) as query:
            code, response = self.run_cli([
                "workspace", "diff", "/pinned/before", "/pinned/after",
                "--before-version", self.BEFORE, "--after-version", self.AFTER])
            self.assertNotEqual(code, 0)
            self.assertEqual(response["schema"], "unknown")
            self.assertEqual(query.call_count, 1)


if __name__ == "__main__":
    unittest.main()
