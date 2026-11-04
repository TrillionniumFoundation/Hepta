"""Host-side regression: preserve post-test source identity after prior gate RED.

This proves the workflow *wiring*, not that the post-test or full CI passed.
The real earlier failure is retained at Actions run 41774368131.
"""
from pathlib import Path
import unittest

WORKFLOW = (Path(__file__).resolve().parents[1] /
            ".github/workflows/hepta-verified-optimization.yml")
STEP = "      - name: "


def step(name: str, source: str) -> str:
    marker = STEP + name + "\n"
    if source.count(marker) != 1:
        raise AssertionError(f"expected exactly one step: {name}")
    tail = source.split(marker, 1)[1]
    return tail.split(STEP, 1)[0]


class FailedNativeSourceDependencyTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_native_gate_still_fails_closed(self):
        native = step("Run actual native integration and regression gates without skipped tests",
                      self.source)
        self.assertIn("set -euo pipefail", native)
        self.assertIn("qualify_hia_verified_increment.py", native)
        self.assertNotIn("continue-on-error:", native)
        self.assertNotIn("if: ${{ always() }}", native)

    def test_source_preparation_runs_after_failure_but_not_cancel(self):
        prep = step("Prepare exact clean source for guarded opportunity and post-test application",
                    self.source)
        self.assertIn("        if: ${{ !cancelled() }}\n", prep)
        self.assertNotIn("continue-on-error:", prep)
        self.assertIn('git --no-replace-objects worktree add --detach', prep)
        self.assertIn('$RUNNER_TEMP/hepta-round7-clean-source', prep)
        self.assertIn('rev-parse HEAD)', prep)
        self.assertIn('$HEPTA_SOURCE_SHA', prep)
        self.assertIn('status --porcelain --untracked-files=all', prep)

    def test_posttest_keeps_non_cancel_guard_and_original_qualification(self):
        post = step("Qualify the captured post-test project on the exact source", self.source)
        self.assertIn("        if: ${{ !cancelled() }}\n", post)
        self.assertIn('cd "$RUNNER_TEMP/hepta-round7-clean-source"', post)
        self.assertIn("qualify_hia_c_posttest.py", post)
        self.assertIn('--expected-source "$HEPTA_SOURCE_SHA"', post)
        self.assertNotIn("continue-on-error:", post)

    def test_dependency_order_cannot_regress(self):
        native = self.source.index(STEP + "Run actual native integration and regression gates without skipped tests")
        prep = self.source.index(STEP + "Prepare exact clean source for guarded opportunity and post-test application")
        post = self.source.index(STEP + "Qualify the captured post-test project on the exact source")
        self.assertLess(native, prep)
        self.assertLess(prep, post)


if __name__ == "__main__":
    unittest.main()
