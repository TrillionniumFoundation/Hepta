"""Regression guard: qualification pushes on distinct refs must not cancel each other."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/hepta-qualification.yml"


def _isolated_concurrency_config(source: str) -> bool:
    block = re.search(r"(?m)^concurrency:\s*\n((?:[ \t]+[^\n]*\n)+)", source)
    if block is None:
        return False
    group = re.search(r"(?m)^\s+group:\s*(.+?)\s*$", block.group(1))
    return (group is not None
            and "${{ github.workflow }}" in group.group(1)
            and "${{ github.ref }}" in group.group(1)
            and re.search(r"(?m)^\s+cancel-in-progress:\s*true\s*$", block.group(1)) is not None)


class QualificationWorkflowConcurrency(unittest.TestCase):
    def test_isolated_by_ref_and_workflow(self):
        self.assertTrue(_isolated_concurrency_config(WORKFLOW.read_text(encoding="utf-8")))

    def test_unscoped_concurrency_group_is_rejected(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        mutated = source.replace("${{ github.ref }}", "")
        self.assertNotEqual(mutated, source)
        self.assertFalse(_isolated_concurrency_config(mutated))

    def test_without_workflow_identity_is_rejected(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        mutated = source.replace("${{ github.workflow }}", "")
        self.assertNotEqual(mutated, source)
        self.assertFalse(_isolated_concurrency_config(mutated))


if __name__ == "__main__":
    unittest.main()
