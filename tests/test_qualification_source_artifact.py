"""Guard the PR HEAD identity shared by checkout, validation, and evidence names."""
import pathlib
import re
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/hepta-qualification.yml"
EXPR = "github.event.pull_request.head.sha || github.sha"
OPEN = chr(36) + "{{"
CLOSE = "}}"


def expression(source: str, field: str) -> str:
    pattern = (r"(?m)^\s*" + re.escape(field) + re.escape(OPEN)
               + r"\s*(.*?)\s*" + re.escape(CLOSE) + r"\s*$")
    matches = re.findall(pattern, source)
    if len(matches) != 1:
        raise ValueError("Expected exactly one source identity field: " + field)
    return matches[0].strip()


def guard(source: str) -> None:
    for field in ("ref: ", "HEPTA_EXPECTED_HEAD_SHA: ",
                  "name: hepta-qualification-"):
        if expression(source, field) != EXPR:
            raise ValueError("Qualification artifact and source HEAD diverge: " + field)


class QualificationSourceArtifactTests(unittest.TestCase):
    def test_real_workflow_uses_one_source_identity(self):
        guard(WORKFLOW.read_text(encoding="utf-8"))

    def test_merge_sha_label_regression_refused(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        corrupt = source.replace("name: hepta-qualification-" + OPEN + " " + EXPR + " " + CLOSE,
                                 "name: hepta-qualification-" + OPEN + " github.sha " + CLOSE)
        self.assertNotEqual(source, corrupt)
        with self.assertRaisesRegex(ValueError, "diverge"):
            guard(corrupt)

    def test_checkout_sha_drift_refused(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        corrupt = source.replace("ref: " + OPEN + " " + EXPR + " " + CLOSE,
                                 "ref: " + OPEN + " github.sha " + CLOSE)
        self.assertNotEqual(source, corrupt)
        with self.assertRaisesRegex(ValueError, "diverge"):
            guard(corrupt)

    def test_expected_sha_drift_refused(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        corrupt = source.replace("HEPTA_EXPECTED_HEAD_SHA: " + OPEN + " " + EXPR + " " + CLOSE,
                                 "HEPTA_EXPECTED_HEAD_SHA: " + OPEN + " github.sha " + CLOSE)
        self.assertNotEqual(source, corrupt)
        with self.assertRaisesRegex(ValueError, "diverge"):
            guard(corrupt)


if __name__ == "__main__":
    unittest.main()
