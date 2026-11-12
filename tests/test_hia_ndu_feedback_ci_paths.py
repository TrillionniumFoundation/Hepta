"""Keep feedback CI triggers aligned with its real suites and entry points."""
import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "experiments.hia_ndu_feedback_20261106"
CI = ROOT / PACKAGE.replace(".", "/") / "ci.py"
WORKFLOW = ROOT / ".github/workflows/hia-ndu-feedback.yml"


class FeedbackCIPathsTests(unittest.TestCase):
    def test_executed_test_modules_and_feedback_entrypoints_trigger_the_lane(self):
        source = ast.parse(CI.read_text(encoding="utf-8"))
        required = {CI.relative_to(ROOT).as_posix(), WORKFLOW.relative_to(ROOT).as_posix(),
                    Path(__file__).relative_to(ROOT).as_posix()}
        calls = [node for node in ast.walk(source) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "run_tests"]
        self.assertTrue(calls, "CI no longer declares an inspectable test inventory")
        for call in calls:
            names = ast.literal_eval(call.args[0])
            self.assertTrue(names)
            for name in names:
                parts = name.split(".")
                modules = [ROOT.joinpath(*parts[:end]).with_suffix(".py")
                           for end in range(len(parts), 0, -1)]
                path = next((candidate for candidate in modules if candidate.is_file()), None)
                self.assertIsNotNone(path, "unresolved test module: " + name)
                required.add(path.relative_to(ROOT).as_posix())

        # Discover callers by their actual imports, including the witness CLI;
        # do not maintain another hand-copied list of qualification scripts.
        for path in (ROOT / "tools").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            if PACKAGE not in text:
                continue
            imports = []
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
                elif isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
            if any(name == PACKAGE or name.startswith(PACKAGE + ".") for name in imports):
                required.add(path.relative_to(ROOT).as_posix())
        # The two adapters are launched through ci.prepare's literal builder
        # names rather than imported into Python.
        for node in ast.walk(source):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(".py"):
                path = ROOT / "tools" / node.value
                self.assertTrue(path.is_file(), "unresolved CI builder: " + node.value)
                required.add(path.relative_to(ROOT).as_posix())
        required.update(path.relative_to(ROOT).as_posix() for path in CI.parent.glob("*.py"))

        # This workflow uses quoted exact paths and directory/** prefixes. Fail
        # closed if its YAML/glob form changes rather than approximate negations.
        block = re.search(r"(?m)^    paths:\n((?:      - [^\n]+\n)+)", WORKFLOW.read_text(encoding="utf-8"))
        self.assertIsNotNone(block, "unrecognized pull_request.paths block")
        patterns = [ast.literal_eval(line.split("- ", 1)[1]) for line in block.group(1).splitlines()]
        for pattern in patterns:
            plain = pattern[:-3] if pattern.endswith("/**") else pattern
            self.assertTrue(isinstance(pattern, str) and not any(char in plain for char in "!*?[]{}"),
                            "unrecognized trigger pattern: " + str(pattern))
        missing = sorted(path for path in required if not any(
            path == pattern or pattern.endswith("/**") and path.startswith(pattern[:-2])
            for pattern in patterns))
        self.assertEqual(missing, [], "executed suites or feedback entry points would not trigger their CI")


if __name__ == "__main__":
    unittest.main()
