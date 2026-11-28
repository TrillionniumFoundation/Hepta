"""Independent checks for current native and exact retained workflow domains."""
import ast
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from tests import hia_workflow_cold_history as history

ROOT = Path(__file__).resolve().parents[1]


class NativeWorkflowColdHistoryTests(unittest.TestCase):
    def test_current_native_entry_archive_and_original_budget_are_admitted(self):
        proof = history.admit_current_native_archive(
            (ROOT / ".github/workflows/hia-core.yml").read_text(),
            (ROOT / "tools/replay_hia_native_cold.py").read_text())
        self.assertTrue(proof["always_archived"])
        self.assertTrue(proof["archive_after_native_command"])
        self.assertEqual(proof["original_budget"],
                         {"qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3})
        self.assertFalse(proof["whole_native_delivery_qualified"])

    def test_missing_or_weakened_native_failure_boundaries_are_refused(self):
        source = (ROOT / ".github/workflows/hia-core.yml").read_text()
        entry = (ROOT / "tools/replay_hia_native_cold.py").read_text()
        lines, start, end = history.archive_block(source)
        block = "\n".join(lines[start:end])
        mutations = [
            source.replace(history.NATIVE_COMMAND,
                           history.NATIVE_COMMAND.replace("replay_hia_native_cold", "replay_hia_selfhost_cold"), 1),
            source + "\n# continue-on-error is forbidden even when accidentally introduced\n",
            source.replace(block, block.replace("        if: always()", "        if: success()", 1), 1),
            source.replace(block, block.replace("          include-hidden-files: true", "", 1), 1),
            source.replace(block, block.replace("          if-no-files-found: error", "", 1), 1),
            source.replace(block, block.replace(
                "            ${{ runner.temp }}/hia-cold.native-cold/", "", 1), 1),
            source.replace(block, "", 1),
            source.replace(history.NATIVE_COMMAND, "", 1) + "\n" + history.NATIVE_COMMAND + "\n",
        ]
        self.assertTrue(all(changed != source for changed in mutations))
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                history.admit_current_native_archive(changed, entry)
        changed_entry = entry.replace('"qualification_wall_limit_seconds": 180',
                                      '"qualification_wall_limit_seconds": 181', 1)
        self.assertNotEqual(changed_entry, entry)
        with self.assertRaisesRegex(ValueError, "180\\+3"):
            history.admit_current_native_archive(source, changed_entry)

    def test_complete_historical_workflow_and_all_original_methods_are_retained(self):
        original, record = history.historical_workflow(ROOT)
        self.assertIn(b"tools/replay_hia_selfhost_cold.py", original)
        self.assertEqual(len(original), 242851)
        source = (ROOT / "tests/test_hia_integrated_workflow.py").read_bytes()
        cls = next(node for node in ast.parse(source).body
                   if isinstance(node, ast.ClassDef) and node.name == "CoreWorkflowContractTests")
        methods = {node.name: sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                   for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}
        self.assertEqual(methods, record["original_method_ast_sha256"])
        self.assertEqual(len(methods), 13)

    def test_foreign_missing_tampered_and_late_changed_authority_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="workflow-history-root-") as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "missing"):
                history.historical_workflow(root)
            target = root / history.FIXTURE
            target.parent.mkdir(parents=True)
            raw = (ROOT / history.FIXTURE).read_bytes()
            target.write_bytes(raw)
            self.assertEqual(history.historical_workflow(root)[0], history.historical_workflow(ROOT)[0])
            target.write_bytes(raw + b"\n")
            with self.assertRaisesRegex(ValueError, "changed"):
                history.historical_workflow(root)
            target.write_bytes(raw)
            calls = []
            def take(path):
                calls.append(path)
                return path.read_bytes() + (b"\n" if len(calls) > 1 else b"")
            with self.assertRaisesRegex(ValueError, "terminal"):
                history.historical_workflow(root, take=take)
            self.assertEqual(calls, [target, target])
