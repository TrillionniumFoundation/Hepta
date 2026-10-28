"""Check the actual workflow invocation against the unified qualifier parser."""
import contextlib
import io
import os
from pathlib import Path
import shlex
import sys
import unittest
from unittest.mock import patch

from tools import qualify_hia_unified as unified


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/hepta-qualification.yml"
STEP = "      - name: Qualify the standalone HIA interpreter and direct native paths"


def workflow_argv(source, workspace):
    """Extract the fixed literal command without executing shell or a qualifier."""
    lines = source.splitlines()
    starts = [i for i, line in enumerate(lines) if line == STEP]
    if len(starts) != 1:
        raise ValueError("expected one HIA qualification step")
    start = starts[0] + 1
    end = next((i for i in range(start, len(lines))
                if lines[i].startswith("      - name:")), len(lines))
    step = lines[start:end]
    if step.count("        run: |") != 1:
        raise ValueError("expected one literal shell run block")
    body = "\n".join(step[step.index("        run: |") + 1:])
    statements = body.replace("\\\n", " ").splitlines()
    commands = [line.strip() for line in statements
                if line.strip().startswith("python tools/qualify_hia_unified.py")]
    if len(commands) != 1:
        raise ValueError("expected one unified qualifier command")
    tokens = shlex.split(commands[0])
    if tokens[:2] != ["python", "tools/qualify_hia_unified.py"]:
        raise ValueError("unexpected unified qualifier invocation")
    # Bind the two literal path variables used by this workflow. Never execute
    # shell syntax while checking the real parser's required CLI contract.
    lean = workspace + "/../toolchains/lean-4.19.0/bin/lean"
    argv = [token.replace("$GITHUB_WORKSPACE", workspace).replace("$LEAN", lean)
            for token in tokens[1:]]
    if any("$" in token or chr(96) in token for token in argv):
        raise ValueError("unsupported shell substitution in workflow argv")
    return argv


class UnifiedWorkflowCLIContractTests(unittest.TestCase):
    def test_workflow_reaches_main_with_required_tools_and_explicit_budget(self):
        workspace = "/unexecuted/hepta-workflow-checkout"
        argv = workflow_argv(WORKFLOW.read_text(encoding="utf-8"), workspace)
        environment = {
            "GITHUB_WORKSPACE": workspace,
            "LEAN": workspace + "/../toolchains/lean-4.19.0/bin/lean",
        }
        result = dict(ok=True, status="mocked_cli_only", passed_gates=0, completed_gates=0,
                      unchanged_source=True, full_seven_deliverables_complete=False)
        with patch.dict(os.environ, environment), patch.object(sys, "argv", argv), \
                patch.object(unified, "qualify", return_value=result) as qualify, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(unified.main(), 0)
        qualify.assert_called_once()
        self.assertEqual(qualify.call_args.args, ("artifacts/hia-unified",))
        supplied = qualify.call_args.kwargs
        self.assertEqual(supplied["lean"], environment["LEAN"])
        self.assertEqual(supplied["qemu_riscv64"], "/usr/bin/qemu-riscv64")
        self.assertEqual(supplied["linker"], workspace + "/../toolchains/rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")
        self.assertEqual(supplied["unit_timeout_seconds"], 3600)

        # Keep LEAN exported while removing each required option from real argv.
        # The parser must reject before qualification can write or run anything.
        for option in ("--lean", "--qemu-riscv64"):
            with self.subTest(missing=option):
                position = argv.index(option)
                incomplete = argv[:position] + argv[position + 2:]
                stderr = io.StringIO()
                with patch.dict(os.environ, environment), patch.object(sys, "argv", incomplete), \
                        patch.object(unified, "qualify") as qualify, \
                        contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as error:
                        unified.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn(option, stderr.getvalue())
                qualify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
