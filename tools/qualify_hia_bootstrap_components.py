"""Execute source-bound byte/bootstrap gates without claiming full self-hosting."""
from __future__ import annotations

import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import struct
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))


def inventory(suite):
    for entry in suite:
        if isinstance(entry, unittest.TestSuite):
            yield from inventory(entry)
        else:
            yield entry.id()


def source_manifest():
    names = ["hepta/hia_native_byte_abi.py", "hepta/hia_native_byte_runner.py", "hepta/hia_program_native.py",
             "hepta/hia_machine_plan.py", "hepta/hia_machine_x64.py", "hepta/hia_machine_elf.py",
             "hepta/hia_program.py", "hepta/hia_agent_assembly.py", "hepta/hia_agent_runner.py",
             "hepta/clang_capture.py", "hepta/hia_agent_store.py",
             "examples/hia_bootstrap/components.hepta", "docs/HIA_DIRECT_BYTE_BOOTSTRAP.md",
             "tools/generate_hia_bootstrap_components.py", "tools/qualify_hia_bootstrap_components.py",
             "tests/test_hia_native_byte_abi.py", "tests/test_hia_bootstrap_components.py"]
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def compact_observation(result):
    return {key: value for key, value in result.items() if key not in {"arguments", "report"}}


def qualify(output):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_native_byte_runner import invoke_byte_program
    from tests.test_hia_bootstrap_components import SOURCE, constant_source, execute_text, reference_tokens, INVALID
    before = source_manifest()
    started = time.monotonic_ns()
    log = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromNames(["tests.test_hia_native_byte_abi", "tests.test_hia_bootstrap_components"])
    expected = list(inventory(suite))

    class Result(unittest.TextTestResult):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw); self.started_ids = []; self.finished_ids = []

        def startTest(self, test):
            self.started_ids.append(test.id()); super().startTest(test)

        def stopTest(self, test):
            self.finished_ids.append(test.id()); super().stopTest(test)

    run = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
    evidence_dir = output.with_suffix(".evidence")
    evidence_dir.mkdir(parents=True, exist_ok=False)
    (evidence_dir / "tests.log").write_text(log.getvalue(), encoding="utf-8")
    source = SOURCE.read_bytes()
    checked = assemble_program(source)
    observations = []
    checks = {}
    lexical = invoke_byte_program(checked, "lex_assembly", [source, bytearray(1 << 20)])
    lexical_ok = lexical["status"] == "returned" and lexical.get("abi_status") == 0
    expected_tokens = reference_tokens(source)
    if lexical_ok:
        count = lexical["core_status"]
        raw = lexical["arguments"][1][:12 * count]
        actual_tokens = list(struct.iter_unpack("<III", raw))
        lexical_ok = actual_tokens == expected_tokens
        (evidence_dir / "own-source.tokens.bin").write_bytes(raw)
        token_hash = sha256(raw).hexdigest()
    else:
        count, token_hash = None, None
    checks["native_own_source_lexer"] = bool(lexical_ok)
    observations.append({"case": "own-source-lexing", **compact_observation(lexical),
                         "source_sha256": sha256(source).hexdigest(), "source_bytes": len(source),
                         "observed_tokens": count, "expected_tokens": len(expected_tokens), "tokens_sha256": token_hash})
    literal_results = []
    for value in (0, 1, 0xffffffff, 0x100000000, 0x8000000000000000, 0xffffffffffffffff):
        text = constant_source(value)
        assembled = invoke_byte_program(checked, "compile_constant", [text, bytearray(11)])
        good = assembled["status"] == "returned" and assembled.get("abi_status") == 0 and assembled.get("core_status") == 11
        code = assembled["arguments"][1] if good else b""
        native_value = execute_text(code) if good else None
        good = good and native_value == value and code == b"\x48\xb8" + value.to_bytes(8, "little") + b"\xc3"
        literal_results.append(bool(good))
        stem = "constant-" + str(value)
        (evidence_dir / (stem + ".hepta")).write_bytes(text)
        (evidence_dir / (stem + ".text.bin")).write_bytes(code)
        observations.append({"case": stem, **compact_observation(assembled),
                             "source_sha256": sha256(text).hexdigest(), "machine_text_hex": code.hex(),
                             "expected_u64": str(value), "observed_native_u64": None if native_value is None else str(native_value),
                             "correct": bool(good)})
    checks["native_input_mutations_generate_and_execute_distinct_code"] = all(literal_results)
    own_compile = invoke_byte_program(checked, "compile_constant", [source, bytearray([0xa5]) * 32])
    rejected = (own_compile["status"] == "returned" and own_compile.get("abi_status") == 0
                and own_compile.get("core_status") == INVALID and own_compile["arguments"][1] == bytes([0xa5]) * 32)
    checks["unsupported_full_own_source_is_rejected_without_output"] = bool(rejected)
    observations.append({"case": "whole-toolchain-own-source-compilation", **compact_observation(own_compile),
                         "expected": "unsupported", "observed_core_status": own_compile.get("core_status"),
                         "whole_toolchain_built": False, "output_unchanged": bool(rejected)})
    after = source_manifest()
    test_ok = run.wasSuccessful() and not run.skipped and expected == run.started_ids == run.finished_ids
    passed = test_ok and all(checks.values()) and before == after
    evidence = {str(path.relative_to(evidence_dir)): sha256(path.read_bytes()).hexdigest()
                for path in sorted(evidence_dir.iterdir()) if path.is_file()}
    result = {"schema": "hepta.hia.bootstrap-components-qualification.v1",
              "component_qualification_passed": bool(passed),
              "status": "COMPONENTS_PASS_BOOTSTRAP_OPEN" if passed else "COMPONENT_QUALIFICATION_FAILED",
              "self_hosted": False, "bootstrap_closure_passed": False,
              "stages": {"B0_python_seed": True, "HIA_native_components_executed": all(checks.values()),
                         "B1_whole_toolchain": False, "B2_whole_toolchain": False, "B3_whole_toolchain": False,
                         "modified_toolchain_self_rebuild": False},
              "remaining_host_dependencies": ["general assembly/Core parsing and semantic verification",
                  "general Core lowering and machine-code generation", "ELF packaging and GNU shared-library linkage",
                  "disposable Python invocation harness"],
              "source_before": before, "source_after": after, "source_unchanged": before == after,
              "tests": {"expected": expected, "started": run.started_ids, "finished": run.finished_ids,
                        "executed": run.testsRun, "failures": [(case.id(), error) for case, error in run.failures],
                        "errors": [(case.id(), error) for case, error in run.errors],
                        "skips": [(case.id(), reason) for case, reason in run.skipped]},
              "checks": checks, "observations": observations,
              "evidence_directory": str(evidence_dir), "evidence_sha256": evidence,
              "wall_ns": str(time.monotonic_ns() - started)}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps({"status": result["status"], "executed_tests": run.testsRun,
                      "self_hosted": False, "output": str(output)}, sort_keys=True))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    return qualify(args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
