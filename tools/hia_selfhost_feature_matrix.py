"""Retain valid-Core cross-feature witnesses and actual bootstrap outcomes.

This finite qualification does not extend the selfhost profile or prove compiler
correctness. Every source keeps the real three-buffer f0 entry; the Core VM and
the HIA-generated compiler consume the same admitted program.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(alloc,read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")
INPUT = b"12345678"
INITIAL = bytes([0xa5]) * 8


def cases():
    """Isolate one unsupported helper feature without changing entry ABI."""
    call = ('  v3:u32 = const() {"value":5}\n'
            '  v4:u32 = const() {"value":12}\n'
            '  v5:u32 = call(v3,v4) {"function":"f1"}\n'
            '  ret(v5)\nend\n')
    helper = '''fn f1(v0:u32,v1:u32) -> (u32) effects() entry(b0)
block b0(v0:u32,v1:u32)
  v2:bool = compare.lt(v0,v1)
  branch v2 b1(v0,v1) b2(v0,v1)
block b1(v3:u32,v4:u32)
  v5:u32 = int.add.wrap(v3,v4)
  jump b3(v5)
block b2(v6:u32,v7:u32)
  v8:u32 = int.add.wrap(v7,v6)
  jump b3(v8)
block b3(v9:u32)
  ret(v9)
end
'''
    unsigned = HEADER + call + helper
    owner = HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n") + '''  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:u32 = call(v4) {"function":"f1"}
  ret(v5)
end
fn f1(v0:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer)
  v1:usize = buffer.len(v0)
  _ = owner.drop(v0)
  v2:u32 = int.cast(v1) {"mode":"wrap"}
  ret(v2)
end
'''
    signed = HEADER + '''  v3:i32 = const() {"value":-5}
  v4:i32 = const() {"value":5}
  v5:i32 = call(v3,v4) {"function":"f1"}
  v6:u32 = int.cast(v5) {"mode":"wrap"}
  ret(v6)
end
fn f1(v0:i32,v1:i32) -> (i32) effects() entry(b0)
block b0(v0:i32,v1:i32)
  v2:i32 = int.add.wrap(v0,v1)
  ret(v2)
end
'''
    pair = HEADER + '''  v3:u32 = const() {"value":5}
  v4:u32 = const() {"value":12}
  v5:u32,v6:u32 = call(v3,v4) {"function":"f1"}
  v7:u32 = int.add.wrap(v5,v6)
  ret(v7)
end
fn f1(v0:u32,v1:u32) -> (u32,u32) effects() entry(b0)
block b0(v0:u32,v1:u32)
  ret(v1,v0)
end
'''
    returned_owner = owner.replace('v5:u32 = call(v4)', 'v5:buffer = call(v4)').replace(
        '  ret(v5)\nend\nfn f1', '  v6:usize = buffer.len(v5)\n  _ = owner.drop(v5)\n'
        '  v7:u32 = int.cast(v6) {"mode":"wrap"}\n  ret(v7)\nend\nfn f1')
    returned_owner = returned_owner[:returned_owner.index('fn f1')] + '''fn f1(v0:buffer) -> (buffer) effects() entry(b0)
block b0(v0:buffer)
  ret(v0)
end
'''
    returned_loan = HEADER + '''  v3:readbuf = borrow.read(v0)
  v4:readbuf = call(v3) {"function":"f1"}
  v5:usize = buffer.len(v4)
  _ = loan.end(v4)
  _ = loan.end(v3)
  v6:u32 = int.cast(v5) {"mode":"wrap"}
  ret(v6)
end
fn f1(v0:readbuf) -> (readbuf) effects() entry(b0) return_loans(["v0"])
block b0(v0:readbuf)
  ret(v0)
end
'''
    definitions = (
        ("unsigned-call-cfg", unsigned, 17, True, "flat"),
        ("owned-argument-scalar-return", owner, 8, True, "elf"),
        ("signed-helper-preserved-entry", signed, 0, False, "flat"),
        ("scalar-pair-helper-preserved-entry", pair, 17, False, "flat"),
        ("returned-owner-helper-preserved-entry", returned_owner, 8, False, "elf"),
        ("returned-loan-helper-preserved-entry", returned_loan, 8, False, "flat"),
        ("named-helper-preserved-entry", unsigned.replace("f1", "combine"), 17, False, "flat"),
        ("named-module-preserved-entry", unsigned.replace("v8 selfhost\n", "v8 named_module\n"), 17, False, "flat"),
        ("named-pair-helper-preserved-entry", pair.replace("f1", "combine"), 17, False, "flat"),
    )
    return [{"id": name, "source": source, "expected_result": value,
             "expected_compiler_acceptance": accepted, "output_format": form}
            for name, source, value, accepted, form in definitions]


def reference(case):
    """Run the unmodified admitted f0 with live disjoint external VM roots."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(case["source"])
    machine = _Machine(checked, 100000, 1 << 20, None, 256)
    roots = (_Owner(-1, bytearray(INPUT)), _Owner(-2, bytearray(INITIAL)),
             _Owner(-3, bytearray(INITIAL)))
    arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
    entry = checked.as_dict()["functions"][0]
    if entry["name"] != "f0" or [p["type"] for p in entry["params"]] != ["readbuf", "mutbuf", "mutbuf"]:
        raise AssertionError("matrix witness changed the mandatory entry ABI")
    values = machine.invoke(entry, arguments)
    report = machine.report("f0", "returned", values=values, external_roots=roots)
    report["external_bytes_unchanged"] = [bytes(root.data) == initial
        for root, initial in zip(roots, (INPUT, INITIAL, INITIAL))]
    if (report["result"] != case["expected_result"] or not all(report["external_bytes_unchanged"])
            or machine.owners or machine.chains or machine.loans_started != machine.loans_ended):
        raise AssertionError(report)
    return {"core_sha256": checked.sha256, "input_sha256": checked.input_sha256,
            "entry_types": [p["type"] for p in entry["params"]], "execution": report}


def digest(data):
    return sha256(data).hexdigest()


def qualify(output):
    from tools.qualify_hia_selfhost import (SOURCE, build_seed, checkout_identity,
        compile_stage, invoke, observe_native_tool, source_manifest, INVALID, CAPACITY)
    from tools.hia_selfhost_contract import validate_contract
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.selfhost-feature-matrix.v1", "status": "FAIL",
              "checkout": checkout_identity(), "stages": [], "cases": [],
              "claims": {"finite_witnesses_only": True, "profile_extended": False,
                         "all_input_compiler_correctness_proved": False,
                         "whole_language_selfhosted": False, "adoption_authority": False}}
    before = {**source_manifest(), "tools/hia_selfhost_feature_matrix.py": digest(Path(__file__).read_bytes())}
    report["source_files"] = before
    try:
        validate_contract()
        source = SOURCE.read_bytes()
        report["compiler_source_sha256"] = digest(source)
        compiler, seed = build_seed(directory)
        report["stages"].append({"generation": "B0", "receipt": seed})
        for generation in ("B1", "B2", "B3"):
            compiler, receipt = compile_stage(directory, generation, compiler, source,
                image_format="seed-shared" if generation == "B1" else "flat-x86-64")
            report["stages"].append({"generation": generation, "receipt": receipt})
        report["fixed_point"] = len({row["receipt"]["produced_sha256"] for row in report["stages"][1:]}) == 1
        for case in cases():
            row = {key: value for key, value in case.items() if key != "source"}
            row["pass"] = False
            report["cases"].append(row)
            try:
                data = case["source"].encode()
                (directory / (case["id"] + ".hiaasm")).write_bytes(data)
                row["source_sha256"] = digest(data)
                row["reference"] = reference(case)
                observed, produced = invoke(directory, case["id"] + "-compile", compiler, data)
                row["compilation"] = observed
                accepted = (observed.get("status") == "returned" and observed.get("abi_status") == 0
                    and type(observed.get("core_u32")) is int and 0 < observed["core_u32"] <= CAPACITY)
                row["observed_compiler_acceptance"] = accepted
                if not case["expected_compiler_acceptance"]:
                    row["pass"] = bool(observed.get("status") == "returned" and observed.get("abi_status") == 0
                        and observed.get("core_u32") == INVALID and observed.get("output_unchanged")
                        and observed.get("source_unchanged") and not observed.get("forbidden_compiler_modules_loaded"))
                    continue
                if not accepted:
                    continue
                image = directory / (case["id"] + (".o" if case["output_format"] == "elf" else ".image.bin"))
                image.write_bytes(produced[:observed["core_u32"]])
                row["produced_sha256"] = digest(image.read_bytes())
                native_format = "flat-x86-64"
                if case["output_format"] == "elf":
                    linked = directory / (case["id"] + ".so")
                    row["link"] = observe_native_tool(directory, case["id"] + "-link", "ld",
                        ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack", "-z", "relro",
                         "-z", "now", "--build-id=none", image, "-lc", "-o", linked])
                    if row["link"]["returncode"]:
                        continue
                    image, native_format = linked, "linked-selfhost"
                native, native_output = invoke(directory, case["id"] + "-native", image, INPUT,
                    image_format=native_format, capacity=8, workspace_size=8, output_initial=INITIAL)
                row["native"] = native
                row["native_image_sha256"] = digest(image.read_bytes())
                row["pass"] = bool(native.get("status") == "returned" and native.get("abi_status") == 0
                    and native.get("core_u32") == case["expected_result"] and native.get("source_unchanged")
                    and native_output == INITIAL and observed.get("source_unchanged")
                    and not observed.get("forbidden_compiler_modules_loaded"))
            except Exception as error:
                row["error"] = {"type": type(error).__name__, "message": str(error)}
        if report["fixed_point"] and len(report["cases"]) == 9 and all(row["pass"] for row in report["cases"]):
            report["status"] = "PASS_FINITE_FEATURE_MATRIX"
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        after = {**source_manifest(), "tools/hia_selfhost_feature_matrix.py": digest(Path(__file__).read_bytes())}
        report["source_files_unchanged"] = before == after
        if before != after:
            report["status"] = "FAIL"
        report["wall_elapsed_ns"] = time.monotonic_ns() - started
        report["files"] = {path.relative_to(directory).as_posix(): {"bytes": path.stat().st_size,
            "sha256": digest(path.read_bytes())} for path in sorted(directory.rglob("*")) if path.is_file()}
        (directory / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "passed": sum(row["pass"] for row in result["cases"]),
                      "cases": len(result["cases"]), "error": result.get("error")}, sort_keys=True))
    return 0 if result["status"] == "PASS_FINITE_FEATURE_MATRIX" else 1


if __name__ == "__main__":
    raise SystemExit(main())
