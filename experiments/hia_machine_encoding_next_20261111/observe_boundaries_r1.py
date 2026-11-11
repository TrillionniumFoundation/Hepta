"""Observe native ABI refusal, nonzero alignment, foreign register order and the real 64 MiB boundary."""
from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_bridge():
    spec = importlib.util.spec_from_file_location("boundary_encoding_bridge", HERE / "native_encoding_bridge.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def state(code, error, events=None):
    return {"data_hex": code.data.hex(), "labels": dict(code.labels),
            "fixups": list(code.fixups), "relocations": list(code.relocations),
            "exception": error, "events": events or []}


def invoke(code, method, args):
    try:
        getattr(code, method)(*args)
        return None
    except BaseException as exc:
        return {"type": type(exc).__name__, "message": str(exc)}


def abi_cases(bridge):
    base = [bridge.MAGIC, bridge.COMMAND_IDS["ret"], 0, 0, 0, 0, 0, 0]
    rows = []
    def add(name, fields=None, slen=64, olen=80, wlen=8, accepted=False):
        values = list(base)
        for index, value in (fields or {}).items():
            values[index] = value & ((1 << 64) - 1)
        rows.append({"id": name, "words": values, "source_length": slen,
                     "output_length": olen, "workspace_length": wlen, "accepted": accepted})
    add("valid-ret", accepted=True)
    add("valid-maximum-alignment-output", {1: 1, 5: 64, 7: 1}, accepted=True)
    add("wrong-magic", {0: bridge.MAGIC ^ 1})
    for length in (0, 1, 63, 65):
        add("source-length-" + str(length), slen=length)
    for length in (0, 79):
        add("output-length-" + str(length), olen=length)
    for length in (0, 7):
        add("workspace-length-" + str(length), wlen=length)
    for command in (0, 38, (1 << 64) - 1):
        add("invalid-command-" + str(command), {1: command})
    for index in (2, 3):
        add("register-16-field-" + str(index), {index: 16})
    add("mode-2", {6: 2})
    for command in (4, 37):
        for value in ((1 << 31), -(1 << 31) - 1):
            add("signed32-" + str(command) + "-" + str(value), {1: command, 4: value})
    add("alu-group-6", {1: 16, 5: 6})
    add("alu-width-2", {1: 16, 7: 2})
    for value in (128, -129):
        add("alu-short-width-" + str(value), {1: 16, 4: value, 7: 1})
    add("shift-group-3", {1: 17, 5: 3})
    add("shift-count-64", {1: 17, 4: 64})
    for command in (26, 27, 34):
        add("condition-16-" + str(command), {1: command, 5: 16})
    for boundary in (0, 2, 3, 65):
        add("invalid-alignment-" + str(boundary), {1: 1, 5: boundary})
    return rows


def run_abi(encoding, bridge, row):
    packet = struct.pack("<8Q", *row["words"])
    before = [b"\x31" * 16 + packet + b"\x32" * 16,
              b"\x41" * 16 + b"\xa5" * 80 + b"\x42" * 16,
              b"\x51" * 16 + b"\x5a" * 8 + b"\x52" * 16]
    buffers = [ctypes.create_string_buffer(raw, len(raw)) for raw in before]
    result = encoding._entry(ctypes.addressof(buffers[0]) + 16, row["source_length"],
        ctypes.addressof(buffers[1]) + 16, row["output_length"],
        ctypes.addressof(buffers[2]) + 16, row["workspace_length"])
    after = [buffer.raw for buffer in buffers]
    if row["accepted"]:
        expected = b"\xc3" if row["id"] == "valid-ret" else b"\x90" * 63
        wanted_output = b"\x41" * 16 + struct.pack("<Q", len(expected)) + expected + b"\xa5" * (72 - len(expected)) + b"\x42" * 16
        wanted_workspace = b"\x51" * 16 + struct.pack("<Q", 8 + len(expected)) + b"\x52" * 16
        equal = result == 0 and after == [before[0], wanted_output, wanted_workspace]
    else:
        equal = result == 0xfffffffd and after == before
    return {**row, "status": result, "before_hex": [x.hex() for x in before],
            "after_hex": [x.hex() for x in after], "equal": equal}


def foreign_register(factory, row):
    code = factory()
    events = []
    class Mapping:
        def __init__(self):
            self.count = 0
        def get(self, key, default):
            answer = row["answers"][self.count]
            self.count += 1
            events.append([key, default, answer])
            return answer
    code.scratch_registers = Mapping()
    error = invoke(code, row["method"], row["args"])
    return state(code, error, events)


def retained_large(directory, name, code, error):
    raw = bytes(code.data)
    packed = gzip.compress(raw, compresslevel=1, mtime=0)
    path = directory / (name + ".data.gz")
    path.write_bytes(packed)
    if gzip.decompress(path.read_bytes()) != raw:
        raise AssertionError("retained complete Code bytes differ")
    result = {"data_bytes": len(raw), "data_sha256": sha(raw), "data_path": path.name,
              "compressed_bytes": len(packed), "compressed_sha256": sha(packed),
              "labels": dict(code.labels), "fixups": list(code.fixups),
              "relocations": list(code.relocations), "exception": error}
    return raw, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    bridge = load_bridge()
    from hepta.hia_machine_x64 import Code, MAX_CODE_BYTES
    from hepta.hia_json_preflight_native import _installed_json_image
    manifest = json.loads(args.manifest.read_bytes())
    image = args.manifest.parent / manifest["image_path"]
    from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH
    def pins():
        result = file_digests(ROOT)
        for path in (ROOT / CONTRACT_PATH, Path(__file__), HERE / "native_encoding_bridge.py",
                     args.manifest.resolve(), args.source.resolve(), image.resolve()):
            result[str(path.resolve())] = sha(path.read_bytes())
        return result
    before = pins()
    report = {"schema": "hepta.hia.machine-encoding.boundary-observation.v1",
              "scope": "DEVELOPMENT_NUMERIC_BYTE_OWNER_NOT_FULL_BACKEND_OR_RELEASE",
              "status": "STARTED", "python": sys.version, "before": before,
              "original_max_code_bytes": MAX_CODE_BYTES, "abi": [], "alignment": [],
              "foreign_registers": [], "large_partial_states": []}
    started = time.monotonic()
    try:
        if MAX_CODE_BYTES != 64 * 1024 * 1024:
            raise AssertionError("original code-byte gate changed")
        encoding = _installed_json_image(str(args.manifest.resolve()), args.source.resolve(),
                                         manifest["schema"], bridge.NativeMachineEncoding)
        selected = bridge.selected_code_class(encoding)
        abi = abi_cases(bridge)
        report["abi_denominator"] = len(abi)
        for row in abi:
            actual = run_abi(encoding, bridge, row)
            report["abi"].append(actual)
            if not actual["equal"]:
                raise AssertionError("ABI no-write observation differs: " + row["id"])
        report["alignment_denominator"] = 64 * 4
        for offset in range(64):
            for boundary in (1, 16, 32, 64):
                original, candidate = Code(), selected()
                original.data = bytearray(b"\xcc" * offset)
                candidate.data = bytearray(b"\xcc" * offset)
                expected = state(original, invoke(original, "align", [boundary]))
                actual = state(candidate, invoke(candidate, "align", [boundary]))
                row = {"offset": offset, "boundary": boundary, "reference": expected,
                       "candidate": actual, "equal": expected == actual}
                report["alignment"].append(row)
                if not row["equal"]:
                    raise AssertionError("nonzero alignment observation differs")
        register_rows = [
            {"id": "mov-source-before-destination", "method": "mov_rr", "args": ["r10", "r11"], "answers": ["r10", "r11"]},
            {"id": "imul-destination-before-source", "method": "imul", "args": ["r10", "r11"], "answers": ["r11", "r10"]},
            {"id": "load-register-before-address", "method": "load", "args": ["r10", "r11", 3], "answers": ["r10", "r11"]},
            {"id": "setcc-observes-register-twice", "method": "setcc", "args": ["ne", "r10"], "answers": ["r10", "r11"]},
            {"id": "setcc-second-register-refusal", "method": "setcc", "args": ["ne", "r10"], "answers": ["r10", "invalid"]},
            {"id": "cmov-destination-before-source", "method": "cmov", "args": ["ne", "r10", "r11"], "answers": ["r11", "r10"]},
        ]
        report["foreign_register_denominator"] = len(register_rows)
        for row in register_rows:
            expected, actual = foreign_register(Code, row), foreign_register(selected, row)
            report["foreign_registers"].append({**row, "reference": expected, "candidate": actual, "equal": expected == actual})
            if expected != actual:
                raise AssertionError("foreign register observation differs: " + row["id"])
        large_rows = [
            {"id": "jmp-prefix-and-fixup-before-refusal", "free": 2, "method": "jmp", "args": ["target"], "options": {}},
            {"id": "jcc-prefix-and-fixup-before-refusal", "free": 3, "method": "jcc", "args": ["ne", "target"], "options": {}},
            {"id": "call-prefix-and-relocation-before-refusal", "free": 2, "method": "call", "args": ["external"], "options": {}},
            {"id": "setcc-movabs-before-refusal", "free": 11, "method": "setcc", "args": ["ne", "r10"], "options": {}},
            {"id": "setcc-mov32-before-refusal", "free": 6, "method": "setcc", "args": ["ne", "r10"], "options": {"move_immediate": "mov32_if_exact"}},
        ]
        report["large_partial_state_denominator"] = len(large_rows)
        for row in large_rows:
            original, candidate = Code(**row["options"]), selected(**row["options"])
            initial = MAX_CODE_BYTES - row["free"]
            original.data = bytearray(b"\xcc") * initial
            candidate.data = bytearray(b"\xcc") * initial
            expected_error = invoke(original, row["method"], row["args"])
            actual_error = invoke(candidate, row["method"], row["args"])
            expected_bytes, expected = retained_large(directory, row["id"] + ".reference", original, expected_error)
            actual_bytes, actual = retained_large(directory, row["id"] + ".candidate", candidate, actual_error)
            metadata = ("data_bytes", "data_sha256", "labels", "fixups", "relocations", "exception")
            equal = expected_bytes == actual_bytes and all(expected[key] == actual[key] for key in metadata)
            report["large_partial_states"].append({**row, "initial_data_bytes": initial,
                "reference": expected, "candidate": actual, "equal": equal})
            if not equal:
                raise AssertionError("real 64 MiB partial state differs: " + row["id"])
            del expected_bytes, actual_bytes, original, candidate
        report["native_calls_by_command"] = dict(encoding.calls)
        report["status"] = "PASS"
    except BaseException:
        report["status"] = "FAIL"
        report["exception"] = traceback.format_exc()
    report["after"] = pins()
    report["source_stable"] = report["after"] == before
    if not report["source_stable"]:
        report["status"] = "FAIL"
    report["seconds"] = time.monotonic() - started
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("schema", "status", "source_stable", "seconds")} |
                     {"counts": {key: len(report[key]) for key in ("abi", "alignment", "foreign_registers", "large_partial_states")},
                      "exception": report.get("exception")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

