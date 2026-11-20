"""Execute v9 VM, LLVM, direct x86 and self-hosted word-memory conformance.

No missing compiler or failed case is skipped. Outputs and native trap evidence
are retained outside the repository by the required --output argument.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import resource
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import _render_assembly_document, render_assembly
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm, compile_program_llvm
from hepta.hia_program_native import build_program_machine
from hepta.hia_program_runtime import execute_program
from tools.hia_word_memory_cases import ORDERS, expected, foreign_program, owned_program
from tools.hia_word_memory_allocator import qualify_allocator
from tools.qualify_hia_selfhost import compile_stage, invoke


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError({"argv": argv, "exit": result.returncode,
                            "stdout": result.stdout, "stderr": result.stderr})
    return {"argv": argv, "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def linked_selfhost(output, name, compiler, source):
    obj, receipt = compile_stage(output, name, compiler, source, output_extension=".o")
    library = output / (name + ".so")
    link = command(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    str(obj), "-o", str(library), "-lc"])
    return library, {"compilation": receipt, "link": link, "sha256": sha(library)}


def bind(library, name, arity):
    owner = ctypes.CDLL(str(library))
    fn = getattr(owner, name)
    fn.argtypes = [ctypes.c_uint64] * arity
    fn.restype = ctypes.c_uint64
    return owner, fn


def buffer_pointer(buffer, offset=0):
    return ctypes.addressof(ctypes.c_char.from_buffer(buffer, offset))


def child_trap(action, expected_signal):
    pid = os.fork()
    if pid == 0:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # RLIMIT_CORE alone does not suppress a system pipe-based core handler.
        # Disable dumpability in this disposable child, while retaining the
        # actual kernel signal status that distinguishes a guard from a fault.
        libc = ctypes.CDLL(None)
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # Linux PR_SET_DUMPABLE
            os._exit(98)
        signal.alarm(5)
        try:
            action()
        except BaseException:
            os._exit(99)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != expected_signal:
        raise AssertionError(("expected native trap", expected_signal, status))


def shared_buffer(size):
    return mmap.mmap(-1, size, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                     prot=mmap.PROT_READ | mmap.PROT_WRITE)


def raw_call(fn, tag, offset, value, target, result, *, size=None, target_offset=16):
    header = ctypes.create_string_buffer(bytes([tag]) + offset.to_bytes(8, "little")
                                         + value.to_bytes(8, "little"))
    size = len(target) - 32 if size is None else size
    return fn(ctypes.addressof(header), 17, buffer_pointer(target, target_offset), size,
              buffer_pointer(result, 16), len(result) - 32)


def qualify_raw(output, compiler, report):
    checked = verify_program(foreign_program())
    source = render_assembly(checked).encode()
    (output / "foreign.hepta").write_bytes(source)
    direct = output / "foreign-direct.so"
    direct_receipt = build_program_machine(
        checked, direct, linker="ld", foreign_buffer_exports=(("f0", 1 << 20),))
    native, selfhost_receipt = linked_selfhost(output, "foreign-selfhost", compiler, source)
    rows = []
    rng = random.Random(0x48494139)
    for label, path, trap_signal in (("direct", direct, signal.SIGABRT),
                                     ("selfhost", native, signal.SIGILL)):
        owner, fn = bind(path, "f0", 6)
        count = failures = 0
        for n in (8, 9, 15, 16, 31, 64, 4095, 4096, 4097):
            offsets = set(range(min(24, n - 7))) | {n - 8}
            for offset in sorted(offsets):
                for tag in range(4):
                    with shared_buffer(n + 32) as target, shared_buffer(40) as result:
                        original = bytes(rng.randrange(256) for _ in range(n + 32))
                        target[:] = original
                        result[:] = b"\xD7" * 40
                        value = rng.getrandbits(64)
                        code = raw_call(fn, tag, offset, value, target, result)
                        assert code == 8, (label, code)
                        order = "little" if tag % 2 == 0 else "big"
                        if tag < 2:
                            expected_value = int.from_bytes(original[16 + offset:24 + offset], order)
                            assert bytes(target) == original
                            assert result[:16] == b"\xD7" * 16 and result[24:] == b"\xD7" * 16
                            assert result[16:24] == expected_value.to_bytes(8, "little")
                        else:
                            changed = bytearray(original)
                            changed[16 + offset:24 + offset] = value.to_bytes(8, order)
                            assert bytes(target) == changed
                            assert result[:] == b"\xD7" * 40
                        count += 1
        for tag in range(4):
            cases = [(n, 0) for n in range(8)] + [
                (8, 1), (9, 2), (31, 24), (31, 31), (31, 32),
                (31, 1 << 32), (31, (1 << 32) + 1),
                (31, 1 << 63), (31, (1 << 64) - 1),
            ]
            for n, offset in cases:
                with shared_buffer(n + 32) as target, shared_buffer(40) as result:
                    target[:] = b"\xA5" * len(target)
                    result[:] = b"\xD7" * len(result)
                    before = bytes(target), bytes(result)
                    child_trap(lambda: raw_call(fn, tag, offset, 0x0123456789ABCDEF,
                                               target, result), trap_signal)
                    assert (bytes(target), bytes(result)) == before
                    failures += 1
        # The next page is inaccessible, so a speculative/partial access past
        # the complete range check has an observably different signal.
        page = mmap.PAGESIZE
        libc = ctypes.CDLL(None)
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        with shared_buffer(2 * page) as target, shared_buffer(40) as result:
            address = buffer_pointer(target)
            target[:page] = b"\xA5" * page
            assert libc.mprotect(address + page, page, 0) == 0
            try:
                for tag in range(4):
                    assert raw_call(fn, tag, page - 8, 7, target, result,
                                    size=page, target_offset=0) == 8
                    child_trap(lambda: raw_call(fn, tag, page - 7, 7, target, result,
                                               size=page, target_offset=0), trap_signal)
                    failures += 1
            finally:
                assert libc.mprotect(address + page, page,
                                     mmap.PROT_READ | mmap.PROT_WRITE) == 0
        rows.append({"backend": label, "valid_calls": count,
                     "trap_cases": failures, "trap_store_output_unchanged": True,
                     "guard_page_cases": 8, "library_sha256": sha(path)})
        del fn, owner

    # f33's Python seed wrapper intentionally caps individual loans at 1 MiB.
    # The B3-generated static ABI carries full u64 extents; this qualification
    # names that actual ABI and never relabels the bounded seed wrapper.
    owner, fn = bind(native, "f0", 6)
    high = (1 << 32) + 1
    with mmap.mmap(-1, high + 32, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS |
                   getattr(mmap, "MAP_NORESERVE", 0),
                   prot=mmap.PROT_READ | mmap.PROT_WRITE) as target, shared_buffer(40) as result:
        target[:16] = b"\xA5" * 16
        target[high - 1:high + 9] = b"\xD7" * 10
        for tag in range(4):
            value = 0xFEDCBA9876543210
            target[high:high + 8] = value.to_bytes(8, "little")
            result[:] = b"\xC3" * 40
            assert raw_call(fn, tag, high, value, target, result,
                            size=high + 8, target_offset=0) == 8
            if tag < 2:
                expected_value = int.from_bytes(value.to_bytes(8, "little"),
                                               "little" if tag == 0 else "big")
                assert result[16:24] == expected_value.to_bytes(8, "little")
            else:
                assert target[high:high + 8] == value.to_bytes(8, "little" if tag == 2 else "big")
            assert target[:16] == b"\xA5" * 16
            assert target[high - 1] == 0xD7 and target[high + 8] == 0xD7
    report["raw"] = {"backends": rows, "high_offset": high, "high_offset_calls": 4,
                     "high_offset_backend": "B3 static foreign ABI",
                     "direct_receipt": direct_receipt, "selfhost_receipt": selfhost_receipt}
    report["source_hashes"]["foreign"] = hashlib.sha256(source).hexdigest()
    return checked


def qualify_refusals(output, compiler, original):
    variants = {}
    for version in (6, 7, 8):
        bad = copy.deepcopy(original.as_dict())
        bad["schema"] = f"hepta.hia.program.v{version}"
        variants[f"old-schema-{version}"] = bad
    for change in ("offset", "value", "result", "attributes", "effects", "readonly"):
        bad = copy.deepcopy(original.as_dict())
        fn = bad["functions"][0]
        word = next(op for b in fn["blocks"] for op in b["ops"]
                    if op["op"] == "buffer.store.u64.le")
        if change == "offset":
            word["args"][1] = word["args"][2]
        elif change == "value":
            word["args"][2] = word["args"][1]
        elif change == "result":
            word["out"] = [{"name": "unexpected_word_result", "type": "u64"}]
        elif change == "attributes":
            word["attrs"] = {"unchecked": True}
        elif change == "effects":
            fn["effects"].remove("trap")
        else:
            # Typed owned-module fixture replaces the writer with a readonly
            # loan so the resulting instruction is rejected by both checkers.
            bad = owned_program()
            target = bad["functions"][2]["blocks"][0]["ops"][1]
            target["op"] = "borrow.read"
            target["out"][0]["type"] = "readbuf"
        variants[change] = bad
    rows = []
    for name, document in variants.items():
        try:
            verify_program(document)
        except HIAProgramRejected as error:
            reference = error.code
        else:
            raise AssertionError(("checker accepted invalid word source", name))
        # This construction-only renderer grants no admission. Core has already
        # rejected the object; the independent native compiler must reject bytes.
        text = _render_assembly_document(document)
        result, _ = invoke(output, "refusal-" + name, compiler, text.encode(),
                           output_initial=b"\xA5" * (1 << 20))
        assert result.get("status") == "returned" and result.get("core_u32") == 0xFFFFFFFF, (name, result)
        assert result.get("output_unchanged") is True, (name, result)
        rows.append({"case": name, "reference_code": reference, "receipt": result})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.word-memory-qualification.v1", "complete": False,
              "started": time.time(), "source_hashes": {}, "compiler_sha256": sha(args.compiler)}
    try:
        checked = verify_program(owned_program())
        source = render_assembly(checked).encode()
        (args.output / "owned.hepta").write_bytes(source)
        report["source_hashes"]["owned"] = hashlib.sha256(source).hexdigest()
        direct, llvm = args.output / "owned-direct.so", args.output / "owned-llvm.so"
        report["direct_build"] = build_program_machine(checked, direct, linker="ld")
        report["llvm_commands"] = []
        report["llvm_build"] = build_program_native(
            checked, llvm, clang=args.clang, command_log=report["llvm_commands"])
        native, report["selfhost_build"] = linked_selfhost(args.output, "owned-selfhost", args.compiler, source)
        libraries = [(label, path, ctypes.CDLL(str(path))) for label, path in (
            ("direct", direct), ("llvm", llvm), ("selfhost", native))]
        comparisons = 0
        for mode in ("load", "store"):
            for order in ORDERS:
                name = mode + "_" + order
                functions = []
                for label, path, owner in libraries:
                    fn = getattr(owner, name)
                    fn.argtypes = [ctypes.c_uint64] * 4
                    fn.restype = ctypes.c_uint64
                    functions.append((label, fn))
                for n in (8, 9, 17, 32, 64):
                    for offset in sorted({0, min(1, n - 8), n - 8}):
                        for value in (0, 1, 0x0123456789ABCDEF, (1 << 64) - 1):
                            for probe in sorted({0, offset, offset + 7, n - 1}):
                                actual = execute_program(checked, name, [n, offset, value, probe])["result"]
                                oracle = expected(mode, order, n, offset, value, probe)
                                assert actual == oracle
                                for label, fn in functions:
                                    assert fn(n, offset, value, probe) == oracle, (label, name, n, offset, value, probe)
                                    comparisons += 1
        report["scalar_comparisons"] = comparisons
        report["cross_objects"] = []
        for target in ("aarch64-unknown-linux-gnu", "riscv64-unknown-linux-gnu"):
            ir = emit_program_llvm(checked, target=target)
            result = compile_program_llvm(ir, program=checked,
                output=args.output / (target + ".o"), clang=args.clang, kind="object")
            report["cross_objects"].append(result)
        foreign = qualify_raw(args.output, args.compiler, report)
        report["allocator_witness"] = qualify_allocator(
            args.output, args.clang, command, sha, shared_buffer, buffer_pointer, child_trap)
        report["refusals"] = qualify_refusals(args.output, args.compiler, foreign)
        report["complete"] = True
    except BaseException:
        report["error"] = traceback.format_exc()
        raise
    finally:
        report["finished"] = time.time()
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: report.get(k) for k in ("complete", "scalar_comparisons", "error")}))


if __name__ == "__main__":
    main()
