"""Actual AArch64 execution of a finite standalone HIA Core corpus.

This harness consumes independently verified Core, not a source AST. It reuses
the exact reviewed 4096-byte, one-live-allocation runtime primitives, adding a
calloc adapter and a fixed scalar C ABI driver. QEMU userspace execution is
reported separately from physical hardware or a production runtime.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import stat
import tempfile

from .clang_capture import run_bounded
from .hia_program import verify_program
from .hia_program_llvm import TARGET_AARCH64, compile_program_llvm, emit_program_llvm
from .native_tool_identity import digest_executable
from .object_symbols import inspect_object_symbols
from .owned_aarch64_link import inspect_synthetic_aarch64_elf


PROFILE = "hepta.hia.program.aarch64-finite-runtime.v1"
REVIEWED_RUNTIME_SHA256 = "5caa9cbc33df5734626ff17045159add08b850abceb021b038ddb110db6f402c"
QEMU_SHA256 = "e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e"
_FIXTURE = Path(__file__).resolve().parents[1] / "examples/llvm_owned/finite_aarch64_runtime.c"
_MARKER = b"/* Exact selected Hepta export; unlike the synthetic stub, invoked for real. */"
_RUNTIME_EXPORTS = frozenset({"malloc", "calloc", "free", "abort", "memcpy", "memmove", "memset", "_start"})
_TYPES = {"usize": "hepta_size", "u8": "hepta_u8", "i8": "signed char", "u32": "hepta_u32",
          "u64": "hepta_u64", "i64": "__INT64_TYPE__", "bool": "_Bool"}
_SIGNATURES = {
    "fill_sum": (["usize", "u8"], ["u64"]),
    "try_capacity": (["usize"], ["u64"]),
    "scalar_mix": (["i64", "i64", "bool"], ["i64"]),
    "tuple_call": (["u64", "u64"], ["u64"]),
    "bool_gate": (["bool", "bool"], ["bool"]),
    "int_add_wrap_u32": (["u32", "u32"], ["u32"]),
    "int_div_checked_i64": (["i64", "i64"], ["i64"]),
    "int_shr_checked_i64": (["i64", "i64"], ["i64"]),
    "cast_i8_u64": (["u64"], ["i8"]),
    "bounds_trap": (["usize"], ["u8"]),
    "move_bytes": (["usize", "usize", "usize", "usize", "usize"], ["u8"]),
}

# The native harness checks these same fixed values after real ABI calls.
# The capacity rejection uses a real NULL from the finite target allocator;
# the interpreter compares that case with its explicit allocation failure hook.
CASES = (
    ("fill_sum", (16, 7), 112, None),
    ("fill_sum", (0, 255), 0, None),
    ("fill_sum", (128, 3), 384, None),
    ("fill_sum", (4096, 1), 4096, None),
    ("try_capacity", (16,), 16, None),
    ("try_capacity", (5000,), 99, 1),
    ("try_capacity", (0,), 0, None),
    ("try_capacity", ((1 << 64) - 1,), 99, None),
    ("scalar_mix", (12, 3, True), 26, None),
    ("scalar_mix", (-8, 7, False), -8, None),
    ("tuple_call", (8, 23), 15, None),
    ("bool_gate", (False, True), True, None),
    ("bool_gate", (False, False), False, None),
    ("int_add_wrap_u32", ((1 << 32) - 1, 1), 0, None),
    ("int_div_checked_i64", (-1024, 7), -146, None),
    ("int_shr_checked_i64", (-1024, 3), -128, None),
    ("cast_i8_u64", (255,), -1, None),
)

# Eight real ABI calls use one allocated 5-byte owner per invocation. The
# expected values exercise both overlap directions, an identical range,
# zero-length movement and normal Drop of every owner.
_OVERLAP_CASES = (
    ((5, 1, 0, 4, 0), 11),
    ((5, 1, 0, 4, 2), 22),
    ((5, 1, 0, 4, 4), 44),
    ((5, 0, 1, 4, 0), 22),
    ((5, 0, 1, 4, 3), 55),
    ((5, 2, 2, 3, 4), 55),
    ((5, 5, 5, 0, 0), 11),
    ((5, 0, 0, 0, 4), 55),
)


_ADAPTER = r"""
/* The standalone Core requests zero-filled bytes through this exact adapter. */
__attribute__((noinline)) void *calloc(hepta_size count, hepta_size width) {
    if (width && count > ((hepta_size)-1) / width) {
        ++denied_allocations;
        return (void *)0;
    }
    hepta_size bytes = count * width;
    void *result = malloc(bytes);
    if (result) memset(result, 0, bytes);
    return result;
}

static void write_counters(void) {
    char text[96];
    hepta_size used = 0;
    const char prefix[] = "HIA_AARCH64 resources ";
    for (hepta_size i = 0; i < sizeof(prefix) - 1; ++i) text[used++] = prefix[i];
    hepta_u32 values[4] = {successful_allocations, releases, outstanding, denied_allocations};
    for (hepta_size i = 0; i < 4; ++i) {
        char digits[10];
        hepta_size n = 0;
        hepta_u32 v = values[i];
        do { digits[n++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (n) text[used++] = digits[--n];
        text[used++] = i == 3 ? '\n' : ' ';
    }
    register long x0 __asm__("x0") = 1;
    register const char *x1 __asm__("x1") = text;
    register hepta_size x2 __asm__("x2") = used;
    register long x8 __asm__("x8") = 64;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    if (x0 != (long)used) hepta_exit(40);
}
"""


class HIAProgramAArch64Rejected(ValueError):
    pass


def _reject(message):
    raise HIAProgramAArch64Rejected("E_HIA_PROGRAM_AARCH64: " + message)


def _read(path, limit):
    """Bound file size before allocation and reject path/fd replacement."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        _reject("expected a bounded ordinary file: " + str(path))
    key = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        if key(os.fstat(stream.fileno())) != key(before):
            _reject("file changed before reading")
        raw = stream.read(limit + 1)
        if len(raw) != before.st_size or key(os.fstat(stream.fileno())) != key(before):
            _reject("file changed during reading")
    if key(path.lstat()) != key(before):
        _reject("file pathname changed after reading")
    return raw


def _runtime_prefix():
    raw = _read(_FIXTURE, 8192)
    if sha256(raw).hexdigest() != REVIEWED_RUNTIME_SHA256 or raw.count(_MARKER) != 1:
        _reject("reviewed finite runtime identity changed")
    return raw.split(_MARKER)[0].decode("ascii")


def _implementation_hash():
    digest = sha256()
    for name in ("hia_program_aarch64.py", "owned_aarch64_link.py"):
        digest.update(name.encode("ascii") + b"\0" + _read(Path(__file__).with_name(name), 65536))
    return digest.hexdigest()


def _literal(value, typ):
    if typ == "bool":
        return "1" if value else "0"
    return "((" + _TYPES[typ] + ")" + str(value) + ("ULL" if value >= 0 else "LL") + ")"


def _runtime_source(document, mode):
    if mode not in {"matrix", "bounds_trap", "overlap_move"}:
        _reject("unsupported fixed target driver mode")
    functions = {fn["name"]: fn for fn in document["functions"]}
    required = ({row[0] for row in CASES} if mode == "matrix"
                else {"move_bytes"} if mode == "overlap_move" else {"bounds_trap"})
    declarations = []
    for name in sorted(required):
        params, returns = _SIGNATURES[name]
        fn = functions.get(name)
        if (fn is None or [p["type"] for p in fn["params"]] != params
                or fn["returns"] != returns):
            _reject("fixed runtime scalar ABI mismatch for " + name)
        declarations.append("extern " + _TYPES[returns[0]] + " " + name + "(" +
                            ", ".join(_TYPES[typ] for typ in params) + ");")
    lines = ["static int smoke(void) {", "    if (!memory_primitives_ok()) return 39;"]
    if mode == "matrix":
        for index, (name, arguments, expected, _) in enumerate(CASES):
            params, returns = _SIGNATURES[name]
            call = name + "(" + ", ".join(_literal(v, t) for v, t in zip(arguments, params)) + ")"
            lines.append("    if (" + call + " != " + _literal(expected, returns[0]) + ") return " + str(11 + index) + ";")
        lines += ["    write_counters();",
                  "    if (successful_allocations != 4 || releases != 4 || outstanding != 0 || denied_allocations != 1) return 38;",
                  "    return 0;"]
    elif mode == "overlap_move":
        # This is the same fixed scalar ABI + arena as the historical corpus.
        # Only the single 5-byte owned buffer is live during each call;
        # memmove must preserve overlapping original byte values.
        params, returns = _SIGNATURES["move_bytes"]
        for index, (arguments, expected) in enumerate(_OVERLAP_CASES):
            call = "move_bytes(" + ", ".join(
                _literal(v, t) for v, t in zip(arguments, params)) + ")"
            lines.append("    if (" + call + " != " +
                         _literal(expected, returns[0]) + ") return " + str(50 + index) + ";")
        lines += ["    write_counters();",
                  "    if (successful_allocations != 8 || releases != 8 || outstanding != 0 || denied_allocations != 0) return 79;",
                  "    return 0;"]
    else:
        # Reaching this would demonstrate that the expected trap was absent.
        lines += ["    (void)bounds_trap(1);", "    write_counters();", "    return 41;"]
    lines += ["}", "__attribute__((noreturn)) void _start(void) { hepta_exit((hepta_u32)smoke()); }"]
    return _runtime_prefix() + _ADAPTER + "\n".join(declarations + lines) + "\n", required


def _tool(path, role):
    found = shutil.which(path)
    if found is None:
        _reject(role + " unavailable")
    resolved = Path(found).resolve(strict=True)
    return resolved, digest_executable(resolved)


def run_finite_program_aarch64(program, *, clang, linker, qemu_aarch64, mode="matrix"):
    """Compile a separately verified Core and execute the fixed driver in QEMU.

    This returns the actual exit code, including deliberate negative controls.
    Qualification callers must assess that exit code and retained evidence.
    """
    verified = verify_program(program)
    ir = emit_program_llvm(verified, target=TARGET_AARCH64)
    own_before = _implementation_hash()
    compiler, compiler_sha = _tool(clang, "Clang")
    lld, linker_sha = _tool(linker, "LLVM lld")
    runner, runner_sha = _tool(qemu_aarch64, "QEMU AArch64")
    if runner_sha != QEMU_SHA256:
        _reject("QEMU runner differs from the exact reviewed 8.2.2 executable")
    runtime, required = _runtime_source(verified.as_dict(), mode)
    runner_version = run_bounded([str(runner), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    linker_version = run_bounded([str(lld), "-flavor", "gnu", "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    if runner_version.returncode or linker_version.returncode or "LLD" not in linker_version.stdout:
        _reject("real target runner or LLVM linker identity unavailable")
    with tempfile.TemporaryDirectory(prefix=".hia-aarch64-") as directory:
        folder = Path(directory)
        core_obj, runtime_c = folder / "core.o", folder / "runtime.c"
        runtime_obj, executable = folder / "runtime.o", folder / "core.elf"
        core_receipt = compile_program_llvm(ir, program=verified, output=core_obj, clang=str(compiler), kind="object")
        runtime_c.write_text(runtime, encoding="ascii")
        compile_command = [str(compiler), "--target=" + TARGET_AARCH64, "-x", "c", "-std=c11",
                           "-ffreestanding", "-nostdinc", "-fno-builtin", "-fno-stack-protector",
                           "-O2", "-Wall", "-Wextra", "-Werror", "-c", str(runtime_c), "-o", str(runtime_obj)]
        compiled = run_bounded(compile_command, timeout=35, stdout_limit=65536, stderr_limit=1048576)
        if compiled.returncode:
            _reject("finite target runtime compile failed: " + compiled.stderr[:2000])
        runtime_bytes = _read(runtime_obj, 1048576)
        inventory = inspect_object_symbols(runtime_bytes, "ELF64", 183)
        if inventory["defined"] != _RUNTIME_EXPORTS or inventory["undefined"] != frozenset(required):
            _reject("finite target runtime ABI inventory mismatch")
        # Invoke the existing LLVM linker directly; no Rust frontend is run.
        link_command = [str(lld), "-flavor", "gnu", "-m", "aarch64linux", "-static", "-z", "noexecstack",
                        "-e", "_start", str(core_obj), str(runtime_obj), "-o", str(executable)]
        linked = run_bounded(link_command, timeout=45, stdout_limit=65536, stderr_limit=1048576)
        if linked.returncode:
            _reject("direct standalone AArch64 link failed: " + linked.stderr[:2000])
        payload = _read(executable, 16777216)
        # This reusable parser checks exact static ELF shape and symbol inventory;
        # it neither emits old source code nor substitutes synthetic execution.
        shape = inspect_synthetic_aarch64_elf(payload, tuple(ir.exports) + ("calloc",))
        execution = run_bounded([str(runner), str(executable)], timeout=25, stdout_limit=65536, stderr_limit=65536)
        if (_read(executable, 16777216) != payload or
                sha256(_read(core_obj, 16777216)).hexdigest() != core_receipt["artifact_sha256"] or
                _read(runtime_obj, 1048576) != runtime_bytes or
                _runtime_source(verified.as_dict(), mode)[0] != runtime or
                emit_program_llvm(verified, target=TARGET_AARCH64) != ir or
                _implementation_hash() != own_before or
                any(digest_executable(path) != digest for path, digest in
                    [(compiler, compiler_sha), (lld, linker_sha), (runner, runner_sha)])):
            _reject("target tool, source, core or executable changed during execution")
    return {"schema": PROFILE, "ok": True, "status": "finite_qemu_execution_observed", "mode": mode,
            "target": TARGET_AARCH64, "core_sha256": verified.sha256, "core_object": core_receipt,
            "llvm_ir": ir.text, "llvm_ir_sha256": ir.sha256, "harness_implementation_sha256": own_before,
            "reviewed_runtime_sha256": REVIEWED_RUNTIME_SHA256,
            "runtime_source": runtime, "runtime_source_sha256": sha256(runtime.encode()).hexdigest(),
            "runtime_object_sha256": sha256(runtime_bytes).hexdigest(),
            "linked_sha256": sha256(payload).hexdigest(), "linked_bytes": len(payload), "elf_inventory": shape,
            "runner": {"path": str(runner), "sha256": runner_sha, "version": runner_version.stdout.splitlines()[0]},
            "linker": {"path": str(lld), "sha256": linker_sha, "version": linker_version.stdout.splitlines()[0]},
            "execution": {"returncode": execution.returncode, "stdout": execution.stdout, "stderr": execution.stderr},
            "runtime_compile_flags": compile_command[1:-4], "link_flags": link_command[1:-4],
            "scope": "fixed scalar ABI corpus; 4096-byte arena with at most one live allocation; Linux userspace QEMU",
            "claims": {"standalone_core_reverified": True, "qemu_userspace_executed": True,
                       "physical_target_executed": False, "general_allocator_qualified": False,
                       "source_ast_used": False, "rust_frontend_used": False, "rust_codegen_used": False,
                       "backend_refinement_proved": False, "whole_language_soundness_proved": False}}
