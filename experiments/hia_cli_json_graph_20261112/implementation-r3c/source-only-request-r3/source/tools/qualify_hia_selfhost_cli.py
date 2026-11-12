"""Finite, source-bound syscall-only executable compiler qualification.

The independent VM references are established before B0. Successor processes
then consume stdin and produce stdout without Python, libc, ld or PT_INTERP.
The Python child is only disposable test setup and execs the admitted ELF.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1 << 20


def echo_source():
    from tools.hia_selfhost_cases import HEADER
    return (HEADER + '  v3:usize = const() {"value":0}\n'
        '  v4:u8 = buffer.load(v0,v3)\n  _ = buffer.store(v1,v3,v4)\n'
        '  v5:u32 = const() {"value":1}\n  ret(v5)\nend\n').encode()


def output_capacity_source():
    """Ordinary valid Core, bounded source/SSA/op counts, >1 MiB native code."""
    from tools.hia_selfhost_cases import HEADER
    source = HEADER
    for i in range(8):
        source += f'  v{i+3}:u64 = const() {{"value":{i}}}\n'
    source += '  v11:u64 = call(v3,v4,v5,v6,v7,v8,v9,v10) {"function":"f1"}\n'
    source += '  v12:u32 = const() {"value":0}\n  ret(v12)\nend\n'
    params = ",".join(f"v{i}:u64" for i in range(8))
    argv = ",".join(f"v{i}" for i in range(8))
    for fn in range(1, 121):
        source += f"fn f{fn}({params}) -> (u64) effects() entry(b0)\nblock b0({params})\n"
        if fn == 120:
            source += "  ret(v0)\nend\n"
        else:
            for i in range(60):
                source += f'  v{i+8}:u64 = call({argv}) {{"function":"f120"}}\n'
            source += "  ret(v67)\nend\n"
    return source.encode()


def inspect_executable(raw):
    if len(raw) <= 176 or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9):
        raise ValueError("not a canonical ELF64 executable")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if header != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0):
        raise ValueError("unexpected executable entry/header")
    load = struct.unpack_from("<IIQQQQQQ", raw, 64)
    stack = struct.unpack_from("<IIQQQQQQ", raw, 120)
    if load != (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096):
        raise ValueError("executable PT_LOAD differs from actual bytes")
    if stack != (0x6474e551, 6, 0, 0, 0, 0, 0, 16):
        raise ValueError("executable GNU_STACK differs")
    return {"elf_type": "ET_EXEC", "machine": "EM_X86_64", "entry": header[3],
        "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"],
        "interpreter": None, "dynamic_loader": False, "libc": False,
        "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def limit_source():
    extra = "".join(f'  v{i}:u64 = const() {{"value":{i}}}\n' for i in range(6, 134))
    return echo_source().replace(b'  v5:u32 = const()', extra.encode() + b'  v5:u32 = const()')


def padded_source(source):
    # Whitespace must preserve the supported grammar's exact newline positions.
    # Spread spaces over existing nonempty lines; never add a giant line or
    # unsupported blank-line sequence to manufacture an admission failure.
    remaining = CAPACITY - len(source)
    lines = source.splitlines(keepends=True)
    result = []
    for line in lines:
        count = min(remaining, 16000 - len(line))
        if count < 0:
            raise ValueError("fixture line is already too long")
        result.append(b" " * count + line)
        remaining -= count
    if remaining:
        raise ValueError("too few source lines for a Core-admissible exact-capacity control")
    return b"".join(result)


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_loans import reference_source
    source = echo_source()
    rows = []
    for byte in (0, 73, 255):
        case = {"source": source.decode(), "source_hex": bytes([byte]).hex(), "initial_hex": "a5"}
        checked = assemble_program(reference_source(case))
        result = execute_program(checked, "reference_entry", [])
        if (result["values"] != [1, byte] or result["resources"]["live_owners"]
                or result["resources"]["live_local_loans"]):
            raise AssertionError(result)
        rows.append({"input_hex": bytes([byte]).hex(), "output_hex": bytes([byte]).hex(),
            "core_sha256": checked.sha256, "result": result})
    large = output_capacity_source()
    if len(large) >= CAPACITY:
        raise AssertionError("capacity control exceeds source bound")
    checked_large = assemble_program(large)
    padded = padded_source(limit_source())
    checked_padded = assemble_program(padded)
    return {"before_B0": True, "echo_source": source.decode(), "echo": rows,
        "padded_core_sha256": checked_padded.sha256, "limit_source": limit_source().decode(),
        "output_capacity_source": large.decode(), "output_capacity_core_sha256": checked_large.sha256,
        "all_input_correctness_proved": False, "whole_stack_rewrite_complete": False}


def execute(directory, name, executable, source, *, mode="ordinary", arguments=()):
    from tools.hia_selfhost_process_owner import run_owned
    directory = Path(directory) / name
    directory.mkdir()
    executable = Path(executable).resolve(strict=True)
    source_path = (directory / "stdin.raw").absolute()
    source_path.write_bytes(source)
    image = executable.read_bytes()
    request = {"executable": str(executable), "executable_sha256": sha256(image).hexdigest(),
        "input": str(source_path), "input_sha256": sha256(source).hexdigest(),
        "mode": mode, "arguments": list(arguments)}
    raw = json.dumps(request, sort_keys=True).encode()
    path = (directory / "request.json").absolute()
    path.write_bytes(raw)
    child = ROOT / "tools/hia_selfhost_cli_child.py"
    receipt = run_owned([sys.executable, "-I", "-S", "-B", str(child),
        "--request", str(path), "--sha256", sha256(raw).hexdigest()],
        cwd=str(directory.absolute()), env={"PATH": "/usr/bin:/bin", "HOME": str(directory.absolute()),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"},
        stdout_path=directory / "stdout.raw", stderr_path=directory / "stderr.raw",
        receipt_path=directory / "owner.json", qualification_seconds=15)
    output = (directory / "stdout.raw").read_bytes()
    stderr = (directory / "stderr.raw").read_bytes()
    if (executable.read_bytes() != image or source_path.read_bytes() != source
            or path.read_bytes() != raw):
        raise AssertionError("native CLI input or executable changed")
    receipt.update(input_sha256=request["input_sha256"], executable_sha256=request["executable_sha256"],
        output_sha256=sha256(output).hexdigest(), output_bytes=len(output), stderr_hex=stderr.hex(),
        stdin_mode=mode, executable_inspection=inspect_executable(image),
        native_execution="execve of kernel ELF; Python setup replaced, not a compiler/runtime dependency")
    return receipt, output


def qualify(directory, compiler, compiler_source, checks, reference, label):
    from tools.qualify_hia_selfhost import compile_stage, invoke, NO_SPACE
    directory = Path(directory)
    observations = []

    def observe(name, executable, data, status=0, expected=None, **options):
        receipt, output = execute(directory, label + "-" + name, executable, data, **options)
        checks[label + "-cli-" + name] = bool(receipt["status"] == ("OWNED_PROCESS_COMPLETED" if status == 0 else "QUALIFICATION_FAILED")
            and receipt["cleanup"]["complete"] and receipt["returncode"] == status
            and receipt["stderr_hex"] == "" and (expected is None or output == expected))
        observations.append({"case": name, "native": receipt})
        return output

    executable_source = compiler_source.replace(b"v8 selfhost\n", b"v8 selfhost_exec\n", 1)
    if executable_source == compiler_source:
        raise ValueError("compiler executable source header was not replaced")
    executable, receipt = compile_stage(directory, label + "-cli-E1-build", compiler,
        executable_source, output_extension=".elf")
    observations.append({**receipt, "inspection": inspect_executable(executable.read_bytes())})
    executable.chmod(0o700)
    previous = executable
    for generation in (2, 3):
        output = observe("E%d" % generation, previous, executable_source,
            expected=executable.read_bytes())
        following = directory / (label + "-cli-E%d.elf" % generation)
        following.write_bytes(output); following.chmod(0o700)
        previous = following
    if label == "original":
        from tools.qualify_hia_selfhost import mutate_compiler
        modified = mutate_compiler(compiler_source).replace(b"v8 selfhost\n", b"v8 selfhost_exec\n", 1)
        modified_images = []
        predecessor = executable
        for generation in (1, 2, 3):
            output = observe("upgrade-M%d" % generation, predecessor, modified,
                expected=modified_images[1] if generation == 3 else None)
            modified_images.append(output)
            predecessor = directory / (label + "-cli-upgrade-M%d.elf" % generation)
            predecessor.write_bytes(output); predecessor.chmod(0o700)
        checks[label + "-cli-modified-codegen-causality"] = bool(
            modified != executable_source and modified_images[0] != modified_images[1]
            and modified_images[1] == modified_images[2]
            and modified_images[2] != executable.read_bytes())
    # Both generations compile an unrelated byte program; no self-source dispatch.
    echo = reference["echo_source"].encode()
    echo_exec_source = echo.replace(b"v8 selfhost\n", b"v8 selfhost_exec\n", 1)
    echo_exec, build = compile_stage(directory, label + "-cli-echo-build", compiler,
        echo_exec_source, output_extension=".elf")
    observations.append(build); echo_exec.chmod(0o700)
    for generation, cli in ((1, executable), (3, previous)):
        observe("echo-compile-E%d" % generation, cli, echo_exec_source, expected=echo_exec.read_bytes())
    for row in reference["echo"]:
        observe("echo-" + row["input_hex"], echo_exec, bytes.fromhex(row["input_hex"]),
            expected=bytes.fromhex(row["output_hex"]))
    for name, data in (("empty", b""), ("bad-header", b"bad"), ("bad-utf8", b"\xff")):
        observe(name, executable, data, status=2, expected=b"")
    observe("argument", executable, b"", status=64, expected=b"", arguments=["unexpected"])
    observe("input-overflow", executable, b" " * (CAPACITY + 1), status=3, expected=b"")
    limit = reference["limit_source"].encode()
    flat, build = compile_stage(directory, label + "-cli-limit-flat-build", compiler, limit)
    observations.append(build)
    observe("input-exact-limit", executable, padded_source(limit),
        expected=flat.read_bytes())
    observe("closed-stdin", executable, echo, status=4, expected=b"", mode="closed-stdin")
    observe("full-stdout", executable, echo, status=4, expected=b"", mode="full-stdout")
    observe("mmap-failure", executable, echo, status=4, expected=b"", mode="mmap-failure")
    large = reference["output_capacity_source"].encode()
    returned, output = invoke(directory, label + "-cli-output-capacity-flat", compiler,
        large, capacity=CAPACITY)
    checks[label + "-cli-output-capacity-reference"] = bool(returned.get("status") == "returned"
        and returned.get("core_u32") == NO_SPACE and returned.get("source_unchanged")
        and returned.get("output_unchanged") and output == b"\xa5" * CAPACITY)
    observations.append({"case": "output-capacity-flat", "native": returned})
    observe("output-overflow", executable, large, status=3, expected=b"")
    return observations
