"""Complete top-level native build policy; authoring input only."""

def _implementation_hash():
    digest = sha256()
    root = Path(__file__).parent
    for name in (
        "hia_schema.py",
        "hia_program.py",
        "hia_capability_flow.py",
        "hia_opcodes.py",
        "hia_json_preflight.py",
        "hia_program_composite.py",
        "hia_program_native.py",
        "hia_machine_encoding_native.py",
        "hia_machine_state_native.py",
        "hia_machine_instructions_native.py",
        "hia_machine_plan_native.py",
        "hia_core_lowering_native.py",
        "hia_core_lowering_selection.py",
        "hia_core_emitter_native.py",
        "hia_core_emitter_selection.py",
        "hia_host_import.py",
        "hia_byte_wrapper_native.py",
        "hia_byte_wrapper_selection.py",
        "hia_machine_object_native.py",
        "hia_machine_object_selection.py",
        "hia_json_wire_native.py",
        "hia_instruction_policy_native.py",
        "hia_json_preflight_native.py",
        "hia_machine_elf.py",
        "hia_machine_plan.py",
        "hia_native_byte_abi.py",
        "hia_agent_exec.py",
        "hia_static_budget.py",
        "hia_heap_bound.py",
        "artifact_publication.py",
        "clang_capture.py",
        "elf_shared_abi.py",
        "object_symbols.py",
        "object_structure.py",
        "native_tool_identity.py",
        "hia_machine_transport.py",
        "hia_exception_delivery.py",
        "hia_machine_plan_control_native.py",
        "hia_machine_elf_native.py",
        "hia_native_build_native.py",
        "hia_native_build_selection.py",
        "hia_native_build_foreign.py",
        "hia_native_byte_abi_native.py",
        "hia_native_byte_abi_selection.py",
        "hia_backend_family_selection.py",
        "hia_core_lowering_control_native.py",
        "hia_core_lowering_control_selection.py",
        "hia_core_emitter_control_native.py",
        "hia_core_emitter_control_selection.py",
        "hia_machine_plan_control_selection.py",
        "hia_machine_elf_selection.py",
        "hia_byte_policy_selection.py",
    ):
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    from .hia_checker_identity import checker_digest
    digest.update(checker_digest().encode())
    from .hia_machine_x64 import native_implementation_identity as encoding_identity
    digest.update(b'native-machine-encoding\0' + encoding_identity() + b'\0')
    from .hia_machine_elf import native_implementation_identity as elf_identity
    selected_elf = elf_identity()
    if selected_elf:
        digest.update(b"machine-elf-native\0" + selected_elf + b"\0")
    from .hia_machine_plan import native_implementation_identity as plan_identity
    digest.update(b'native-machine-plan\0' + plan_identity() + b'\0')
    from .hia_json_preflight_native import _source_resource_path
    digest.update(b'core-lowering-abi\0' + _source_resource_path('docs/HIA_CORE_LOWERING_ABI.json').read_bytes() + b'\0')
    from .hia_core_lowering_selection import native_implementation_identity as lowering_identity
    digest.update(b'native-core-lowering\0' + lowering_identity(globals()) + b'\0')
    digest.update(b'core-emitter-abi\0' + _source_resource_path('docs/HIA_CORE_EMITTER_ABI.json').read_bytes() + b'\0')
    from .hia_core_emitter_selection import native_implementation_identity as emitter_identity
    digest.update(b'native-core-emitter\0' + emitter_identity(globals()) + b'\0')
    from . import hia_native_byte_abi as byte_abi
    from .hia_byte_policy_selection import native_byte_policy_scope
    with native_byte_policy_scope(vars(byte_abi)):
        from .hia_byte_wrapper_selection import native_implementation_identity as byte_identity
        digest.update(b'byte-wrapper-abi\0' + _source_resource_path('docs/HIA_BYTE_WRAPPER_ABI.json').read_bytes() + b'\0')
        digest.update(b'native-byte-wrapper\0' + byte_identity(vars(byte_abi)) + b'\0')
        from .hia_native_byte_abi_selection import native_implementation_identity as byte_abi_identity
        digest.update(b'native-byte-abi\0' + byte_abi_identity() + b'\0')
    from . import hia_machine_elf as elf
    from .hia_machine_object_selection import native_implementation_identity as object_identity
    digest.update(b'machine-object-abi\0' + _source_resource_path('docs/HIA_MACHINE_OBJECT_ABI.json').read_bytes() + b'\0')
    digest.update(b'native-machine-object\0' + object_identity(vars(elf)) + b'\0')
    from .hia_native_build_selection import native_implementation_identity as build_identity
    digest.update(b'native-build-coordinator\0' + build_identity(globals()) + b'\0')
    return digest.hexdigest()



def validate_block_layout_plan(program, machine_plan):
    """Compatibility entry for v1 layouts and explicit v2 machine choices.

    This checks a finite preservation contract relative to canonical lowering;
    it is not a universal Core-to-machine semantic proof.
    """
    from .hia_program import verify_program
    from .hia_machine_plan import MachinePlanRejected, validate_plan
    try:
        return validate_plan(verify_program(program), machine_plan)
    except MachinePlanRejected as exc:
        _reject(str(exc).split(": ", 1)[-1], "E_HIA_MACHINE_PLAN")

def emit_program_machine(program, *, target=TARGET, machine_plan=None, foreign_buffer_exports=()):
    """Recheck immutable Core and emit deterministic native object bytes."""
    from .hia_program import VerifiedProgram, verify_program
    if target != TARGET:
        _reject("direct machine backend supports only x86_64 Linux", "E_HIA_PROGRAM_TARGET")
    from .hia_machine_x64 import native_encoding_scope
    from .hia_machine_elf import native_elf_scope
    from .hia_core_lowering_selection import native_core_lowering_scope
    from .hia_machine_plan_native import native_machine_plan_scope
    from .hia_core_emitter_selection import native_core_emitter_scope
    from .hia_native_byte_abi_selection import native_byte_abi_scope
    with (native_encoding_scope(), native_elf_scope(), native_core_lowering_scope(globals()),
          native_machine_plan_scope(), native_core_emitter_scope(globals()), native_byte_abi_scope()):
        before = _implementation_hash()
        if not isinstance(program, VerifiedProgram):
            _reject("an immutable VerifiedProgram from verify_program is required")
        checked = verify_program(program)
        if (checked.canonical_bytes != program.canonical_bytes
                or checked.input_sha256 != program.input_sha256):
            _reject("verified program identity changed", "E_HIA_PROGRAM_ORIGIN")
        from .hia_native_byte_abi import normalize_exports, PROFILE as BYTE_PROFILE
        byte_exports = normalize_exports(foreign_buffer_exports, checked)
        plan = None if machine_plan is None else validate_block_layout_plan(checked, machine_plan)
        plan_hash = None if plan is None else sha256(json.dumps(
            plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        emitter = _Emitter(checked.as_dict(), checked.scalar_entrypoints,
                           None if plan is None else plan["block_order"], byte_exports, plan)
        text, obj = emitter.render()
        if len(obj) > MAX_ARTIFACT_BYTES:
            _reject("object exceeds artifact byte budget", "E_HIA_PROGRAM_LIMIT")
        exports = tuple(sorted(emitter.exports))
        _inspect_object(obj, exports)
        if _implementation_hash() != before:
            _reject("verifier/emitter changed during generation", "E_HIA_PROGRAM_STALE")
        return HIAProgramMachine(obj, text, sha256(obj).hexdigest(), checked.sha256,
                                 before, exports, BYTE_PROFILE if byte_exports else PROFILE, target, checked.input_sha256,
                                 tuple(emitter.frames), plan_hash, byte_exports)


def _inspect_object(data, exports):
    inventory = inspect_object_symbols(data, "ELF64", 62)
    if (inventory.get("defined") != frozenset(exports)
            or inventory.get("undefined") is None
            or not inventory["undefined"] <= IMPORTS):
        _reject("object import/export inventory differs from the closed ABI")
    return {name: sorted(values) for name, values in inventory.items()}

def _read_artifact(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARTIFACT_BYTES:
        _reject("artifact must be a bounded ordinary nonempty file")
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW), "rb") as stream:
        if key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed before reading")
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed during reading")
    if key(path.lstat()) != key(before):
        _reject("artifact pathname changed during reading")
    return data

def _run_logged(argv, *, command_log=None, parent_death_guard=False, **kwargs):
    if command_log is not None and type(command_log) is not list:
        _reject("command log must be a plain list", "E_HIA_COMMAND_LOG")
    row = {"argv": list(argv), "status": "attempted", "returncode": None}
    if command_log is not None:
        command_log.append(row)
    try:
        captured_argv = argv
        if parent_death_guard:
            if sys.platform != "linux":
                _reject("parent-death guarded linkage requires Linux", "E_HIA_PROGRAM_TARGET")
            captured_argv = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_exec",
                             str(os.getpid()), *argv]
            kwargs["cwd"] = Path(__file__).resolve().parent.parent
            row["process_guard"] = {"profile": "linux-pdeathsig-sigkill-exec-v1",
                "module": "hepta.hia_agent_exec", "sha256": sha256(
                    Path(__file__).with_name("hia_agent_exec.py").read_bytes()).hexdigest(),
                "capture_argv": captured_argv,
                "role": "set parent-death SIGKILL then exec the recorded tool argv in the same PID"}
        result = run_bounded(captured_argv, **kwargs)
    except BaseException as error:
        row.update(status="capture_failed", error={"type": type(error).__name__, "message": str(error)})
        capture = getattr(error, "capture", None)
        if capture is not None:
            row["returncode"] = capture.returncode
            for name in ("stdout", "stderr"):
                raw = getattr(capture, name)
                row[name + "_hex"] = raw.hex()
                row[name + "_total_bytes"] = getattr(capture, name + "_total_bytes")
                row[name + "_complete"] = len(raw) == row[name + "_total_bytes"]
        raise
    row.update(status="completed", returncode=result.returncode)
    for name in ("stdout", "stderr"):
        raw = getattr(result, "raw_" + name)
        if raw is not None:
            row[name + "_hex"] = raw.hex()
            row[name + "_total_bytes"] = len(raw)
            row[name + "_complete"] = True
        else:
            row[name + "_text_fallback"] = getattr(result, name)
    return result

def _host():
    widths = {"pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
              "long_bits": ctypes.sizeof(ctypes.c_long) * 8,
              "size_t_bits": ctypes.sizeof(ctypes.c_size_t) * 8}
    return {"system": platform.system(), "machine": platform.machine(), "byteorder": sys.byteorder, **widths}

def compile_program_machine(image, *, program, output, kind="shared", linker="cc", command_log=None,
                            machine_plan=None, parent_death_guard=False, timeout_seconds=None):
    """Publish a rederived object, or link and inspect a native shared library."""
    if command_log is not None and type(command_log) is not list:
        _reject("command log must be a plain list", "E_HIA_COMMAND_LOG")
    if (timeout_seconds is not None and (type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= 3600)):
        _reject("linkage deadline must be in (0,3600] seconds", "E_HIA_PROGRAM_LIMIT")
    deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds

    def remaining(maximum):
        budget = maximum if deadline is None else min(maximum, deadline - time.monotonic())
        if budget <= 0:
            _reject("native build deadline is exhausted", "E_HIA_PROGRAM_LIMIT")
        return budget
    if not isinstance(image, HIAProgramMachine) or image != emit_program_machine(
            program, target=image.target, machine_plan=machine_plan,
            foreign_buffer_exports=image.foreign_buffer_exports):
        _reject("machine image differs from independently reverified Core", "E_HIA_PROGRAM_ORIGIN")
    if kind not in {"object", "shared"}:
        _reject("only relocatable objects and shared libraries are supported")
    host = _host()
    if kind == "shared" and (host["system"] != "Linux" or host["machine"].lower() not in {"x86_64", "amd64"}
                             or host["byteorder"] != "little" or any(host[k] != 64 for k in ("pointer_bits", "long_bits", "size_t_bits"))):
        _reject("shared linkage requires a Linux x86-64 LP64 host", "E_HIA_PROGRAM_TARGET")
    destination = Path(os.path.abspath(output))
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        _reject("a new output path in an existing directory is required")
    tool = None
    tool_digest = None
    toolchain = None
    linker_mode = None
    flags = []
    if kind == "shared":
        found = shutil.which(linker)
        if found is None:
            _reject("GNU ld or a native C linker driver is required for shared linkage")
        tool = Path(found).resolve(); tool_digest = digest_executable(tool)
        version = _run_logged([str(tool), "--version"], command_log=command_log,
                             parent_death_guard=parent_death_guard, timeout=remaining(10), stdout_limit=65536, stderr_limit=65536)
        if version.returncode:
            _reject("cannot identify the native linker")
        if version.stdout.startswith("GNU ld "):
            linker_mode, default_target = "gnu-ld", "elf_x86_64 (explicit emulation)"
        else:
            linker_mode = "c-driver"
            triple = _run_logged([str(tool), "-dumpmachine"], command_log=command_log,
                                parent_death_guard=parent_death_guard, timeout=remaining(10), stdout_limit=65536, stderr_limit=65536)
            if (triple.returncode or triple.stdout.strip() not in
                    {"x86_64-linux-gnu", "x86_64-pc-linux-gnu", "x86_64-unknown-linux-gnu"}):
                _reject("linker driver must target x86_64 GNU/Linux")
            default_target = triple.stdout.strip()
        toolchain = {"path": str(tool), "sha256": tool_digest,
                     "version": version.stdout.splitlines()[0] if version.stdout else "",
                     "default_target": default_target, "mode": linker_mode,
                     "role": "link_generated_object_only"}
    with tempfile.TemporaryDirectory(prefix=".hia-direct-", dir=destination.parent) as directory:
        obj = Path(directory) / "program.o"
        obj.write_bytes(image.object_bytes)
        artifact = obj
        if kind == "shared":
            artifact = Path(directory) / "program.so"
            # The reviewed Safe Core consumer checks both loader lookup tables.
            # GNU ld's default hash style varies across distributions; freeze
            # this part of the produced ELF contract and retain it in receipts.
            flags = (["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both"]
                     if linker_mode == "gnu-ld" else
                     ["-shared", "-Wl,-z,defs", "-Wl,-z,noexecstack", "-Wl,-z,relro", "-Wl,-z,now", "-Wl,--build-id=none", "-Wl,--hash-style=both"])
            libraries = ["-lc"] if linker_mode == "gnu-ld" else []
            result = _run_logged([str(tool), *flags, str(obj), *libraries, "-o", str(artifact)],
                                 command_log=command_log, parent_death_guard=parent_death_guard,
                                 timeout=remaining(60), stdout_limit=65536, stderr_limit=1048576)
            if result.returncode:
                _reject("linker rejected generated machine object: " + result.stderr[:3000])
        data = _read_artifact(artifact)
        inventory = inspect_owned_shared_elf(data, image.exports) if kind == "shared" else _inspect_object(data, image.exports)
        def recheck():
            if _implementation_hash() != image.implementation_sha256 or (tool is not None and digest_executable(tool) != tool_digest):
                _reject("implementation or linker driver changed during build", "E_HIA_PROGRAM_STALE")
        recheck()
        published = publish_verified(artifact, destination, data)
        try:
            recheck(); verify_published(artifact, destination, data)
        except BaseException:
            withdraw_own_link(artifact, destination)
            raise
    return {"schema": "hepta.hia.program.direct-native.v1", "ok": True,
            "status": "native_emitted_not_executed", "profile": image.profile,
            "target": image.target, "kind": kind, "output": str(destination),
            "supported_core_schemas": sorted(CORE_SCHEMAS), "supported_opcodes": sorted(SUPPORTED_OPCODES),
            "input_sha256": image.input_sha256, "core_sha256": image.core_sha256,
            "implementation_sha256": image.implementation_sha256,
            "machine_text_sha256": sha256(image.text_bytes).hexdigest(), "object_sha256": image.sha256,
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "machine_text_bytes": len(image.text_bytes), "exports": list(image.exports),
            "binary_inventory": inventory, "build_host": host, "toolchain": toolchain, "flags": flags,
            "function_frames": dict(image.function_frames),
            "machine_plan_sha256": image.machine_plan_sha256,
            "foreign_buffer_exports": [list(pair) for pair in image.foreign_buffer_exports],
            "implicit_profitability_optimizer_used": False,
            "parent_death_guarded_linker": bool(parent_death_guard) if kind == "shared" else False,
            "external_abi": ("SysV AMD64 scalar C functions plus explicit synchronous borrowed-byte pointer/length entrypoints"
                             if image.foreign_buffer_exports else
                             "SysV AMD64 scalar C functions; resources and multiple results are internal"),
            "runtime_assumptions": ["Linux x86-64 LP64 runtime and ordinary C scalar ABI",
                "calloc/malloc return null or fresh nonaliasing allocations; calloc initializes every byte",
                "free releases a live allocation; libc memory functions implement their standard byte semantics",
                "abort terminates execution; traps do not promise cleanup",
                "linker, loader, libc and host hardware are trusted; native execution has no VM step/heap/call quotas"] +
                (["foreign caller supplies live, correctly sized allocations for the synchronous call",
                  "mutable foreign ranges are exclusive and read-only ranges are not concurrently mutated",
                  "numeric guards do not prove allocation provenance or pointer liveness"] if image.foreign_buffer_exports else []),
            "claims": {"standalone_core_reverified": True, "direct_machine_code": True,
                "llvm_ir_used": False, "llvm_codegen_used": False, "assembler_used": False,
                "source_ast_required": False, "rust_reference_required": False,
                "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
                "external_linker_used": kind == "shared", "native_execution_qualified": False,
                "backend_refinement_proved": False, "whole_language_soundness_proved": False,
                "self_hosted": False, "foreign_buffer_entrypoints_exposed": bool(image.foreign_buffer_exports)}}

def build_program_machine(document, output, *, kind="shared", linker="cc", target=TARGET,
                          command_log=None, bounded_resource_limits=None, foreign_buffer_exports=()):
    from .hia_program import verify_program
    program = verify_program(document)
    budget = None
    if bounded_resource_limits is not None:
        from .hia_static_budget import qualify_bounded_resources
        budget = qualify_bounded_resources(program, limits=bounded_resource_limits)
    image = emit_program_machine(program, target=target, foreign_buffer_exports=foreign_buffer_exports)
    result = compile_program_machine(image, program=program, output=output, kind=kind,
                                     linker=linker, command_log=command_log)
    if budget is not None:
        result["bounded_resources"] = budget
    return result

def _reject(message, code="E_HIA_PROGRAM_NATIVE"):
    raise HIAProgramNativeRejected(code + ": " + message)
