"""Explicit Linux-file capability profile; no implicit OS provider.

This is a new HIA process policy, not complete CPython read_bounded equivalence.
PathLike callbacks, Python stream allocation/buffering/signal handlers and the
old fdopen directory leak are outside its claimed physical reference domain.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType

from .hia_opcodes import EFFECTS, OpcodeSpec
from .hia_program import (
    HIAProgramRejected, _decode, _reference_primitive_structure,
    _function_interfaces, _verify_function,
)
from .hia_schema import SCHEMA_V8

PROFILE = "hepta.hia.linux-file.v1"
MODULE = "selfhost_linux_file"
PROFILE_SOURCE_FILES = (
    "examples/hia_bootstrap/selfhost_linux_file.hepta",
    "examples/hia_bootstrap/linux_file_entry_packer.hepta",
    "examples/hia_bootstrap/native_file_read.hepta",
)
SOURCE_LIMIT = WORKSPACE_LIMIT = 1048576
OUTPUT_LIMIT = 8388609
FUNCTION_LIMIT = 128
BLOCK_LIMIT = 1536
INSTRUCTION_LIMIT = 8192
READ = "linux.stdin.read"
WRITE = "linux.stdout.write"
STDERR = "linux.stderr.write"
STARTUP_EFFECT = "linux_startup"
PROFILE_EFFECTS = EFFECTS | {"linux_io", STARTUP_EFFECT, "linux_file"}
IO_OPCODES = MappingProxyType({
    READ: OpcodeSpec(READ, ("mutbuf", "usize", "usize"), ("i64",),
                     effects=("linux_io", "write", "trap"), traps=("bounds",),
                     since=8, guards=("write:0",),
                     semantic_rule="single_linux_read_fd0_raw_signed_result"),
    WRITE: OpcodeSpec(WRITE, ("view", "usize", "usize"), ("i64",),
                      effects=("linux_io", "read", "trap"), traps=("bounds",),
                      since=8, guards=("read:0",),
                      semantic_rule="single_linux_write_fd1_raw_signed_result"),
    STDERR: OpcodeSpec(STDERR, ("view", "usize", "usize"), ("i64",),
                       effects=("linux_io", "read", "trap"), traps=("bounds",),
                       since=8, guards=("read:0",),
                       semantic_rule="single_linux_write_fd2_raw_signed_result"),
})
STARTUP_OPCODES = MappingProxyType({
    **{name: OpcodeSpec(name, (), ("usize",),
        effects=(STARTUP_EFFECT, "read", "trap"), traps=("bounds",), since=8,
        semantic_rule="immutable_kernel_startup_ordered_count")
       for name in ("linux.argv.count", "linux.env.count")},
    **{name: OpcodeSpec(name, ("usize",), ("usize",),
        effects=(STARTUP_EFFECT, "read", "trap"), traps=("bounds",), since=8,
        semantic_rule="immutable_kernel_startup_raw_string_length")
       for name in ("linux.argv.length", "linux.env.length")},
    **{name: OpcodeSpec(name, ("mutbuf", "usize", "usize", "usize", "usize"), ("usize",),
        effects=(STARTUP_EFFECT, "read", "write", "trap"), traps=("bounds",),
        since=8, guards=("write:0",),
        semantic_rule="immutable_kernel_startup_bounded_raw_string_copy")
       for name in ("linux.argv.copy", "linux.env.copy")},
})
FILE_OPCODES = MappingProxyType({
    "linux.file.open": OpcodeSpec("linux.file.open", ("view", "usize", "usize"), ("i64",),
        effects=("linux_file", "read", "trap"), traps=("bounds",), since=8,
        guards=("read:0",), semantic_rule="fixed_readonly_openat_one_private_descriptor"),
    **{name: OpcodeSpec(name, ("mutbuf", "usize", "usize"), ("i64",),
        effects=("linux_file", "write", "trap"), traps=("bounds",), since=8,
        guards=("write:0",), semantic_rule="fixed_active_descriptor_stat_or_read")
       for name in ("linux.file.stat", "linux.file.read")},
    **{name: OpcodeSpec(name, (), ("i64",), effects=("linux_file", "trap"),
        traps=("bounds",), since=8, semantic_rule="fixed_active_descriptor_close_or_flags")
       for name in ("linux.file.close", "linux.file.fdflags", "linux.file.statusflags")},
})
PROFILE_OPCODES = MappingProxyType({**IO_OPCODES, **STARTUP_OPCODES, **FILE_OPCODES})
FILE_FLAGS = 0x20000 | 0x800 | 0x80000

@dataclass(frozen=True, slots=True)
class LinuxFileRequest:
    operation: str
    fd: int | None
    path: bytes
    offset: int
    count: int
    extent: int
    flags: int



@dataclass(frozen=True, slots=True)
class LinuxStartupSnapshot:
    """Explicit immutable VM reference data; never a native kernel capability."""

    argv: tuple[bytes, ...]
    environment: tuple[bytes, ...]


def _checked_startup(snapshot):
    if type(snapshot) is not LinuxStartupSnapshot:
        raise HIAProgramRejected("an explicit reference startup snapshot is required",
                                 "E_HIA_LINUX_FILE_STARTUP")
    for values in (snapshot.argv, snapshot.environment):
        if (type(values) is not tuple or any(type(value) is not bytes or b"\x00" in value
                                             for value in values)):
            raise HIAProgramRejected("ordered immutable NUL-free startup byte strings required",
                                     "E_HIA_LINUX_FILE_STARTUP")
    # Do not collapse duplicates, decode bytes, select environment names or add
    # the existing 1MiB per-buffer ceiling to the total kernel-startup domain.
    return LinuxStartupSnapshot(snapshot.argv, snapshot.environment)



def profile_resource_path(name):
    """Resolve one declared build asset in this checkout or installed package.

    Missing installed assets never fall back to another checkout, cwd or HOME.
    Resolving a path grants no compiler, cold, execution or default authority.
    """
    if type(name) is not str or name not in PROFILE_SOURCE_FILES:
        raise ValueError("an exact declared Linux stdio build resource is required")
    from .hia_json_preflight_native import _source_resource_path
    return _source_resource_path(name)


def require_profile(profile):
    if type(profile) is not str or profile != PROFILE:
        raise HIAProgramRejected("an exact explicit Linux stdio profile is required",
                                 "E_HIA_LINUX_FILE_PROFILE")


def profile_effects(profile):
    require_profile(profile)
    return PROFILE_EFFECTS


def profile_opcode(profile, opcode, schema):
    require_profile(profile)
    if schema != SCHEMA_V8:
        raise HIAProgramRejected("Linux stdio requires explicit primitive v8",
                                 "E_HIA_LINUX_FILE_PROFILE")
    return PROFILE_OPCODES.get(opcode)


@dataclass(frozen=True, slots=True)
class VerifiedLinuxFileProgram:
    """Detached bytes only. All consumers recheck; this is not VerifiedProgram."""

    canonical_bytes: bytes

    def as_dict(self):
        if type(self.canonical_bytes) is not bytes:
            raise HIAProgramRejected("profile bytes must be immutable", "E_HIA_FORMAT")
        return _decode(self.canonical_bytes)[0]

    @property
    def sha256(self):
        return sha256(self.canonical_bytes).hexdigest()

    @property
    def input_sha256(self):
        return self.sha256

    def report(self):
        checked = verify_linux_file_program(self)
        doc = checked.as_dict()
        return {"schema": "hepta.hia.linux-file-verification.v1", "profile": PROFILE,
                "program_sha256": checked.sha256,
                "functions_checked": len(doc["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in doc["functions"]),
                "operations_checked": sum(len(b["ops"]) for f in doc["functions"]
                                           for b in f["blocks"]),
                "typed_closed_ssa_checked": True,
                "linear_resources_and_loan_provenance_checked": True,
                "fixed_descriptors": {READ: 0, WRITE: 1, STDERR: 2},
                "private_file_capability": "only actual open result; readonly; single active",
                "file_result_extent": OUTPUT_LIMIT,
                "startup_reference_is_native_authority": False,
                "default_core_authority": False, "kernel_authority": False,
                "native_artifact_created": False, "matching_cold": False,
                "whole": False}


def verify_linux_file_program(program):
    if type(program) is VerifiedLinuxFileProgram:
        if type(program.canonical_bytes) is not bytes:
            raise HIAProgramRejected("profile bytes must be immutable", "E_HIA_FORMAT")
        program = program.canonical_bytes
    data, raw = _decode(program)
    if (type(data) is not dict or data.get("schema") != SCHEMA_V8
            or data.get("module") != MODULE):
        raise HIAProgramRejected("explicit primitive v8 Linux stdio module required",
                                 "E_HIA_LINUX_FILE_PROFILE")
    functions, blocks = _reference_primitive_structure(data, profile=PROFILE)
    if (len(functions) > FUNCTION_LIMIT
            or sum(len(v) for v in blocks.values()) > BLOCK_LIMIT
            or sum(len(b["ops"]) for f in functions.values()
                   for b in f["blocks"]) > INSTRUCTION_LIMIT):
        raise HIAProgramRejected("original selfhost structural limits exceeded", "E_HIA_LIMIT")
    entry = data["functions"][0]
    if (entry["name"] != "f0"
            or [p["type"] for p in entry["params"]] != ["readbuf", "mutbuf", "mutbuf"]
            or entry["returns"] != ["u32"]):
        raise HIAProgramRejected("Linux stdio uses the original f0 three-buffer ABI",
                                 "E_HIA_LINUX_FILE_ABI")
    interfaces = _function_interfaces(functions)
    for fn in functions.values():
        _verify_function(data["schema"], fn, blocks[fn["name"]], interfaces, profile=PROFILE)
    return VerifiedLinuxFileProgram(raw)


def assemble_linux_file(source):
    from .hia_agent_assembly import _source, _parse_assembly_document
    raw, _ = _source(source)
    if len(raw) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    return verify_linux_file_program(_parse_assembly_document(raw))


def render_linux_file(program):
    from .hia_agent_assembly import _render_assembly_document
    checked = verify_linux_file_program(program)
    rendered = _render_assembly_document(checked.as_dict())
    if len(rendered.encode("utf-8")) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    if assemble_linux_file(rendered).canonical_bytes != checked.canonical_bytes:
        raise HIAProgramRejected("profile rendering changed verified bytes",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP")
    return rendered


@dataclass(frozen=True, slots=True)
class LinuxFileIORequest:
    operation: str
    fd: int
    offset: int
    count: int
    extent: int
    write_bytes: bytes


class LinuxFileProviderRejected(ValueError):
    """The supplied observation is outside one fixed Linux I/O result."""


class LinuxFileSignal(Exception):
    """An explicit reference-provider signal, never an implicit OS action."""

    def __init__(self, number):
        if type(number) is not int or not 1 <= number <= 64:
            raise ValueError("exact Linux signal number required")
        self.number = number
        super().__init__(number)


def _execute(checked, function, buffers, provider, startup, *, max_steps, max_heap_bytes,
             allocation_fail_at, max_call_depth):
    from .hia_program_runtime import (
        _Machine, _Owner, _View, _underlying, HIAProgramTrap, HIAProgramBudgetExceeded,
    )

    class LinuxFileMachine(_Machine):
        def __init__(self):
            super().__init__(checked, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
            self.effects = []
            self.file_fd = None

        def operation(self, ins, env, depth):
            operation = ins["op"]
            if operation in FILE_OPCODES:
                args = [env[name] for name in ins["args"]]
                view = None
                owner = None
                offset = count = extent = 0
                path = b""
                if operation in ("linux.file.open", "linux.file.stat", "linux.file.read"):
                    view, offset, count = args
                    if (type(view) is not _View
                            or operation != "linux.file.open" and not view.mutable
                            or type(offset) is not int or type(count) is not int
                            or offset < 0 or count < 0):
                        raise HIAProgramRejected("invalid file borrow", "E_HIA_RUNTIME_INVARIANT")
                    owner = _underlying(view)
                    extent = len(owner.data)
                    if offset > extent or count > extent - offset:
                        raise HIAProgramTrap("bounds", "file operation exceeds borrowed extent")
                    if operation == "linux.file.stat" and count != 144:
                        raise HIAProgramTrap("bounds", "exact x86-64 stat extent required")
                if operation == "linux.file.open":
                    if self.file_fd is not None:
                        raise HIAProgramTrap("bounds", "cannot replace an active file capability")
                    if count == 0 or owner.data[offset + count - 1] != 0:
                        raise HIAProgramTrap("bounds", "borrowed pathname lacks terminal NUL")
                    path = bytes(owner.data[offset:offset + count])
                elif self.file_fd is None:
                    raise HIAProgramTrap("bounds", "file capability is closed or absent")
                request = LinuxFileRequest(operation, self.file_fd, path, offset, count,
                                           extent, FILE_FLAGS if path else 0)
                row = {"operation": operation, "fd": self.file_fd, "path_hex": path.hex(),
                       "offset": offset, "count": count, "extent": extent,
                       "flags": request.flags, "status": "issued"}
                self.effects.append(row)
                if operation == "linux.file.close":
                    # Revoke before invoking the finite physical provider. A
                    # failing/unknown close never grants the old fd again.
                    self.file_fd = None
                try:
                    response = provider(request)
                except BaseException:
                    row["status"] = "provider_raised"
                    raise
                if (type(response) is not tuple or len(response) != 2
                        or type(response[0]) is not int or type(response[1]) is not bytes):
                    raise LinuxFileProviderRejected("exact signed result/bytes required")
                result, payload = response
                if not -4095 <= result <= 2147483647:
                    raise LinuxFileProviderRejected("result outside fixed Linux file domain")
                if operation == "linux.file.read":
                    valid = result <= count and len(payload) == max(0, result)
                elif operation == "linux.file.stat":
                    valid = (result == 0 and len(payload) == 144) or (result < 0 and not payload)
                elif operation == "linux.file.close":
                    valid = result <= 0 and not payload
                else:
                    valid = not payload
                if not valid:
                    raise LinuxFileProviderRejected("payload/result disagree with file operation")
                if operation == "linux.file.open" and result >= 0:
                    self.file_fd = result
                if payload:
                    owner.data[offset:offset + len(payload)] = payload
                row.update(status="returned", result=result, read_hex=payload.hex(),
                           active_fd_after=self.file_fd)
                env[ins["out"][0]["name"]] = result
                return
            if operation in STARTUP_OPCODES:
                values = startup.argv if operation.startswith("linux.argv.") else startup.environment
                kind = operation.rsplit(".", 1)[1]
                args = [env[name] for name in ins["args"]]
                if kind == "count":
                    result = len(values)
                    event = {"operation": operation, "result": result}
                else:
                    index = args[0] if kind == "length" else args[2]
                    if type(index) is not int or index < 0 or index >= len(values):
                        raise HIAProgramTrap("bounds", "startup string index is outside the selected vector")
                    raw = values[index]
                    if kind == "length":
                        result = len(raw)
                        event = {"operation": operation, "index": index, "result": result}
                    else:
                        view, destination, _, offset, count = args
                        if (type(view) is not _View or not view.mutable
                                or any(type(v) is not int or v < 0 for v in (destination, offset, count))):
                            raise HIAProgramRejected("invalid startup copy capability",
                                                     "E_HIA_RUNTIME_INVARIANT")
                        owner = _underlying(view)
                        # Same order as the native primitive: selected string,
                        # source offset/count, then destination offset/count.
                        if offset > len(raw) or count > len(raw) - offset:
                            raise HIAProgramTrap("bounds", "startup copy exceeds its source string")
                        if destination > len(owner.data) or count > len(owner.data) - destination:
                            raise HIAProgramTrap("bounds", "startup copy exceeds its destination borrow")
                        payload = raw[offset:offset + count]
                        owner.data[destination:destination + count] = payload
                        result = count
                        event = {"operation": operation, "index": index, "offset": offset,
                                 "destination": destination, "count": count, "result": result,
                                 "copied_hex": payload.hex()}
                self.effects.append({**event, "status": "returned", "reference_snapshot": True})
                env[ins["out"][0]["name"]] = result
                return
            if operation not in IO_OPCODES:
                return super().operation(ins, env, depth)
            view, offset, count = (env[name] for name in ins["args"])
            owner = _underlying(view)
            if (type(view) is not _View or operation == READ and not view.mutable
                    or type(offset) is not int or type(count) is not int
                    or offset < 0 or count < 0):
                raise HIAProgramRejected("invalid typed physical effect borrow",
                                         "E_HIA_RUNTIME_INVARIANT")
            extent = len(owner.data)
            # Match generated native code: prove offset first, then subtract.
            if offset > extent or count > extent - offset:
                raise HIAProgramTrap("bounds", "physical I/O exceeds the borrowed extent")
            request = LinuxFileIORequest(operation, {READ: 0, WRITE: 1, STDERR: 2}[operation],
                offset, count, extent,
                bytes(owner.data[offset:offset + count]) if operation != READ else b"")
            row = {"operation": operation, "fd": request.fd, "offset": offset,
                   "count": count, "extent": extent, "write_hex": request.write_bytes.hex(),
                   "status": "issued"}
            self.effects.append(row)
            try:
                response = provider(request)
            except BaseException:
                row["status"] = "provider_raised"
                raise
            if (type(response) is not tuple or len(response) != 2
                    or type(response[0]) is not int or type(response[1]) is not bytes):
                raise LinuxFileProviderRejected("exact integer/bytes response required")
            result, payload = response
            if (not -4095 <= result <= count or result < 0 and payload
                    or operation != READ and payload
                    or operation == READ and len(payload) != max(0, result)):
                raise LinuxFileProviderRejected("response outside one Linux I/O observation")
            # No mutation happens before the complete provider result is admitted.
            row.update(status="returned", result=result, read_hex=payload.hex())
            if operation == READ and result > 0:
                owner.data[offset:offset + result] = payload
            env[ins["out"][0]["name"]] = result

    roots = tuple(_Owner(-(i + 1), bytearray(raw)) for i, raw in enumerate(buffers))
    arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
    machine = LinuxFileMachine()

    def observation(status, values=None, error=None):
        result = machine.report(function, status, values, error, external_roots=roots)
        result.update(schema="hepta.hia.linux-file-execution.v1", profile=PROFILE,
            source_hex=roots[0].data.hex(), output_hex=roots[1].data.hex(),
            workspace_hex=roots[2].data.hex(), effects=machine.effects,
            explicit_effect_provider=True, actual_kernel_execution=False,
            default_core_authority=False, matching_cold=False, whole=False)
        return result

    try:
        values = machine.invoke(machine.functions[function], arguments)
    except HIAProgramTrap as exc:
        exc.report = observation("trapped", error=exc)
        raise
    except HIAProgramBudgetExceeded as exc:
        exc.report = observation("budget_exceeded", error=exc)
        raise
    except (LinuxFileSignal, LinuxFileProviderRejected) as exc:
        # These are profile-owned reference outcomes, not ordinary Core traps
        # or a claim that a real kernel signal/provider was observed.
        exc.report = {"schema": "hepta.hia.linux-file-external-outcome.v1",
            "profile": PROFILE, "program_sha256": checked.sha256,
            "status": "external_signal" if type(exc) is LinuxFileSignal else "provider_refused",
            "signal": exc.number if type(exc) is LinuxFileSignal else None,
            "steps": machine.steps, "resources": machine.resources(),
            "source_hex": roots[0].data.hex(), "output_hex": roots[1].data.hex(),
            "workspace_hex": roots[2].data.hex(), "effects": machine.effects,
            "actual_kernel_execution": False, "matching_cold": False, "whole": False}
        raise
    except RecursionError as exc:
        limit = HIAProgramBudgetExceeded("calls", "host recursion limit reached")
        limit.report = observation("budget_exceeded", error=limit)
        raise limit from exc
    if machine.file_fd is not None or machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
        raise HIAProgramRejected("profile return retains local resources", "E_HIA_RUNTIME_INVARIANT")
    return observation("returned", values)


def execute_linux_file(program, function, arguments, *, provider, startup,
                        max_steps=1000000, max_heap_bytes=16 * 1024 * 1024,
                        allocation_fail_at=None, max_call_depth=256):
    checked = verify_linux_file_program(program)
    startup = _checked_startup(startup)
    if (type(function) is not str or function != "f0"
            or type(arguments) not in (list, tuple) or not callable(provider)
            or type(max_steps) is not int or not 1 <= max_steps <= 10000000
            or type(max_heap_bytes) is not int or not 0 <= max_heap_bytes <= 1024 * 1024 * 1024
            or type(max_call_depth) is not int or not 1 <= max_call_depth <= 256
            or allocation_fail_at is not None
               and (type(allocation_fail_at) is not int or allocation_fail_at < 1)):
        raise HIAProgramRejected("invalid profile boundary/provider/limits", "E_HIA_INPUT")
    buffers = tuple(arguments)
    if len(buffers) != 3 or any(type(raw) is not bytes or len(raw) > limit
            for raw, limit in zip(buffers, (SOURCE_LIMIT, OUTPUT_LIMIT, WORKSPACE_LIMIT))):
        raise HIAProgramRejected("exact source/workspace <=1 MiB and file-result borrow <=8 MiB+1 required",
                                 "E_HIA_LINUX_FILE_ABI")
    return _execute(checked, function, buffers, provider, startup, max_steps=max_steps,
        max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
        max_call_depth=max_call_depth)
