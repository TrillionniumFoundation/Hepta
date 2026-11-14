"""Explicit independent file-to-assembly canonical roundtrip profile.

The fixed controller calls a separately bound three-request representation
resident and one frozen semantic resident. Every call preserves the original
distinct-owner/loan/bounds protocol. No bytes, digest, dictionary or filename
supplied by the caller may select executable code. The original v3 profile,
complete public R7 canonical image and ordinary B3 remain separate.
Matching cold, portability and whole old CLI authority are not claimed.
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

PROFILE = "hepta.hia.linux-file-roundtrip.v2"
MODULE = "selfhost_linux_file_roundtrip"
PROFILE_SOURCE_FILES = ('examples/hia_bootstrap/selfhost_linux_file_roundtrip.hepta', 'examples/hia_bootstrap/linux_file_roundtrip_entry_packer.hepta', 'examples/hia_bootstrap/native_file_roundtrip.hepta', 'examples/hia_bootstrap/core_representation_private.hepta', 'examples/hia_bootstrap/file_render_checker_v4.hepta')
SOURCE_LIMIT = WORKSPACE_LIMIT = 1048576
OUTPUT_LIMIT = 1048576
FILE_BUFFER_LIMIT = 8388609
FUNCTION_LIMIT = 128
SEMANTIC_INPUT_FUNCTION_LIMIT = 256
BLOCK_LIMIT = 1536
INSTRUCTION_LIMIT = 8192
READ = "linux.stdin.read"
WRITE = "linux.stdout.write"
STDERR = "linux.stderr.write"
STARTUP_EFFECT = "linux_startup"
PROFILE_EFFECTS = EFFECTS | {"linux_io", STARTUP_EFFECT, "linux_file", "linux_roundtrip"}
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
RESIDENT_OPCODES = MappingProxyType({
    name: OpcodeSpec(name, ("view", "usize", "usize", "mutbuf", "usize", "usize", "mutbuf", "usize", "usize"),
        ("u32",), effects=("linux_roundtrip", "read", "write", "trap"), traps=("bounds",), since=8,
        guards=("read:0", "write:3", "write:6", "distinct:0:3", "distinct:0:6", "distinct:3:6"),
        semantic_rule="fixed_captured_file_render_resident_three_buffer_call")
    for name in ("linux.roundtrip.representation", "linux.roundtrip.semantic")
})
PROFILE_OPCODES = MappingProxyType({**IO_OPCODES, **STARTUP_OPCODES, **FILE_OPCODES, **RESIDENT_OPCODES})
# The physical second-resident opcode retains its historical name. In this
# independent v3 profile its exact source authority is semantic validation;
# it neither accepts an arbitrary compiler nor produces a runnable user image.
COMPONENT_PINS = {'linux.roundtrip.representation': 'cca0b52ca56a84782fd4ac41f5fbed56c64ebaf8c29ce60885d23b11920cb886', 'linux.roundtrip.semantic': '2fbedf12008851e7f428fbc60fed144c0d0ebd99d7cc93e004058a8d5e375aa9'}


def _checked_components(values):
    from .hia_agent_assembly import assemble_program
    if type(values) is not tuple or len(values) != 2:
        raise HIAProgramRejected("exact two frozen HIA component sources required", "E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT")
    result = {}
    for (name, expected), raw in zip(COMPONENT_PINS.items(), values):
        if type(raw) is not bytes or sha256(raw).hexdigest() != expected:
            raise HIAProgramRejected("frozen component source mismatch", "E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT")
        result[name] = assemble_program(raw)
    return result

FILE_FLAGS = 0x20000 | 0x800 | 0x80000

@dataclass(frozen=True, slots=True)
class LinuxFileRoundtripRequest:
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
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_STARTUP")
    for values in (snapshot.argv, snapshot.environment):
        if (type(values) is not tuple or any(type(value) is not bytes or b"\x00" in value
                                             for value in values)):
            raise HIAProgramRejected("ordered immutable NUL-free startup byte strings required",
                                     "E_HIA_LINUX_FILE_ROUNDTRIP_STARTUP")
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
    from .hia_optional_profiles import optional_profile_resource_path
    return optional_profile_resource_path(PROFILE, name)


def require_profile(profile):
    if type(profile) is not str or profile != PROFILE:
        raise HIAProgramRejected("an exact explicit Linux stdio profile is required",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE")


def profile_effects(profile):
    require_profile(profile)
    return PROFILE_EFFECTS


def profile_opcode(profile, opcode, schema):
    require_profile(profile)
    if schema != SCHEMA_V8:
        raise HIAProgramRejected("Linux stdio requires explicit primitive v8",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE")
    return PROFILE_OPCODES.get(opcode)


@dataclass(frozen=True, slots=True)
class VerifiedLinuxFileRoundtripProgram:
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
        checked = verify_linux_file_roundtrip_program(self)
        doc = checked.as_dict()
        return {"schema": "hepta.hia.linux-file-roundtrip-verification.v1", "profile": PROFILE,
                "program_sha256": checked.sha256,
                "functions_checked": len(doc["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in doc["functions"]),
                "operations_checked": sum(len(b["ops"]) for f in doc["functions"]
                                           for b in f["blocks"]),
                "typed_closed_ssa_checked": True,
                "linear_resources_and_loan_provenance_checked": True,
                "fixed_descriptors": {READ: 0, WRITE: 1, STDERR: 2},
                "private_file_capability": "only actual open result; readonly; single active",
                "file_buffer_extent": FILE_BUFFER_LIMIT,
                "resident_compiler_and_output_extent": OUTPUT_LIMIT,
                "startup_reference_is_native_authority": False,
                "default_core_authority": False, "kernel_authority": False,
                "native_artifact_created": False, "matching_cold": False,
                "whole": False}


def verify_linux_file_roundtrip_program(program):
    if type(program) is VerifiedLinuxFileRoundtripProgram:
        if type(program.canonical_bytes) is not bytes:
            raise HIAProgramRejected("profile bytes must be immutable", "E_HIA_FORMAT")
        program = program.canonical_bytes
    data, raw = _decode(program)
    if (type(data) is not dict or data.get("schema") != SCHEMA_V8
            or data.get("module") != MODULE):
        raise HIAProgramRejected("explicit primitive v8 Linux stdio module required",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE")
    functions, blocks = _reference_primitive_structure(data, profile=PROFILE)
    if (len(functions) > FUNCTION_LIMIT
            or sum(len(v) for v in blocks.values()) > BLOCK_LIMIT
            or sum(len(b["ops"]) for f in functions.values()
                   for b in f["blocks"]) > INSTRUCTION_LIMIT):
        raise HIAProgramRejected("original selfhost structural limits exceeded", "E_HIA_LIMIT")
    entry = data["functions"][0]
    if (entry["name"] != "f0"
            or [p["type"] for p in entry["params"]] != ["mutbuf", "mutbuf", "mutbuf"]
            or entry["returns"] != ["u32"]):
        raise HIAProgramRejected("Linux stdio uses the original f0 three-buffer ABI",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_ABI")
    interfaces = _function_interfaces(functions)
    for fn in functions.values():
        _verify_function(data["schema"], fn, blocks[fn["name"]], interfaces, profile=PROFILE)
    return VerifiedLinuxFileRoundtripProgram(raw)


def assemble_linux_file_roundtrip(source):
    from .hia_agent_assembly import _source, _parse_assembly_document
    raw, _ = _source(source)
    if len(raw) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    return verify_linux_file_roundtrip_program(_parse_assembly_document(raw))


def render_linux_file_roundtrip(program):
    from .hia_agent_assembly import _render_assembly_document
    checked = verify_linux_file_roundtrip_program(program)
    rendered = _render_assembly_document(checked.as_dict())
    if len(rendered.encode("utf-8")) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    if assemble_linux_file_roundtrip(rendered).canonical_bytes != checked.canonical_bytes:
        raise HIAProgramRejected("profile rendering changed verified bytes",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_ROUNDTRIP")
    return rendered


@dataclass(frozen=True, slots=True)
class LinuxFileRoundtripIORequest:
    operation: str
    fd: int
    offset: int
    count: int
    extent: int
    write_bytes: bytes


class LinuxFileRoundtripProviderRejected(ValueError):
    """The supplied observation is outside one fixed Linux I/O result."""


class LinuxFileRoundtripSignal(Exception):
    """An explicit reference-provider signal, never an implicit OS action."""

    def __init__(self, number):
        if type(number) is not int or not 1 <= number <= 64:
            raise ValueError("exact Linux signal number required")
        self.number = number
        super().__init__(number)


def _execute(checked, function, buffers, provider, startup, components, *, max_steps, max_heap_bytes,
             allocation_fail_at, max_call_depth):
    from .hia_program_runtime import (
        _Machine, _Owner, _View, _underlying, HIAProgramTrap, HIAProgramBudgetExceeded,
    )

    class LinuxFileRoundtripMachine(_Machine):
        def __init__(self):
            super().__init__(checked, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
            self.effects = []
            self.file_fd = None

        def operation(self, ins, env, depth):
            operation = ins["op"]
            if operation in RESIDENT_OPCODES:
                args = [env[name] for name in ins["args"]]
                spans = []
                for i in (0, 3, 6):
                    view, offset, count = args[i:i + 3]
                    if (type(view) is not _View or i and not view.mutable
                            or type(offset) is not int or type(count) is not int
                            or offset < 0 or count < 0):
                        raise HIAProgramRejected("invalid resident borrow", "E_HIA_RUNTIME_INVARIANT")
                    owner = _underlying(view)
                    if offset > len(owner.data) or count > len(owner.data) - offset:
                        raise HIAProgramTrap("bounds", "resident call exceeds borrowed extent")
                    spans.append((owner, offset, count))
                if len({id(item[0]) for item in spans}) != 3:
                    raise HIAProgramRejected("resident buffers must have distinct roots", "E_HIA_LOAN")
                remaining = max_steps - self.steps
                if remaining <= 0:
                    raise HIAProgramBudgetExceeded("steps", "shared process VM fuel exhausted")
                roots_child = tuple(_Owner(-(i + 1), bytearray(owner.data[offset:offset + count]))
                    for i, (owner, offset, count) in enumerate(spans))
                child = _Machine(components[operation], remaining, max_heap_bytes, None, max_call_depth)
                child_args = [_View(roots_child[0], False), _View(roots_child[1], True), _View(roots_child[2], True)]
                event = {"operation": operation, "status": "issued", "source_sha256": components[operation].sha256,
                    "spans": [{"offset": offset, "bytes": count} for _, offset, count in spans]}
                self.effects.append(event)
                try:
                    values = child.invoke(child.functions["f0"], child_args)
                    if len(values) != 1 or type(values[0]) is not int or not 0 <= values[0] <= 0xffffffff:
                        raise HIAProgramRejected("invalid resident u32 return", "E_HIA_RUNTIME_INVARIANT")
                    if child.owners or child.chains or child.loans_started != child.loans_ended:
                        raise HIAProgramRejected("resident retained local resources", "E_HIA_RUNTIME_INVARIANT")
                    env[ins["out"][0]["name"]] = values[0]
                    event.update(status="returned", result=values[0])
                except BaseException:
                    event["status"] = "raised"
                    raise
                finally:
                    self.steps += child.steps
                    event["VM_steps"] = child.steps
                    for i in (1, 2):
                        owner, offset, count = spans[i]
                        owner.data[offset:offset + count] = roots_child[i].data
                    if bytes(roots_child[0].data) != bytes(spans[0][0].data[spans[0][1]:spans[0][1] + spans[0][2]]):
                        raise HIAProgramRejected("resident modified readonly source", "E_HIA_RUNTIME_INVARIANT")
                return
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
                request = LinuxFileRoundtripRequest(operation, self.file_fd, path, offset, count,
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
                    raise LinuxFileRoundtripProviderRejected("exact signed result/bytes required")
                result, payload = response
                if not -4095 <= result <= 2147483647:
                    raise LinuxFileRoundtripProviderRejected("result outside fixed Linux file domain")
                if operation == "linux.file.read":
                    valid = result <= count and len(payload) == max(0, result)
                elif operation == "linux.file.stat":
                    valid = (result == 0 and len(payload) == 144) or (result < 0 and not payload)
                elif operation == "linux.file.close":
                    valid = result <= 0 and not payload
                else:
                    valid = not payload
                if not valid:
                    raise LinuxFileRoundtripProviderRejected("payload/result disagree with file operation")
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
            request = LinuxFileRoundtripIORequest(operation, {READ: 0, WRITE: 1, STDERR: 2}[operation],
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
                raise LinuxFileRoundtripProviderRejected("exact integer/bytes response required")
            result, payload = response
            if (not -4095 <= result <= count or result < 0 and payload
                    or operation != READ and payload
                    or operation == READ and len(payload) != max(0, result)):
                raise LinuxFileRoundtripProviderRejected("response outside one Linux I/O observation")
            # No mutation happens before the complete provider result is admitted.
            row.update(status="returned", result=result, read_hex=payload.hex())
            if operation == READ and result > 0:
                owner.data[offset:offset + result] = payload
            env[ins["out"][0]["name"]] = result

    roots = tuple(_Owner(-(i + 1), bytearray(raw)) for i, raw in enumerate(buffers))
    arguments = [_View(root, True) for root in roots]
    machine = LinuxFileRoundtripMachine()

    def observation(status, values=None, error=None):
        result = machine.report(function, status, values, error, external_roots=roots)
        result.update(schema="hepta.hia.linux-file-roundtrip-execution.v1", profile=PROFILE,
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
    except (LinuxFileRoundtripSignal, LinuxFileRoundtripProviderRejected) as exc:
        # These are profile-owned reference outcomes, not ordinary Core traps
        # or a claim that a real kernel signal/provider was observed.
        exc.report = {"schema": "hepta.hia.linux-file-roundtrip-external-outcome.v1",
            "profile": PROFILE, "program_sha256": checked.sha256,
            "status": "external_signal" if type(exc) is LinuxFileRoundtripSignal else "provider_refused",
            "signal": exc.number if type(exc) is LinuxFileRoundtripSignal else None,
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


def execute_linux_file_roundtrip(program, function, arguments, *, provider, startup, components,
                        max_steps=1000000, max_heap_bytes=16 * 1024 * 1024,
                        allocation_fail_at=None, max_call_depth=256):
    checked = verify_linux_file_roundtrip_program(program)
    startup = _checked_startup(startup)
    components = _checked_components(components)
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
            for raw, limit in zip(buffers, (FILE_BUFFER_LIMIT, OUTPUT_LIMIT, WORKSPACE_LIMIT))):
        raise HIAProgramRejected("exact file borrow <=8 MiB+1 and output/workspace <=1 MiB required",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_ABI")
    return _execute(checked, function, buffers, provider, startup, components, max_steps=max_steps,
        max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
        max_call_depth=max_call_depth)
