"""Explicit Linux startup/stdin/stdout/stderr profile; it is never an ordinary Core authority.

This module extends the *actual* typed instruction and loan checker. It does not
replace an I/O instruction by a call to a fabricated function. The VM receives a
caller-supplied finite physical-effect provider; importing or verifying this
profile does not bind Python's file descriptors. Native construction is a
separate HIA-compiler/HIA-ELF-packer operation.
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

PROFILE = "hepta.hia.linux-process.v1"
MODULE = "selfhost_linux_process"
PROFILE_SOURCE_FILES = (
    "examples/hia_bootstrap/selfhost_linux_process.hepta",
    "examples/hia_bootstrap/linux_process_entry_packer.hepta",
)
SOURCE_LIMIT = OUTPUT_LIMIT = WORKSPACE_LIMIT = 1048576
FUNCTION_LIMIT = 128
BLOCK_LIMIT = 1536
INSTRUCTION_LIMIT = 8192
READ = "linux.stdin.read"
WRITE = "linux.stdout.write"
STDERR = "linux.stderr.write"
STARTUP_EFFECT = "linux_startup"
PROFILE_EFFECTS = EFFECTS | {"linux_io", STARTUP_EFFECT}
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
PROFILE_OPCODES = MappingProxyType({**IO_OPCODES, **STARTUP_OPCODES})


@dataclass(frozen=True, slots=True)
class LinuxStartupSnapshot:
    """Explicit immutable VM reference data; never a native kernel capability."""

    argv: tuple[bytes, ...]
    environment: tuple[bytes, ...]


def _checked_startup(snapshot):
    if type(snapshot) is not LinuxStartupSnapshot:
        raise HIAProgramRejected("an explicit reference startup snapshot is required",
                                 "E_HIA_LINUX_PROCESS_STARTUP")
    for values in (snapshot.argv, snapshot.environment):
        if (type(values) is not tuple or any(type(value) is not bytes or b"\x00" in value
                                             for value in values)):
            raise HIAProgramRejected("ordered immutable NUL-free startup byte strings required",
                                     "E_HIA_LINUX_PROCESS_STARTUP")
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
                                 "E_HIA_LINUX_PROCESS_PROFILE")


def profile_effects(profile):
    require_profile(profile)
    return PROFILE_EFFECTS


def profile_opcode(profile, opcode, schema):
    require_profile(profile)
    if schema != SCHEMA_V8:
        raise HIAProgramRejected("Linux stdio requires explicit primitive v8",
                                 "E_HIA_LINUX_PROCESS_PROFILE")
    return PROFILE_OPCODES.get(opcode)


@dataclass(frozen=True, slots=True)
class VerifiedLinuxProcessProgram:
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
        checked = verify_linux_process_program(self)
        doc = checked.as_dict()
        return {"schema": "hepta.hia.linux-process-verification.v1", "profile": PROFILE,
                "program_sha256": checked.sha256,
                "functions_checked": len(doc["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in doc["functions"]),
                "operations_checked": sum(len(b["ops"]) for f in doc["functions"]
                                           for b in f["blocks"]),
                "typed_closed_ssa_checked": True,
                "linear_resources_and_loan_provenance_checked": True,
                "fixed_descriptors": {READ: 0, WRITE: 1, STDERR: 2},
                "startup_reference_is_native_authority": False,
                "default_core_authority": False, "kernel_authority": False,
                "native_artifact_created": False, "matching_cold": False,
                "whole": False}


def verify_linux_process_program(program):
    if type(program) is VerifiedLinuxProcessProgram:
        if type(program.canonical_bytes) is not bytes:
            raise HIAProgramRejected("profile bytes must be immutable", "E_HIA_FORMAT")
        program = program.canonical_bytes
    data, raw = _decode(program)
    if (type(data) is not dict or data.get("schema") != SCHEMA_V8
            or data.get("module") != MODULE):
        raise HIAProgramRejected("explicit primitive v8 Linux stdio module required",
                                 "E_HIA_LINUX_PROCESS_PROFILE")
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
                                 "E_HIA_LINUX_PROCESS_ABI")
    interfaces = _function_interfaces(functions)
    for fn in functions.values():
        _verify_function(data["schema"], fn, blocks[fn["name"]], interfaces, profile=PROFILE)
    return VerifiedLinuxProcessProgram(raw)


def assemble_linux_process(source):
    from .hia_agent_assembly import _source, _parse_assembly_document
    raw, _ = _source(source)
    if len(raw) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    return verify_linux_process_program(_parse_assembly_document(raw))


def render_linux_process(program):
    from .hia_agent_assembly import _render_assembly_document
    checked = verify_linux_process_program(program)
    rendered = _render_assembly_document(checked.as_dict())
    if len(rendered.encode("utf-8")) > SOURCE_LIMIT:
        raise HIAProgramRejected("Linux stdio source exceeds 1 MiB", "E_HIA_LIMIT")
    if assemble_linux_process(rendered).canonical_bytes != checked.canonical_bytes:
        raise HIAProgramRejected("profile rendering changed verified bytes",
                                 "E_HIA_LINUX_PROCESS_ROUNDTRIP")
    return rendered


@dataclass(frozen=True, slots=True)
class LinuxProcessRequest:
    operation: str
    fd: int
    offset: int
    count: int
    extent: int
    write_bytes: bytes


class LinuxProcessProviderRejected(ValueError):
    """The supplied observation is outside one fixed Linux I/O result."""


class LinuxProcessSignal(Exception):
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

    class LinuxProcessMachine(_Machine):
        def __init__(self):
            super().__init__(checked, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
            self.effects = []

        def operation(self, ins, env, depth):
            operation = ins["op"]
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
            request = LinuxProcessRequest(operation, {READ: 0, WRITE: 1, STDERR: 2}[operation],
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
                raise LinuxProcessProviderRejected("exact integer/bytes response required")
            result, payload = response
            if (not -4095 <= result <= count or result < 0 and payload
                    or operation != READ and payload
                    or operation == READ and len(payload) != max(0, result)):
                raise LinuxProcessProviderRejected("response outside one Linux I/O observation")
            # No mutation happens before the complete provider result is admitted.
            row.update(status="returned", result=result, read_hex=payload.hex())
            if operation == READ and result > 0:
                owner.data[offset:offset + result] = payload
            env[ins["out"][0]["name"]] = result

    roots = tuple(_Owner(-(i + 1), bytearray(raw)) for i, raw in enumerate(buffers))
    arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
    machine = LinuxProcessMachine()

    def observation(status, values=None, error=None):
        result = machine.report(function, status, values, error, external_roots=roots)
        result.update(schema="hepta.hia.linux-process-execution.v1", profile=PROFILE,
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
    except (LinuxProcessSignal, LinuxProcessProviderRejected) as exc:
        # These are profile-owned reference outcomes, not ordinary Core traps
        # or a claim that a real kernel signal/provider was observed.
        exc.report = {"schema": "hepta.hia.linux-process-external-outcome.v1",
            "profile": PROFILE, "program_sha256": checked.sha256,
            "status": "external_signal" if type(exc) is LinuxProcessSignal else "provider_refused",
            "signal": exc.number if type(exc) is LinuxProcessSignal else None,
            "steps": machine.steps, "resources": machine.resources(),
            "source_hex": roots[0].data.hex(), "output_hex": roots[1].data.hex(),
            "workspace_hex": roots[2].data.hex(), "effects": machine.effects,
            "actual_kernel_execution": False, "matching_cold": False, "whole": False}
        raise
    except RecursionError as exc:
        limit = HIAProgramBudgetExceeded("calls", "host recursion limit reached")
        limit.report = observation("budget_exceeded", error=limit)
        raise limit from exc
    if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
        raise HIAProgramRejected("profile return retains local resources", "E_HIA_RUNTIME_INVARIANT")
    return observation("returned", values)


def execute_linux_process(program, function, arguments, *, provider, startup,
                        max_steps=1000000, max_heap_bytes=16 * 1024 * 1024,
                        allocation_fail_at=None, max_call_depth=256):
    checked = verify_linux_process_program(program)
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
    if len(buffers) != 3 or any(type(raw) is not bytes or len(raw) > SOURCE_LIMIT for raw in buffers):
        raise HIAProgramRejected("three exact immutable buffers, at most 1 MiB each, required",
                                 "E_HIA_LINUX_PROCESS_ABI")
    return _execute(checked, function, buffers, provider, startup, max_steps=max_steps,
        max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
        max_call_depth=max_call_depth)
