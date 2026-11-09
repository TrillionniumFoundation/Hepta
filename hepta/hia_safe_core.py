"""All-input translation validation for a small, explicit direct-native profile.

The checker independently interprets admitted Core and *final linked machine
bytes*.  It asks Z3 whether any scalar inputs, caller bytes or ABI state can
change the return/abort outcome, caller memory, memory bounds or saved state.
Only UNSAT for every violation obligation passes. The independent decoder,
ELF parser, Core model, Z3 and libc/loader contract are a stated trust base;
this is not a Lean-kernel proof of a complete ISA or the whole HIA language.
"""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import tempfile
import time

from .hia_program import verify_program
from .hia_safe_core_elf import bind_final_artifact
from .hia_safe_core_x64 import Executor


SCHEMA = "hepta.hia.safe-core-machine-validation.v1"
PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v1"
ARTIFACT_PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1"
PROFILE_V2 = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v2"
ARTIFACT_PROFILE_V2 = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v2"
ARTIFACT_PROPERTY = "all-input Core-to-final-image return/abort/caller-bytes refinement, memory bounds and SysV preservation"
ARTIFACT_OBLIGATIONS = (
    ("caller_contract_nonvacuous", "sat"),
    ("machine_memory_access_bounds", "unsat"),
    ("sysv_stack_alignment_and_preservation", "unsat"),
    ("all_inputs_reach_a_terminal_model_outcome", "unsat"),
    ("core_to_final_image_return_abort_and_caller_bytes", "unsat"),
)
PINNED_Z3_VERSION = "4.15.4"
WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64, "bool": 1}
WIDTHS_V2 = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64, "bool": 1}
LOANS = {"readbuf", "mutbuf"}
OPERATIONS = frozenset({"const", "int.add.wrap", "int.sub.wrap", "int.add.checked", "int.sub.checked",
                        "bit.and", "bit.or", "bit.xor", "bit.not", "bool.and", "bool.or", "bool.not",
                        "int.cast", "select", "buffer.len", "buffer.load", "buffer.store",
                        *["compare." + c for c in ("eq", "ne", "lt", "le", "gt", "ge")]})
LIMITS = {
    "functions": 1, "blocks": 16, "operations": 64, "abi_argument_words": 6,
    "borrowed_ranges": 1, "foreign_extent": 1 << 20, "machine_text_bytes": 65536,
    "stack_bytes": 16384, "machine_steps_across_paths": 65536, "machine_paths": 4096,
    "core_paths": 1024,
}
CLAIMS = {
    "all_input_refinement_in_independent_model": True,
    "exact_final_image_and_relocations_bound": True,
    "core_abort_and_foreign_memory_effects_preserved": True,
    "foreign_memory_access_bounds_checked": True,
    "sysv_saved_registers_and_stack_checked": True,
    "acyclic_model_termination_checked": True,
    "machine_checked_isa_refinement_proved": False,
    "python_checker_soundness_proved": False,
    "foreign_pointer_provenance_or_liveness_proved": False,
    "whole_language_soundness_proved": False,
    "timing_or_side_channels_proved": False,
    "serialized_receipt_authorizes_execution": False,
}
ASSUMPTIONS = [
    "The caller obeys SysV AMD64, provides a live nonwrapping stack with 16 KiB available below RSP, and uses a conforming return address.",
    "For ABI-admitted nonempty borrowed ranges the caller supplies a live initialized allocation disjoint from the active stack; mutable ranges are exclusive for the synchronous call.",
    "The loader maps the inspected file bytes with the checked permissions and resolves the immediately bound abort slot to a nonreturning libc abort; hostile interposition is outside the contract.",
    "The independent Python Core/x86/ELF models, canonical Core verifier and the identified Z3 implementation are trusted; their refinement to the complete hardware ISA is not kernel-proved.",
    "Native traps are observed as nonreturning abort, with preceding caller-memory effects retained; distinct HIA trap codes are not promised by the existing native ABI.",
    "No concurrency, signals, hardware faults, stack exhaustion, timing, side-channel or arbitrary native-caller safety claim is made.",
]

UNPROVED_OBLIGATIONS = [
    {"property": "complete_x86_hardware_refinement", "status": "unproved",
     "reason": "The independent instruction semantics and ELF/loader model are trusted Python implementations."},
    {"property": "whole_HIA_language_refinement", "status": "unproved",
     "reason": "Only the declared finite Safe Core profile is admitted."},
    {"property": "foreign_pointer_provenance_and_liveness", "status": "assumed",
     "reason": "The synchronous caller supplies the live private allocation and stack."},
    {"property": "concurrency_signals_faults_and_side_channels", "status": "unproved",
     "reason": "These observations lie outside the sequential return/abort/byte model."},
    {"property": "execution_authorization", "status": "not_granted",
     "reason": "A mathematical validation receipt does not authorize loading, execution or adoption."},
]
CHECKER_SOURCE_FILES = (
    "hia_safe_core.py", "hia_safe_core_x64.py", "hia_safe_core_elf.py",
    "hia_program.py", "hia_opcodes.py", "hia_capability_flow.py", "hia_schema.py",
    "hia_json_preflight.py", "elf_shared_abi.py",
)


def _checker_source_identity():
    """Identify the consumer models separately from producer provenance."""
    return {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in CHECKER_SOURCE_FILES}


class SafeCoreRejected(ValueError):
    def __init__(self, message, *, counterexample=None, validation=None):
        super().__init__("E_HIA_SAFE_CORE: " + message)
        self.counterexample = counterexample
        self.validation = validation


def require(condition, message):
    if not condition:
        raise SafeCoreRejected(message)


def _source_identity():
    names = ("hia_safe_core.py", "hia_safe_core_x64.py", "hia_safe_core_elf.py",
             "hia_program.py", "hia_opcodes.py", "hia_capability_flow.py", "hia_schema.py",
             "hia_json_preflight.py", "hia_program_native.py", "hia_machine_x64.py",
             "hia_machine_elf.py", "hia_native_byte_abi.py", "elf_shared_abi.py")
    return {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in names}


def _solver_identity(z):
    require(z.get_version_string() == PINNED_Z3_VERSION, "the pinned Z3 version is required")
    function = z.z3core.Z3_get_version.__defaults__[0].f
    libraries = [item for item in function._objects.values() if hasattr(item, "_name")]
    require(len(libraries) == 1, "ambiguous loaded solver library")
    library = Path(libraries[0]._name).resolve(strict=True)
    require(library.stat().st_size <= 128 * 1024 * 1024, "solver library size is outside the identity budget")
    digest = sha256()
    for path in sorted(Path(z.__file__).parent.glob("*.py")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return {"name": "Z3", "version": z.get_version_string(), "binding_sha256": digest.hexdigest(),
            "library_sha256": sha256(library.read_bytes()).hexdigest()}


def _profile_configuration(profile_version):
    require(type(profile_version) is int and profile_version in (1, 2),
            "Safe Core profile_version must be exactly 1 or 2")
    return ((PROFILE, ARTIFACT_PROFILE, WIDTHS) if profile_version == 1
            else (PROFILE_V2, ARTIFACT_PROFILE_V2, WIDTHS_V2))


def _profile(checked, image=None, *, foreign_buffer_exports=(), profile_version=1):
    _, _, widths = _profile_configuration(profile_version)
    require(checked.structured_bytes is None, "an explicit primitive Core is required")
    document = checked.as_dict()
    require(document["schema"] in {"hepta.hia.program.v" + str(i) for i in range(1, 9)} and
            len(document["functions"]) == 1, "Safe Core admits exactly one primitive function")
    fn = document["functions"][0]
    if image is not None:
        require(image.machine_plan_sha256 is None, "agent machine plans need a separate Safe Core profile")
        require(image.exports == (fn["name"],), "the machine export must exactly match the single Core function")
        foreign_buffer_exports = image.foreign_buffer_exports
    require(len(fn["returns"]) == 1 and fn["returns"][0] in widths,
            "exactly one scalar entry/return is required")
    require(set(fn["effects"]) <= {"read", "write", "trap"}, "unreviewed resource effects")
    loan_count = sum(p["type"] in LOANS for p in fn["params"])
    require(loan_count <= 1 and sum(2 if p["type"] in LOANS else 1 for p in fn["params"]) <= 6,
            "one borrowed range and at most six ABI argument words are admitted")
    if loan_count:
        require(type(foreign_buffer_exports) is tuple and len(foreign_buffer_exports) == 1 and
                type(foreign_buffer_exports[0]) is tuple and len(foreign_buffer_exports[0]) == 2 and
                foreign_buffer_exports[0][0] == fn["name"] and type(foreign_buffer_exports[0][1]) is int and
                1 <= foreign_buffer_exports[0][1] <= LIMITS["foreign_extent"] and fn["returns"] == ["u32"],
                "borrowed range requires an exact extent and the u32 packed-result ABI")
    else:
        require(foreign_buffer_exports == (), "scalar entry cannot carry a foreign range manifest")
    blocks = {block["id"]: block for block in fn["blocks"]}
    require(len(blocks) <= 16 and sum(len(b["ops"]) for b in blocks.values()) <= 64,
            "Safe Core block/operation budget exceeded")
    types = [p["type"] for p in fn["params"]] + fn["returns"]
    for block in blocks.values():
        types.extend(p["type"] for p in block["params"])
        for op in block["ops"]:
            require(op["op"] in OPERATIONS, "operation lies outside Safe Core: " + op["op"])
            require(op["op"] != "int.cast" or op["attrs"]["mode"] == "wrap" or profile_version == 2,
                    "checked casts are outside Safe Core v1")
            types.extend(p["type"] for p in op["out"])
    require(all(t in widths or t in LOANS for t in types), "type lies outside Safe Core")
    visiting, done = set(), set()

    def visit(name):
        require(name not in visiting, "loops or recursion lie outside Safe Core")
        if name in done:
            return
        visiting.add(name)
        term = blocks[name]["term"]
        require(term["op"] in {"ret", "trap", "jump", "branch"}, "unreviewed terminator")
        edges = [term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []
        for edge in edges:
            visit(edge["target"])
        visiting.remove(name)
        done.add(name)
    for name in blocks:
        visit(name)
    return fn, blocks


class _Theory:
    def __init__(self, z, timeout_ms, *, widths=WIDTHS):
        self.z, self.ctx = z, z.Context()
        self.widths = dict(widths)
        self.started = time.monotonic()
        self.deadline = self.started + timeout_ms / 1000
        self.memory = z.Array("initial_caller_bytes", z.BitVecSort(64, self.ctx), z.BitVecSort(8, self.ctx))
        self.inputs, self.words, self.loan = {}, [], None

    def check_time(self):
        require(time.monotonic() < self.deadline, "total validation deadline exhausted")

    def bv(self, value):
        return self.z.BitVecVal(value & ((1 << 64) - 1), 64, ctx=self.ctx)

    def normalized(self, value, typ):
        return self.z.simplify(value & self.bv((1 << self.widths[typ]) - 1))

    def arguments(self, fn):
        for param in fn["params"]:
            name, typ = param["name"], param["type"]
            first = self.z.BitVec("abi_word_" + str(len(self.words)), 64, ctx=self.ctx)
            self.words.append(first)
            if typ in LOANS:
                length = self.z.BitVec("abi_word_" + str(len(self.words)), 64, ctx=self.ctx)
                self.words.append(length)
                self.loan = (first, length, typ)
                self.inputs[name] = self.loan
            else:
                self.inputs[name] = self.normalized(first, typ)

    def reference(self, fn, blocks, extent):
        z = self.z
        outcomes, path = [], z.BoolVal(True, ctx=self.ctx)

        def outcome(kind, path, memory, value=None):
            outcomes.append(dict(kind=kind, path=z.simplify(path), memory=memory,
                                 value=self.bv(0) if value is None else value))

        if self.loan is not None:
            pointer, length, typ = self.loan
            for code, bad in ((1, z.UGT(length, extent)), (2, z.And(length != 0, pointer == 0)),
                              (3, z.And(length != 0, z.ULT(pointer + length, pointer)))):
                outcome("return", z.And(path, bad), self.memory, self.bv(code << 32))
                path = z.simplify(z.And(path, z.Not(bad)))
        pending = [(fn["entry"], dict(self.inputs), self.memory, path)]
        paths = 0
        while pending:
            ident, env, memory, path = pending.pop()
            self.check_time()
            paths += 1
            require(paths <= 1024, "Core path budget exceeded")
            block = blocks[ident]
            types = {p["name"]: p["type"] for p in block["params"]}
            for operation in block["ops"]:
                self.check_time()
                name, attrs = operation["op"], operation["attrs"]
                args = [env[p] for p in operation["args"]]
                out = operation["out"]
                typ = out[0]["type"] if out else None
                value, trap = None, None
                if name == "const":
                    value = self.bv(int(attrs["value"]))
                elif name.startswith("int.add.") or name.startswith("int.sub."):
                    a, b = args
                    value = self.normalized(a + b if name.startswith("int.add.") else a - b, typ)
                    if name.endswith("checked"):
                        trap = z.ULT(value, a) if name.startswith("int.add.") else z.ULT(a, b)
                elif name in ("bit.and", "bool.and", "bit.or", "bool.or", "bit.xor"):
                    a, b = args
                    value = a & b if name.endswith("and") else a | b if name.endswith("or") and name != "bit.xor" else a ^ b
                elif name in ("bit.not", "bool.not"):
                    value = self.normalized(~args[0], typ)
                elif name == "int.cast":
                    value = self.normalized(args[0], typ)
                    if attrs["mode"] == "checked":
                        # Normalized unsigned inputs must fit the target before
                        # narrowing. Equal-width and widening casts never fail.
                        trap = z.UGT(args[0], self.bv((1 << self.widths[typ]) - 1))
                elif name.startswith("compare."):
                    a, b = args
                    relation = {"eq": lambda: a == b, "ne": lambda: a != b, "lt": lambda: z.ULT(a, b),
                                "le": lambda: z.ULE(a, b), "gt": lambda: z.UGT(a, b), "ge": lambda: z.UGE(a, b)}[name.split(".")[1]]()
                    value = z.If(relation, self.bv(1), self.bv(0))
                elif name == "select":
                    value = z.If(args[0] != 0, args[1], args[2])
                elif name == "buffer.len":
                    value = args[0][1]
                elif name in ("buffer.load", "buffer.store"):
                    pointer, length, permission = args[0]
                    index = args[1]
                    trap = z.UGE(index, length)
                    outcome("abort", z.And(path, trap), memory)
                    path = z.simplify(z.And(path, z.Not(trap)))
                    trap = None
                    if name == "buffer.load":
                        value = z.ZeroExt(56, z.Select(memory, pointer + index))
                    else:
                        require(permission == "mutbuf", "reference cannot write a read-only loan")
                        memory = z.Store(memory, pointer + index, z.Extract(7, 0, args[2]))
                else:
                    raise SafeCoreRejected("missing independent Core semantics")
                if trap is not None:
                    outcome("abort", z.And(path, trap), memory)
                    path = z.simplify(z.And(path, z.Not(trap)))
                if out:
                    require(len(out) == 1 and value is not None, "unsupported Core result shape")
                    env[out[0]["name"]], types[out[0]["name"]] = z.simplify(value), typ
            term = block["term"]
            if term["op"] == "ret":
                outcome("return", path, memory, env[term["values"][0]])
            elif term["op"] == "trap":
                outcome("abort", path, memory)
            else:
                edges = [(term, path)] if term["op"] == "jump" else [
                    (term["then"], z.And(path, env[term["cond"]] != 0)),
                    (term["else"], z.And(path, env[term["cond"]] == 0))]
                for edge, guard in edges:
                    values = [env[name] for name in edge["args"]]
                    incoming = {p["name"]: value for p, value in zip(blocks[edge["target"]]["params"], values)}
                    pending.append((edge["target"], incoming, memory, z.simplify(guard)))
        return outcomes

    def merge(self, outcomes):
        z = self.z
        require(outcomes, "model has no terminal outcome")
        result, memory = self.bv(0), self.memory
        for row in outcomes:
            result = z.If(row["path"], row["value"], result)
            memory = z.If(row["path"], row["memory"], memory)
        aborts = z.Or(*[row["path"] for row in outcomes if row["kind"] == "abort"], z.BoolVal(False, ctx=self.ctx))
        coverage = z.Or(*[row["path"] for row in outcomes])
        return coverage, aborts, result, memory


def validate_safe_core_image(document, image, final_bytes, *, timeout_ms=15000, query_directory=None,
                             profile_version=1):
    """Canonical build convenience wrapper; semantics are checked on supplied bytes."""
    from .hia_program_native import HIAProgramMachine, emit_program_machine
    checked = verify_program(document)
    require(isinstance(image, HIAProgramMachine), "a direct-native machine image is required")
    canonical_profile, _, _ = _profile_configuration(profile_version)
    _profile(checked, image, profile_version=profile_version)
    producer_identity = _source_identity()
    require(image == emit_program_machine(checked, foreign_buffer_exports=image.foreign_buffer_exports),
            "candidate image is not rederived from the exact Core")
    report = validate_safe_core_artifact(
        checked, image.object_bytes, final_bytes,
        foreign_buffer_exports=image.foreign_buffer_exports,
        timeout_ms=timeout_ms, query_directory=query_directory, profile_version=profile_version)
    require(producer_identity == _source_identity(), "producer source changed during validation")
    report["source_identity"] = producer_identity
    report["profile"] = canonical_profile
    report["backend_implementation_sha256"] = image.implementation_sha256
    report["producer_provenance"] = {"method": "canonical_reemission_identity",
                                     "semantic_proof": False}
    return report


def validate_safe_core_artifact(document, object_bytes, final_bytes, *,
                                foreign_buffer_exports=(), timeout_ms=15000, query_directory=None,
                                profile_version=1):
    """Independently check exact object/final ELF bytes, without importing an emitter.

    Object text, symbols, relocations and loader state are decoded from the supplied
    bytes.  The compiler is neither invoked nor assumed correct.  This accepts a
    noncanonical encoding only when the independent model proves all obligations;
    producer receipts and matching hashes never substitute for that computation.
    """
    require(type(object_bytes) is bytes and type(final_bytes) is bytes,
            "object and final image must be immutable bytes, not mutable buffers or subclasses")
    require(type(timeout_ms) is int and 100 <= timeout_ms <= 60000, "timeout must be 100..60000 milliseconds")
    checked = verify_program(document)
    _, artifact_profile, widths = _profile_configuration(profile_version)
    fn, blocks = _profile(checked, foreign_buffer_exports=foreign_buffer_exports,
                         profile_version=profile_version)
    identity = _checker_source_identity()
    checker_identity = identity
    binding = bind_final_artifact(object_bytes, final_bytes, fn["name"])
    try:
        z = importlib.import_module("z3")
    except ImportError as exc:
        raise SafeCoreRejected("pinned z3-solver is unavailable; no proof result") from exc
    solver_identity = _solver_identity(z)
    retained = None
    if query_directory is not None:
        retained = Path(query_directory).absolute()
        retained.mkdir(parents=False, exist_ok=False)
    t = _Theory(z, timeout_ms, widths=widths)
    t.arguments(fn)
    extent = None if not foreign_buffer_exports else foreign_buffer_exports[0][1]
    reference = t.reference(fn, blocks, extent)
    machine = Executor(t, binding, t.words, t.loan)
    observed = machine.run()
    # The abstract stack is keyed by exact offsets.  Foreign data is a separate
    # array only under this explicit disjointness premise; numeric ABI guards
    # are still modelled and proved for every invalid pointer/length word pair.
    assumptions = [z.UGE(machine.sp, 16384), z.ULE(machine.sp, (1 << 64) - 16),
                   machine.sp & t.bv(15) == 8]
    if t.loan is not None:
        pointer, length, typ = t.loan
        admitted = z.And(z.ULE(length, extent), z.Or(length == 0, z.And(pointer != 0, z.UGE(pointer + length, pointer))))
        disjoint = z.Or(length == 0, z.ULE(pointer + length, machine.sp - 16384), z.UGE(pointer, machine.sp + 8))
        assumptions.append(z.Implies(admitted, disjoint))
    rc, ra, rv, rm = t.merge(reference)
    mc, ma, mv, mm = t.merge(observed)
    false = z.BoolVal(False, ctx=t.ctx)
    obligations = [
        ("caller_contract_nonvacuous", z.BoolVal(True, ctx=t.ctx), "sat"),
        ("machine_memory_access_bounds", z.Or(*machine.faults, false), "unsat"),
        ("sysv_stack_alignment_and_preservation", z.Or(*machine.abi_faults, false), "unsat"),
        ("all_inputs_reach_a_terminal_model_outcome", z.Or(z.Not(rc), z.Not(mc)), "unsat"),
        ("core_to_final_image_return_abort_and_caller_bytes",
         z.Or(ra != ma, z.And(z.Not(ra), rv != mv), rm != mm), "unsat"),
    ]
    require(tuple((name, expected) for name, _, expected in obligations) == ARTIFACT_OBLIGATIONS,
            "the declared and executed obligation inventories differ")
    reports = []

    def report(status, *, complete):
        subject = {"core_sha256": checked.sha256, "input_sha256": checked.input_sha256,
                   "object_sha256": sha256(object_bytes).hexdigest(),
                   "final_image_sha256": sha256(final_bytes).hexdigest(),
                   "entry_symbol": fn["name"], "foreign_buffer_exports": [list(pair) for pair in foreign_buffer_exports]}
        checker = {"name": "hepta.hia_safe_core.validate_safe_core_artifact",
                   "source_identity": checker_identity, "solver": solver_identity,
                   "producer_reemission_used": False}
        return {"schema": SCHEMA, "profile": artifact_profile, "ok": status == "smt_validated",
                "status": status, "complete": complete,
                "artifact_input_profile": artifact_profile,
                "validation_mode": "independent_supplied_bytes", "subject": subject,
                "property": ARTIFACT_PROPERTY,
                "checker": checker, "unproved_obligations": [dict(row) for row in UNPROVED_OBLIGATIONS],
                "core_sha256": checked.sha256, "input_sha256": checked.input_sha256,
                "core_schema": checked.as_dict()["schema"], "backend_implementation_sha256": None,
                "source_identity": identity, "solver": solver_identity, "image_binding": binding["binding"],
                "function": fn["name"], "foreign_buffer_exports": [list(pair) for pair in foreign_buffer_exports],
                "model_counts": {"decoded_instructions": len(machine.code), "symbolic_machine_steps": machine.steps,
                                 "machine_terminal_paths": len(observed), "core_terminal_paths": len(reference),
                                 "maximum_observed_stack_bytes": -machine.minimum_stack_offset},
                "obligations": list(reports), "claims": dict(CLAIMS) if complete else {},
                "assumptions": list(ASSUMPTIONS), "limits": dict(LIMITS),
                "elapsed_seconds": time.monotonic() - t.started}

    def check_deadline():
        try:
            t.check_time()
        except SafeCoreRejected as exc:
            raise SafeCoreRejected("validation deadline expired; no completed proof",
                                   validation=report("unknown", complete=False)) from exc

    for index, (name, violation, expected) in enumerate(obligations):
        check_deadline()
        solver = z.Solver(ctx=t.ctx)
        solver.set(timeout=max(1, int((t.deadline - time.monotonic()) * 1000)))
        solver.add(*assumptions, violation)
        query_bytes = (solver.sexpr() + "\n(check-sat)\n").encode()
        require(len(query_bytes) <= 16 * 1024 * 1024, "SMT query byte budget exceeded")
        query_hash = sha256(query_bytes).hexdigest()
        filename = f"{index:02d}-{name}.smt2"
        if retained is not None:
            with (retained / filename).open("xb") as stream:
                stream.write(query_bytes)
        started = time.monotonic()
        result = str(solver.check())
        reports.append({"name": name, "result": result, "expected": expected,
                        "query_sha256": query_hash, "elapsed_seconds": time.monotonic() - started})
        if retained is not None:
            reports[-1]["query_file"] = filename
            (retained / (filename + ".result.json")).write_text(json.dumps(reports[-1], indent=2) + "\n")
        check_deadline()
        if result != expected:
            counterexample = None
            if result == "sat":
                model = solver.model()
                counterexample = {"abi_words": [model.eval(v, model_completion=True).as_long() for v in t.words],
                                  "initial_rsp": model.eval(machine.sp, model_completion=True).as_long(),
                                  "obligation": name}
            raise SafeCoreRejected(name + ": " + result + (" (" + solver.reason_unknown() + ")" if result == "unknown" else ""),
                                   counterexample=counterexample,
                                   validation=report("refuted" if counterexample is not None else "unknown", complete=False))
    require(identity == _checker_source_identity() and solver_identity == _solver_identity(z),
            "checker or solver source changed during validation")
    check_deadline()
    return report("smt_validated", complete=True)


def build_safe_core(document, output, *, foreign_extent=None, linker="ld", timeout_ms=15000,
                    query_directory=None, profile_version=1):
    """Build privately, validate final bytes, then atomically publish those bytes."""
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    from .hia_program_native import emit_program_machine, compile_program_machine
    checked = verify_program(document)
    functions = checked.as_dict()["functions"]
    require(len(functions) == 1, "Safe Core requires one function")
    exports = () if foreign_extent is None else ((functions[0]["name"], foreign_extent),)
    _profile(checked, foreign_buffer_exports=exports, profile_version=profile_version)
    image = emit_program_machine(checked, foreign_buffer_exports=exports)
    destination = Path(os.path.abspath(output))
    require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(),
            "output must be a new path in an existing directory")
    with tempfile.TemporaryDirectory(prefix=".hia-safe-core-", dir=destination.parent) as temporary:
        candidate = Path(temporary) / "candidate.so"
        compilation = compile_program_machine(image, program=checked, output=candidate, linker=linker)
        data = candidate.read_bytes()
        report = validate_safe_core_image(checked, image, data, timeout_ms=timeout_ms,
                                          query_directory=query_directory, profile_version=profile_version)
        published = publish_verified(candidate, destination, data)
        try:
            verify_published(candidate, destination, data)
            require(report["source_identity"] == _source_identity(), "checker changed before final publication")
        except BaseException:
            withdraw_own_link(candidate, destination)
            raise
    return {"schema": "hepta.hia.safe-core-build.v1", "ok": True, "output": str(destination),
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "compilation": compilation, "validation": report,
            "status": "smt_validated_not_executed", "claims": dict(CLAIMS)}
