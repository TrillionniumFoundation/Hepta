"""All-input translation validation for a small, explicit direct-native profile.

The checker independently interprets admitted Core and *final linked machine
bytes*. It asks whether any scalar inputs, caller bytes or ABI state can
change the return/abort outcome, caller memory, memory bounds or saved state.
Only UNSAT for every violation obligation passes. A bounded scalar lane uses
the selected HIA decoder and word solver; the general model uses pinned Z3.
These models and the loader contract are trusted, not a complete ISA proof.
"""
from __future__ import annotations

from .hia_loaded_source import loaded_checker_identity, loaded_source_identity
from .hia_verified_input_identity import INPUT_SOURCE_FILES, bind_input_execution
from .hia_solver_identity import solver_identity as _loaded_solver_identity

from hashlib import sha256
import importlib
from itertools import combinations
import json
import os
from pathlib import Path
import tempfile
import time

from .hia_program import verify_program
from .hia_safe_core_elf import bind_final_artifact
from .hia_safe_core_x64 import Executor
from .hia_verified_image import VerifiedImageRejected, read_bounded_elf_image


SCHEMA = "hepta.hia.safe-core-machine-validation.v1"
PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v1"
ARTIFACT_PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1"
PROFILE_V2 = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v2"
ARTIFACT_PROFILE_V2 = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v2"
PROFILE_V3 = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v3"
ARTIFACT_PROFILE_V3 = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v3"
PROFILE_V4 = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v4"
ARTIFACT_PROFILE_V4 = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v4"
PROFILE_V5 = "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v5"
ARTIFACT_PROFILE_V5 = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v5"
PROFILE_V6 = "hia.safe-core.integer-acyclic-single-borrow.x86_64.v6"
ARTIFACT_PROFILE_V6 = "hia.safe-core.integer-acyclic-single-borrow.supplied-elf.x86_64.v6"
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
WIDTHS_V6 = {**WIDTHS_V2, "i8": 8, "i16": 16, "i32": 32, "i64": 64, "isize": 64}
LOANS = {"readbuf", "mutbuf"}
OPERATIONS = frozenset({"const", "int.add.wrap", "int.sub.wrap", "int.mul.wrap", "int.add.checked", "int.sub.checked",
                        "bit.and", "bit.or", "bit.xor", "bit.not", "bool.and", "bool.or", "bool.not",
                        "int.cast", "select", "buffer.len", "buffer.load", "buffer.store",
                        *["compare." + c for c in ("eq", "ne", "lt", "le", "gt", "ge")]})
OPERATIONS_V3 = OPERATIONS | {"int.neg.checked", "int.shl.checked", "int.shr.checked"}
OPERATIONS_V4 = OPERATIONS_V3 | {"int.mul.checked"}
OPERATIONS_V5 = OPERATIONS_V4 | {"int.div.checked", "int.rem.checked"}
OPERATIONS_V6 = OPERATIONS_V5
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
     "reason": "The independent checker, including selected HIA rules and retained host semantics, is trusted."},
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
    "hia_json_preflight.py", "elf_shared_abi.py", "hia_solver_identity.py",
) + INPUT_SOURCE_FILES


def _selected_machine_proof(*, observe=False):
    from .hia_cnf_native import selected_cnf
    from .hia_default_native import default_safe_core_pair
    from .hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

    decoder, cnf = selected_safe_core_x64_decode(), selected_cnf()
    if decoder is None and cnf is None:
        return default_safe_core_pair(observe=observe)
    return decoder, cnf


def _checker_source_identity(pair=None):
    """Identify the consumer models separately from producer provenance."""
    from .hia_safe_core_elf_inventory_native import selected_safe_core_elf_inventory

    decoder, cnf = _selected_machine_proof() if pair is None else pair
    helpers = (
        ('x64_decoder', 'hia_safe_core_x64_decode_native.py', decoder),
        ('elf_inventory', 'hia_safe_core_elf_inventory_native.py', selected_safe_core_elf_inventory()),
        ('cnf', 'hia_cnf_native.py', cnf),
    )
    sources = CHECKER_SOURCE_FILES
    if decoder is not None and cnf is not None:
        sources += ('hia_optimization.py',)
    if getattr(cnf, '_default_package_binding', None) is not None:
        sources += ('hia_default_native.py',)
    return loaded_checker_identity(__name__, sources, helpers)


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
             "hia_machine_elf.py", "hia_native_byte_abi.py", "elf_shared_abi.py",
             "hia_verified_image.py", "hia_solver_identity.py")
    return loaded_source_identity(__name__, names + INPUT_SOURCE_FILES)


def _solver_identity(z):
    return _loaded_solver_identity(z, expected_version=PINNED_Z3_VERSION)


class _MemoryReductionUnavailable(Exception):
    """This bounded lowering cannot represent the input; make no proof claim."""


class _FiniteCallerMemory:
    """Transport a single-base byte-array DAG to the HIA memory formulas."""

    def __init__(self, z, decoder, initial, deadline):
        self.z, self.decoder, self.initial, self.deadline = z, decoder, initial, deadline
        # Keep the source ASTs alive: the solver may recycle the numeric IDs
        # of temporary expressions after word/array substitution.
        self.scalars = {}
        self.array_indices = {initial: 0}
        self.rows = [(0, 0, 0)]
        self.effects = [()]
        self.reads = {}
        self.initial_bytes = {}
        self.used = False

    def reduce(self, expression):
        try:
            value = self.scalar(expression)
        except (_MemoryReductionUnavailable, RecursionError):
            return None
        if not self.used:
            return None
        # Each distinct symbolic read represents a byte of the same initial
        # array. Equal addresses cannot be assigned independent bytes.
        consistency = [self.formula('memory_read_agrees', left, right, a, b)
                       for (left, a), (right, b) in combinations(self.initial_bytes.values(), 2)]
        return self.z.simplify(self.z.And(value, *consistency))

    def formula(self, operation, *arguments):
        return self.decoder.memory_formula(self.z, self.initial.ctx, operation, *arguments)

    def scalar(self, term):
        z = self.z
        if term in self.scalars:
            return self.scalars[term]
        if len(self.scalars) >= 1024 or time.monotonic() >= self.deadline or not z.is_app(term):
            raise _MemoryReductionUnavailable
        if not (z.is_bool(term) or z.is_bv(term)):
            raise _MemoryReductionUnavailable
        children = term.children()
        kind = term.decl().kind()
        if kind == z.Z3_OP_SELECT:
            memory, address = children
            self.used = True
            value = self.read(self.array(memory), self.scalar(address))
        elif kind in (z.Z3_OP_EQ, z.Z3_OP_DISTINCT) and len(children) == 2 and z.is_array(children[0]):
            left, right = map(self.array, children)
            self.used = True
            terms = []
            # Both snapshots use the same initial array. Away from the
            # union of writes they agree, even if the write addresses alias.
            for index in self.decoder.possible_memory_writes(self.rows, left, right):
                address = self.effects[index][0]
                terms.append(self.read(left, address) != self.read(right, address))
            difference = z.Or(*terms) if terms else z.BoolVal(False, ctx=self.initial.ctx)
            value = z.Not(difference) if kind == z.Z3_OP_EQ else difference
        else:
            changes = [(child, lowered) for child in children
                       if not z.eq(child, lowered := self.scalar(child))]
            value = z.substitute(term, *changes) if changes else term
        if len(self.scalars) >= 1024:
            raise _MemoryReductionUnavailable
        self.scalars[term] = value
        return value

    def array(self, term):
        from .hia_safe_core_x64_decode_native import MEMORY_GRAPH_ROWS

        z = self.z
        if term in self.array_indices:
            return self.array_indices[term]
        if not z.is_app(term) or len(self.rows) >= MEMORY_GRAPH_ROWS or time.monotonic() >= self.deadline:
            raise _MemoryReductionUnavailable
        kind = term.decl().kind()
        if kind == z.Z3_OP_STORE:
            parent, address, byte = term.children()
            row = (1, self.array(parent), 0)
            effect = (self.scalar(address), self.scalar(byte))
        elif kind == z.Z3_OP_ITE:
            condition, yes, no = term.children()
            row = (2, self.array(yes), self.array(no))
            effect = (self.scalar(condition),)
        else:
            # An unrelated second array, a constant array, or arbitrary
            # function application does not satisfy the common-base theorem.
            raise _MemoryReductionUnavailable
        index = len(self.rows)
        if index >= MEMORY_GRAPH_ROWS:
            raise _MemoryReductionUnavailable
        self.array_indices[term] = index
        self.rows.append(row)
        self.effects.append(effect)
        return index

    def read(self, index, address):
        z = self.z
        address = z.simplify(address)
        identity = address.get_id()
        key = (index, address)
        if key in self.reads:
            return self.reads[key]
        if len(self.reads) >= 512 or time.monotonic() >= self.deadline:
            raise _MemoryReductionUnavailable
        kind, first, second = self.rows[index]
        if kind == 0:
            if len(self.initial_bytes) >= 16:
                raise _MemoryReductionUnavailable
            value = z.FreshConst(self.initial.range(), prefix='hia_initial_byte')
            self.initial_bytes[identity] = (address, value)
        elif kind == 1:
            write_address, byte = self.effects[index]
            value = self.formula('memory_read_store', address, write_address, byte, self.read(first, address))
        else:
            condition, = self.effects[index]
            value = self.formula('memory_read_join', condition, self.read(first, address), self.read(second, address))
        self.reads[key] = z.simplify(value)
        return self.reads[key]

    def witness(self, model, original):
        z = self.z
        memory = z.K(self.initial.domain(), z.BitVecVal(0, 8, ctx=self.initial.ctx))
        for address, byte in self.initial_bytes.values():
            memory = z.Store(memory, model.eval(address, model_completion=True),
                             model.eval(byte, model_completion=True))
        model.update_value(self.initial, memory)
        return model if z.is_true(model.eval(original, model_completion=True)) else None


def _native_obligation(z, cnf, expression, deadline, *, memory=None, native_only=False):
    """Use HIA for a precise finite Boolean reduction when available."""
    from .hia_cnf_native import SAT, UNSAT, WRAPPING_PRODUCT, abstract_wide_division, bitblast_goal, bitvector_circuit

    if cnf is None:
        return None
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 4:
        return None
    candidate = z.simplify(expression)
    reduced_memory = memory.reduce(candidate) if memory is not None else None
    if reduced_memory is not None:
        candidate = reduced_memory
    circuit = bitvector_circuit(z, candidate)
    remaining = int((deadline - time.monotonic()) * 1000)
    if circuit is not None and remaining > 0:
        product = any(node[0] == WRAPPING_PRODUCT for node in circuit.nodes)
        learning = memory is not None or product or len(circuit.nodes) > 64
        if memory is not None:
            ceiling = 5_000_000 if reduced_memory is None else 8_000_000
            steps = min(ceiling, remaining * 800)
        elif learning:
            steps = min(2_000_000, remaining * 800)
        else:
            steps = min(200_000, remaining * 100)
        solved = cnf.solve_circuit(circuit.nodes, circuit.returns, steps=steps, batch=True,
                                   watched=not learning, restarts=learning)
        if solved is not None:
            result, assignment, steps, variables, clauses, formula = solved
            witness = circuit.witness(z, assignment, candidate) if result == SAT else None
            if witness is not None and reduced_memory is not None:
                witness = memory.witness(witness, expression)
            elif witness is not None and not z.is_true(witness.eval(expression, model_completion=True)):
                witness = None
            if result == UNSAT or (result == SAT and witness is not None):
                receipt = {"method": "native_hia_circuit_cnf", "image_sha256": cnf.image_sha256,
                           "formula_sha256": sha256(formula).hexdigest(), "variables": variables,
                           "clauses": clauses, "steps": steps}
                if learning:
                    receipt["search"] = "native_hia_conflict_learning"
                    receipt["restarts"] = "bounded_geometric"
                if reduced_memory is not None:
                    receipt["caller_memory"] = "native_hia_finite_byte_array"
                return ("sat" if result == SAT else "unsat"), witness, receipt
    abstract = abstract_wide_division(z, candidate)
    if abstract is not None:
        # Arbitrary shared values include every concrete division. Only UNSAT
        # survives this overapproximation; a SAT guess is not a counterexample.
        circuit = bitvector_circuit(z, abstract)
        remaining = int((deadline - time.monotonic()) * 1000)
        if circuit is not None and remaining > 0:
            solved = cnf.solve_circuit(circuit.nodes, circuit.returns,
                                       steps=min(2_000_000, remaining * 800), restarts=True)
            if solved is not None and solved[0] == UNSAT:
                _, _, steps, variables, clauses, formula = solved
                receipt = {"method": "native_hia_circuit_cnf", "image_sha256": cnf.image_sha256,
                           "formula_sha256": sha256(formula).hexdigest(), "variables": variables,
                           "clauses": clauses, "steps": steps, "abstraction": "wide_division_unsat_only",
                           "search": "native_hia_conflict_learning", "restarts": "bounded_geometric"}
                if reduced_memory is not None:
                    receipt["caller_memory"] = "native_hia_finite_byte_array"
                return "unsat", None, receipt
    remaining = int((deadline - time.monotonic()) * 1000)
    if native_only or remaining < 4:
        return None
    goal = expression if reduced_memory is None else candidate
    reduced = bitblast_goal(z, goal, timeout_ms=min(100, remaining // 4))
    remaining = int((deadline - time.monotonic()) * 1000)
    if reduced is None or remaining <= 0:
        return None
    variables = len(reduced.atoms)
    result, assignment, steps = cnf.solve_sparse(variables, reduced.clauses, steps=min(200_000, remaining * 100),
                                                 batch=True, watched=reduced_memory is not None)
    if result not in (SAT, UNSAT):
        return None
    witness = None
    if result == SAT:
        try:
            witness = reduced.witness(z, assignment, goal)
            if witness is not None and reduced_memory is not None:
                witness = memory.witness(witness, expression)
        except z.Z3Exception:
            return None
        if witness is None:
            return None
    payload = json.dumps((variables, reduced.clauses), separators=(",", ":")).encode("ascii")
    receipt = {"method": "native_hia_cnf", "image_sha256": cnf.image_sha256,
               "formula_sha256": sha256(payload).hexdigest(),
               "variables": variables, "clauses": len(reduced.clauses), "steps": steps}
    if reduced_memory is not None:
        receipt["caller_memory"] = "native_hia_finite_byte_array"
    return ("sat" if result == SAT else "unsat"), witness, receipt


def _native_memory_faults(z, cnf, assumptions, faults, deadline, memory):
    # A disjunction is unsatisfiable exactly when every arm is
    # unsatisfiable under the same caller assumptions. Keep the retained
    # SMT query intact; this partition only changes native search order.
    arms = [fault for fault in faults if not z.is_false(fault)]
    if cnf is None or memory is None or not 2 <= len(arms) <= 16:
        return None
    parts = []
    for arm in arms:
        arm_memory = _FiniteCallerMemory(z, memory.decoder, memory.initial, deadline)
        result = _native_obligation(z, cnf, z.And(*assumptions, arm), deadline,
                                    memory=arm_memory, native_only=True)
        if result is None:
            return None
        verdict, witness, receipt = result
        if verdict == "sat":
            return verdict, witness, receipt
        parts.append(receipt)
    formulas = [part["formula_sha256"] for part in parts]
    return "unsat", None, {
        "method": "native_hia_circuit_cnf", "image_sha256": cnf.image_sha256,
        "formula_sha256": sha256(b"".join(bytes.fromhex(formula) for formula in formulas)).hexdigest(),
        "disjunct_formula_sha256": formulas,
        **{key: sum(part[key] for part in parts) for key in ("variables", "clauses", "steps")},
        "search": "native_hia_conflict_learning", "restarts": "bounded_geometric",
    }


def _profile_configuration(profile_version):
    require(type(profile_version) is int and profile_version in (1, 2, 3, 4, 5, 6),
            "Safe Core profile_version must be exactly 1, 2, 3, 4, 5 or 6")
    return ((PROFILE, ARTIFACT_PROFILE, WIDTHS) if profile_version == 1
            else (PROFILE_V2, ARTIFACT_PROFILE_V2, WIDTHS_V2) if profile_version == 2
            else (PROFILE_V3, ARTIFACT_PROFILE_V3, WIDTHS_V2) if profile_version == 3
            else (PROFILE_V4, ARTIFACT_PROFILE_V4, WIDTHS_V2) if profile_version == 4
            else (PROFILE_V5, ARTIFACT_PROFILE_V5, WIDTHS_V2) if profile_version == 5
            else (PROFILE_V6, ARTIFACT_PROFILE_V6, WIDTHS_V6))


def _unsigned_profile_version(checked):
    """Select v2 through v6 from a checked snapshot; this grants no admission.

    Producers, selectors and loaders must still apply the selected profile
    and independently validate the final bytes. Existing unsigned Core keeps
    its old profile; the historical helper name remains API-compatible.
    """
    document = checked.as_dict()
    types = set()
    for function in document["functions"]:
        types.update(function["returns"])
        types.update(parameter["type"] for parameter in function["params"])
        for block in function["blocks"]:
            types.update(parameter["type"] for parameter in block["params"])
            types.update(output["type"] for operation in block["ops"] for output in operation["out"])
    if types & {"i8", "i16", "i32", "i64", "isize"}:
        return 6
    operations = {operation["op"] for function in document["functions"]
                  for block in function["blocks"] for operation in block["ops"]}
    if operations & (OPERATIONS_V5 - OPERATIONS_V4):
        return 5
    if operations & (OPERATIONS_V4 - OPERATIONS_V3):
        return 4
    return 3 if operations & (OPERATIONS_V3 - OPERATIONS) else 2


def _profile(checked, image=None, *, foreign_buffer_exports=(), profile_version=1):
    _, _, widths = _profile_configuration(profile_version)
    operations = (OPERATIONS_V6 if profile_version == 6 else OPERATIONS_V5
                  if profile_version == 5 else OPERATIONS_V4
                  if profile_version == 4 else OPERATIONS_V3
                  if profile_version == 3 else OPERATIONS)
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
            require(op["op"] in operations, "operation lies outside Safe Core: " + op["op"])
            require(op["op"] != "int.cast" or op["attrs"]["mode"] == "wrap" or profile_version >= 2,
                    "checked casts are outside Safe Core v1")
            types.extend(p["type"] for p in op["out"])
    require(all(t in widths or t in LOANS for t in types), "type lies outside Safe Core")
    _review_core_graph(blocks)
    return fn, blocks


def _review_core_graph(blocks):
    from .hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

    native = selected_safe_core_x64_decode()
    kinds = {"ret", "trap", "jump", "branch"}
    if native is None or any(block["term"]["op"] not in kinds for block in blocks.values()):
        # Preserve the original rejection order for out-of-profile terminators.
        _reference_core_graph(blocks)
        return
    indices = {name: index for index, name in enumerate(blocks)}
    adjacency = []
    for block in blocks.values():
        term = block["term"]
        if term["op"] == "jump":
            targets = (term["target"],)
        elif term["op"] == "branch":
            targets = (term["then"]["target"], term["else"]["target"])
        else:
            targets = ()
        bits = 0
        for target in targets:
            bits |= 1 << indices[target]
        adjacency.append(bits)
    require(native.acyclic_core_graph(adjacency), "loops or recursion lie outside Safe Core")


def _reference_core_graph(blocks):
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


class _Theory:
    def __init__(self, z, timeout_ms, *, widths=WIDTHS, core_model=None):
        from .hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

        self.core_model = selected_safe_core_x64_decode() if core_model is None else core_model
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
        width = self.widths[typ]
        if typ.startswith("i") and width < 64:
            return self.z.simplify(self.z.SignExt(64 - width, self.z.Extract(width - 1, 0, value)))
        return self.z.simplify(value & self.bv((1 << width) - 1))

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
                self.inputs[name] = self.parameter_word(first, typ)

    def parameter_word(self, word, typ):
        if self.core_model is None:
            return self.normalized(word, typ)
        value, trap = self.core_model.symbolic_core(
            self.z, self.ctx, 'parameter', self.widths[typ], (word,), signed_result=typ.startswith('i'),
        )
        if trap is not None:
            raise RuntimeError('invalid native Safe Core parameter formula')
        return value

    def scalar_operation(self, name, attrs, args, typ, input_type=None):
        if self.core_model is None:
            return self._reference_scalar_operation(name, attrs, args, typ, input_type)
        if name == "int.cast":
            name += "." + attrs["mode"]
        literal = int(attrs["value"]) & ((1 << 64) - 1) if name == "const" else 0
        return self.core_model.symbolic_core(
            self.z, self.ctx, name, self.widths[typ], args, literal,
            signed_result=typ.startswith("i"), signed_input=(input_type or typ).startswith("i"),
        )

    def _reference_scalar_operation(self, name, attrs, args, typ, input_type=None):
        input_type = input_type or typ
        z = self.z
        trap = None
        if name == "const":
            value = self.bv(int(attrs["value"]))
        elif name.startswith("int.add.") or name.startswith("int.sub."):
            a, b = args
            value = self.normalized(a + b if name.startswith("int.add.") else a - b, typ)
            if name.endswith("checked"):
                if typ.startswith("i"):
                    # One extra bit represents every exact signed sum
                    # or difference. Compare against the independently
                    # normalized result, including narrow-type overflow.
                    full = (z.SignExt(1, a) + z.SignExt(1, b) if name.startswith("int.add.")
                            else z.SignExt(1, a) - z.SignExt(1, b))
                    trap = full != z.SignExt(1, value)
                else:
                    trap = z.ULT(value, a) if name.startswith("int.add.") else z.ULT(a, b)
        elif name == "int.mul.wrap":
            value = self.normalized(args[0] * args[1], typ)
        elif name == "int.mul.checked":
            # Check the exact mathematical product before narrowing;
            # the low 64 bits alone cannot detect a 64-bit overflow.
            extension = z.SignExt if typ.startswith("i") else z.ZeroExt
            full = extension(64, args[0]) * extension(64, args[1])
            value = self.normalized(z.Extract(63, 0, full), typ)
            trap = (full != z.SignExt(64, value) if typ.startswith("i")
                    else z.Extract(127, self.widths[typ], full) != 0)
        elif name in ("int.div.checked", "int.rem.checked"):
            if typ.startswith("i"):
                # Signed division truncates toward zero; SRem retains
                # the dividend's sign. Core traps MIN/-1 for both
                # operations, even when the mathematical remainder is 0.
                value = (args[0] / args[1] if name == "int.div.checked"
                         else z.SRem(args[0], args[1]))
                minimum = self.bv(-(1 << (self.widths[typ] - 1)))
                trap = z.Or(args[1] == 0, z.And(args[0] == minimum, args[1] == self.bv(-1)))
            else:
                value = (z.UDiv(args[0], args[1]) if name == "int.div.checked"
                         else z.URem(args[0], args[1]))
                trap = args[1] == 0
        elif name == "int.neg.checked":
            value = self.normalized(-args[0], typ)
            trap = (args[0] == self.bv(-(1 << (self.widths[typ] - 1)))
                    if typ.startswith("i") else args[0] != 0)
        elif name in ("int.shl.checked", "int.shr.checked"):
            left, count = args
            # Core checks the normalized complete count before the
            # ISA applies CL masking. Left shift truncates its result;
            # discarded value bits are not an arithmetic overflow.
            trap = z.UGE(count, self.bv(self.widths[typ]))
            value = self.normalized(left << count if name == "int.shl.checked"
                                    else left >> count if typ.startswith("i")
                                    else z.LShR(left, count), typ)
        elif name in ("bit.and", "bool.and", "bit.or", "bool.or", "bit.xor"):
            a, b = args
            value = a & b if name.endswith("and") else a | b if name.endswith("or") and name != "bit.xor" else a ^ b
        elif name in ("bit.not", "bool.not"):
            value = self.normalized(~args[0], typ)
        elif name == "int.cast":
            value = self.normalized(args[0], typ)
            if attrs["mode"] == "checked":
                source_type = input_type
                if source_type.startswith("i") or typ.startswith("i"):
                    # A signed 65-bit domain contains every source
                    # integer, including U64_MAX, without reinterpretation.
                    exact = (z.SignExt(1, args[0]) if source_type.startswith("i")
                             else z.ZeroExt(1, args[0]))
                    width = self.widths[typ]
                    low = -(1 << (width - 1)) if typ.startswith("i") else 0
                    high = (1 << (width - 1)) - 1 if typ.startswith("i") else (1 << width) - 1
                    trap = z.Or(exact < z.BitVecVal(low, 65, ctx=self.ctx),
                                exact > z.BitVecVal(high, 65, ctx=self.ctx))
                else:
                    trap = z.UGT(args[0], self.bv((1 << self.widths[typ]) - 1))
        elif name.startswith("compare."):
            a, b = args
            signed = input_type.startswith("i")
            relation = {"eq": lambda: a == b, "ne": lambda: a != b,
                        "lt": lambda: a < b if signed else z.ULT(a, b),
                        "le": lambda: a <= b if signed else z.ULE(a, b),
                        "gt": lambda: a > b if signed else z.UGT(a, b),
                        "ge": lambda: a >= b if signed else z.UGE(a, b)}[name.split(".")[1]]()
            value = z.If(relation, self.bv(1), self.bv(0))
        elif name == "select":
            value = z.If(args[0] != 0, args[1], args[2])
        else:
            raise SafeCoreRejected("missing independent Core semantics")
        return value, trap

    def borrow_guards(self, extent):
        if self.core_model is None:
            return self._reference_borrow_guards(extent)
        pointer, length, _ = self.loan
        return tuple(self.core_model.symbolic_core(self.z, self.ctx, name, 64, (pointer, length), literal)
                     for name, literal in (("borrow.extent", extent), ("borrow.null", 0), ("borrow.wrap", 0)))

    def _reference_borrow_guards(self, extent):
        z = self.z
        pointer, length, _ = self.loan
        return ((self.bv(1 << 32), z.UGT(length, extent)),
                (self.bv(2 << 32), z.And(length != 0, pointer == 0)),
                (self.bv(3 << 32), z.And(length != 0, z.ULT(pointer + length, pointer))))

    def buffer_address(self, pointer, length, index):
        if self.core_model is None:
            return self._reference_buffer_address(pointer, length, index)
        return self.core_model.symbolic_core(self.z, self.ctx, "buffer.address", 64, (pointer, length, index))

    def _reference_buffer_address(self, pointer, length, index):
        return pointer + index, self.z.UGE(index, length)

    def reference(self, fn, blocks, extent):
        z = self.z
        outcomes, path = [], z.BoolVal(True, ctx=self.ctx)

        def outcome(kind, path, memory, value=None):
            outcomes.append(dict(kind=kind, path=z.simplify(path), memory=memory,
                                 value=self.bv(0) if value is None else value))

        if self.loan is not None:
            for packed, bad in self.borrow_guards(extent):
                outcome("return", z.And(path, bad), self.memory, packed)
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
                if name == "buffer.len":
                    value = args[0][1]
                elif name in ("buffer.load", "buffer.store"):
                    pointer, length, permission = args[0]
                    index = args[1]
                    address, trap = self.buffer_address(pointer, length, index)
                    outcome("abort", z.And(path, trap), memory)
                    path = z.simplify(z.And(path, z.Not(trap)))
                    trap = None
                    if name == "buffer.load":
                        value = z.ZeroExt(56, z.Select(memory, address))
                    else:
                        require(permission == "mutbuf", "reference cannot write a read-only loan")
                        memory = z.Store(memory, address, z.Extract(7, 0, args[2]))
                else:
                    input_type = types[operation["args"][0]] if args else None
                    value, trap = self.scalar_operation(name, attrs, args, typ, input_type)
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


def _reference_artifact_assumptions(theory, stack, extent):
    z = theory.z
    assumptions = [z.UGE(stack, 16384), z.ULE(stack, (1 << 64) - 16),
                   stack & theory.bv(15) == 8]
    if theory.loan is not None:
        pointer, length, _ = theory.loan
        admitted = z.And(z.ULE(length, extent),
                         z.Or(length == 0, z.And(pointer != 0, z.UGE(pointer + length, pointer))))
        disjoint = z.Or(length == 0, z.ULE(pointer + length, stack - 16384), z.UGE(pointer, stack + 8))
        assumptions.append(z.Implies(admitted, disjoint))
    return assumptions


def _reference_artifact_errors(z, core, machine):
    rc, ra, rv, rm = core
    mc, ma, mv, mm = machine
    return (z.Or(z.Not(rc), z.Not(mc)),
            z.Or(ra != ma, z.And(z.Not(ra), rv != mv), rm != mm))


def _artifact_report(checked, fn, binding, profile, foreign_exports, identity, solver,
                     assumptions, counts, reports, started, status, *, complete):
    subject = {"core_sha256": checked.sha256, "input_sha256": checked.input_sha256,
               "object_sha256": binding["binding"]["object_sha256"],
               "final_image_sha256": binding["binding"]["final_image_sha256"],
               "entry_symbol": fn["name"], "foreign_buffer_exports": [list(pair) for pair in foreign_exports]}
    checker = {"name": "hepta.hia_safe_core.validate_safe_core_artifact",
               "source_identity": identity, "solver": solver, "producer_reemission_used": False}
    return {"schema": SCHEMA, "profile": profile, "ok": status == "smt_validated",
            "status": status, "complete": complete, "artifact_input_profile": profile,
            "validation_mode": "independent_supplied_bytes", "subject": subject,
            "property": ARTIFACT_PROPERTY, "checker": checker,
            "unproved_obligations": [dict(row) for row in UNPROVED_OBLIGATIONS],
            "core_sha256": checked.sha256, "input_sha256": checked.input_sha256,
            "core_schema": checked.as_dict()["schema"], "backend_implementation_sha256": None,
            "source_identity": identity, "solver": solver, "image_binding": binding["binding"],
            "function": fn["name"], "foreign_buffer_exports": subject["foreign_buffer_exports"],
            "model_counts": counts, "obligations": list(reports),
            "claims": dict(CLAIMS) if complete else {}, "assumptions": list(assumptions),
            "limits": dict(LIMITS), "elapsed_seconds": time.monotonic() - started}


MACHINE_CIRCUIT_SOLVER_VERSION = "machine-word-circuit-cnf.v1"
MACHINE_CIRCUIT_ASSUMPTIONS = [
    *ASSUMPTIONS[:3],
    "The loaded Core verifier, ELF binding, HIA machine word projection and native HIA CNF solver are trusted; the model is not a kernel proof of x86 semantics.",
    *ASSUMPTIONS[4:],
]


def _machine_circuit_solver(pair):
    from .hia_optimization import _native_solver_identity

    decoder, cnf = pair
    if decoder is None or cnf is None:
        return None
    return dict(_native_solver_identity(cnf), version=MACHINE_CIRCUIT_SOLVER_VERSION)


def _scalar_caller_contract():
    # The bounded machine model is parametric in an aligned, nonwrapping
    # stack. Check that those same three ABI assumptions have a model.
    nodes = [(1, 64, 0, 0, 0), (2, 64, 0, 0, 16384), (2, 64, 0, 0, (1 << 64) - 16),
             (2, 64, 0, 0, 15), (2, 64, 0, 0, 8),
             (15, 1, 0, 1, 0), (13, 1, 0, 2, 0), (3, 64, 0, 3, 0), (7, 1, 7, 4, 0),
             (3, 1, 5, 6, 0), (3, 1, 9, 8, 0), (2, 1, 0, 0, 0)]
    return nodes, [(10, 11)], None


def _try_native_scalar_artifact(checked, fn, blocks, binding, profile, profile_version,
                                pair, identity, started, deadline, query_directory):
    from .hia_cnf_native import SAT
    from .hia_optimization import _native_circuit_decision

    decoder, cnf = pair
    if len(blocks) != 1:
        return None
    machine = decoder.project_scalar_values(
        binding, len(fn["params"]), allow_variable_shifts=profile_version >= 3,
        allow_unsigned_multiply=profile_version >= 4, allow_unsigned_divide=profile_version >= 5,
        allow_signed=profile_version >= 6)
    if machine is None:
        return None
    # The reference evaluates the separately verified Core input, never the
    # producer's lowering or a second copy of the supplied machine circuit.
    graph = (blocks, tuple(blocks))
    core = cnf.project_scalar_graphs((fn, fn), (graph, graph), totality=False)
    if core is None:
        return None
    circuits = cnf.bind_artifact_circuits(machine, core, len(fn["params"]),
                                         signed_return=fn["returns"][0].startswith("i"))
    if circuits is None:
        return None
    solver = _machine_circuit_solver(pair)
    counts = dict(machine[2], core_terminal_paths=1)
    reports = []
    queries = []
    counterexample = None
    # A successful projection structurally excludes memory and ABI faults
    # for every admitted stack and word. Their reduced violation is false.
    no_violation = ((), (), None)
    queries_to_solve = (_scalar_caller_contract(), no_violation, no_violation, *circuits)
    for index, ((name, expected), circuit) in enumerate(zip(ARTIFACT_OBLIGATIONS, queries_to_solve, strict=True)):
        before = time.monotonic()
        decision = _native_circuit_decision(cnf, circuit, deadline)
        if decision is None:
            return None
        verdict, model, discharge, frame = decision
        result = "sat" if verdict == SAT else "unsat"
        discharge["method"] = "native_hia_circuit_cnf"
        if index in (1, 2):
            discharge["structural_reduction"] = "native_hia_bounded_machine_projection"
        if result != expected:
            if index < 3:
                raise SafeCoreRejected("inconsistent native scalar caller or machine bound")
            # The HIA solver has independently evaluated these ABI words
            # against the original, un-bit-blasted circuit.
            words = [(model >> (1 + 64 * word)) & ((1 << 64) - 1)
                     for word in range(len(fn["params"]))]
            counterexample = {"abi_words": words, "initial_rsp": 0x10008, "obligation": name}
        query = decoder.format_proof_query(frame)
        reports.append({"name": name, "result": result, "expected": expected,
                        "query_sha256": sha256(query).hexdigest(),
                        "elapsed_seconds": time.monotonic() - before, "native_cnf": discharge})
        queries.append(query)
        if counterexample is not None:
            break

    packaged = getattr(cnf, '_default_package_binding', None)
    if packaged is not None:
        packaged.check_files()
    else:
        pair = _selected_machine_proof()
    require(identity == _checker_source_identity(pair), "checker or solver source changed during validation")
    require(time.monotonic_ns() < deadline, "validation deadline expired; no completed proof")
    if query_directory is not None:
        retained = Path(query_directory).absolute()
        retained.mkdir(parents=False, exist_ok=False)
        for index, (row, query) in enumerate(zip(reports, queries, strict=True)):
            filename = f"{index:02d}-{row['name']}.smt2"
            with (retained / filename).open("xb") as stream:
                stream.write(query)
            row["query_file"] = filename
            (retained / (filename + ".result.json")).write_text(json.dumps(row, indent=2) + "\n")
        require(time.monotonic_ns() < deadline, "validation deadline expired; no completed proof")
    status = "smt_validated" if counterexample is None else "refuted"
    validation = _artifact_report(checked, fn, binding, profile, (), identity, solver,
                                  MACHINE_CIRCUIT_ASSUMPTIONS, counts, reports, started / 1_000_000_000,
                                  status, complete=counterexample is None)
    if counterexample is not None:
        raise SafeCoreRejected(counterexample["obligation"] + ": sat", counterexample=counterexample,
                               validation=validation)
    return validation


@bind_input_execution
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
    pair = _selected_machine_proof(observe=True)
    decoder, cnf = pair
    identity = _checker_source_identity(pair)
    binding = bind_final_artifact(object_bytes, final_bytes, fn["name"])
    if decoder is not None and cnf is not None and not foreign_buffer_exports:
        started = time.monotonic_ns()
        deadline = started + timeout_ms * 1_000_000
        native = _try_native_scalar_artifact(checked, fn, blocks, binding, artifact_profile,
                                             profile_version, pair, identity, started, deadline, query_directory)
        if native is not None:
            return native
        timeout_ms = (deadline - time.monotonic_ns()) // 1_000_000
        require(timeout_ms > 0, "validation deadline expired; no completed proof")
    try:
        z = importlib.import_module("z3")
    except ImportError as exc:
        raise SafeCoreRejected("pinned z3-solver is unavailable; no proof result") from exc
    solver_identity = _solver_identity(z)
    retained = None
    if query_directory is not None:
        retained = Path(query_directory).absolute()
        retained.mkdir(parents=False, exist_ok=False)
    t = _Theory(z, timeout_ms, widths=widths, core_model=decoder)
    t.arguments(fn)
    extent = None if not foreign_buffer_exports else foreign_buffer_exports[0][1]
    reference = t.reference(fn, blocks, extent)
    machine = Executor(t, binding, t.words, t.loan,
                       allow_variable_shifts=profile_version >= 3,
                       allow_unsigned_multiply=profile_version >= 4,
                       allow_unsigned_divide=profile_version >= 5,
                       allow_signed=profile_version >= 6, native_model=decoder)
    observed = machine.run()
    # The abstract stack is keyed by exact offsets.  Foreign data is a separate
    # array only under this explicit disjointness premise; numeric ABI guards
    # are still modelled and proved for every invalid pointer/length word pair.
    predicates = machine.native_model
    if predicates is None:
        assumptions = _reference_artifact_assumptions(t, machine.sp, extent)
    else:
        assumptions = [predicates.artifact_predicate(z, t.ctx, rule, machine.sp) for rule in
                       ('caller_stack_floor', 'caller_stack_ceiling', 'caller_stack_alignment')]
        if t.loan is not None:
            pointer, length, _ = t.loan
            assumptions.append(predicates.artifact_predicate(
                z, t.ctx, 'caller_loan_disjoint', machine.sp, pointer, length, t.bv(extent)))
    rc, ra, rv, rm = t.merge(reference)
    mc, ma, mv, mm = t.merge(observed)
    if predicates is None:
        bad_coverage, different_behavior = _reference_artifact_errors(z, (rc, ra, rv, rm), (mc, ma, mv, mm))
    else:
        bad_coverage = predicates.artifact_predicate(z, t.ctx, 'terminal_coverage_error', rc, mc)
        memory_difference = predicates.artifact_predicate(z, t.ctx, 'caller_memory_difference', rm, mm)
        different_behavior = predicates.artifact_predicate(
            z, t.ctx, 'observable_refinement_error', ra, ma, rv, mv, memory_difference)
    false = z.BoolVal(False, ctx=t.ctx)
    obligations = [
        ("caller_contract_nonvacuous", z.BoolVal(True, ctx=t.ctx), "sat"),
        ("machine_memory_access_bounds", z.Or(*machine.faults, false), "unsat"),
        ("sysv_stack_alignment_and_preservation", z.Or(*machine.abi_faults, false), "unsat"),
        ("all_inputs_reach_a_terminal_model_outcome", bad_coverage, "unsat"),
        ("core_to_final_image_return_abort_and_caller_bytes", different_behavior, "unsat"),
    ]
    require(tuple((name, expected) for name, _, expected in obligations) == ARTIFACT_OBLIGATIONS,
            "the declared and executed obligation inventories differ")
    reports = []

    def report(status, *, complete):
        counts = {"decoded_instructions": len(machine.code), "symbolic_machine_steps": machine.steps,
                  "machine_terminal_paths": len(observed), "core_terminal_paths": len(reference),
                  "maximum_observed_stack_bytes": -machine.minimum_stack_offset}
        return _artifact_report(checked, fn, binding, artifact_profile, foreign_buffer_exports,
                                identity, solver_identity, ASSUMPTIONS, counts, reports, t.started,
                                status, complete=complete)

    def check_deadline():
        try:
            t.check_time()
        except SafeCoreRejected as exc:
            raise SafeCoreRejected("validation deadline expired; no completed proof",
                                   validation=report("unknown", complete=False)) from exc

    for index, (name, violation, expected) in enumerate(obligations):
        check_deadline()
        solver = z.Solver(ctx=t.ctx)
        solver.add(*assumptions, violation)
        query_bytes = (solver.sexpr() + "\n(check-sat)\n").encode()
        require(len(query_bytes) <= 16 * 1024 * 1024, "SMT query byte budget exceeded")
        query_hash = sha256(query_bytes).hexdigest()
        filename = f"{index:02d}-{name}.smt2"
        if retained is not None:
            with (retained / filename).open("xb") as stream:
                stream.write(query_bytes)
        started = time.monotonic()
        memory = (_FiniteCallerMemory(z, machine.native_model, t.memory, t.deadline)
                  if t.loan is not None and machine.native_model is not None and cnf is not None else None)
        native = None
        if name == "machine_memory_access_bounds":
            native = _native_memory_faults(z, cnf, assumptions, machine.faults, t.deadline, memory)
        if native is None:
            native = _native_obligation(z, cnf, z.And(*assumptions, violation), t.deadline, memory=memory)
        if native is None:
            check_deadline()
            solver.set(timeout=max(1, int((t.deadline - time.monotonic()) * 1000)))
            result = str(solver.check())
            witness = None
        else:
            result, witness, receipt = native
        reports.append({"name": name, "result": result, "expected": expected,
                        "query_sha256": query_hash, "elapsed_seconds": time.monotonic() - started})
        if native is not None:
            reports[-1]["native_cnf"] = receipt
        if retained is not None:
            reports[-1]["query_file"] = filename
            (retained / (filename + ".result.json")).write_text(json.dumps(reports[-1], indent=2) + "\n")
        check_deadline()
        if result != expected:
            counterexample = None
            if result == "sat":
                model = solver.model() if native is None else witness
                counterexample = {"abi_words": [model.eval(v, model_completion=True).as_long() for v in t.words],
                                  "initial_rsp": model.eval(machine.sp, model_completion=True).as_long(),
                                  "obligation": name}
            raise SafeCoreRejected(name + ": " + result + (" (" + solver.reason_unknown() + ")" if result == "unknown" else ""),
                                   counterexample=counterexample,
                                   validation=report("refuted" if counterexample is not None else "unknown", complete=False))
    packaged_proof = getattr(cnf, '_default_package_binding', None)
    if packaged_proof is not None:
        packaged_proof.check_files()
    else:
        pair = _selected_machine_proof()
    require(identity == _checker_source_identity(pair)
            and solver_identity == _solver_identity(z),
            "checker or solver source changed during validation")
    check_deadline()
    return report("smt_validated", complete=True)


def build_safe_core(document, output, *, foreign_extent=None, linker="ld", timeout_ms=15000,
                    query_directory=None, profile_version=1):
    """Build privately, validate final bytes, then atomically publish those bytes."""
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    from .hia_program_native import emit_program_machine, compile_program_machine
    source_identity = _source_identity()
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
        from .hia_elf_verified_linker_native import selected_verified_linker, verified_linker_matches
        selected = selected_verified_linker(package_default=linker == "ld")
        linker_identity = None if selected is None else selected.identity()
        compilation = compile_program_machine(image, program=checked, output=candidate, linker=linker,
                                               verified_shared=True)
        try:
            data = read_bounded_elf_image(candidate)
        except VerifiedImageRejected as exc:
            raise SafeCoreRejected(str(exc)) from exc
        require(source_identity == _source_identity(), "producer source changed before final-image validation")
        report = validate_safe_core_image(checked, image, data, timeout_ms=timeout_ms,
                                          query_directory=query_directory, profile_version=profile_version)
        require(report.get("ok") is True and report.get("complete") is True,
                "final-image validation did not complete")
        require(report["source_identity"] == source_identity == _source_identity(),
                "producer or checker changed before final publication")
        require(report["checker"]["source_identity"] == _checker_source_identity(),
                "checker changed before final publication")
        if linker_identity is not None:
            require(verified_linker_matches(linker_identity) and
                    compilation["toolchain"] == selected.toolchain(linker_identity),
                    "verified HIA linker changed before final publication")
        published = publish_verified(candidate, destination, data)
        try:
            verify_published(candidate, destination, data)
            require(report["source_identity"] == _source_identity()
                    and report["checker"]["source_identity"] == _checker_source_identity(),
                    "checker changed during final publication")
            if linker_identity is not None:
                require(verified_linker_matches(linker_identity), "verified HIA linker changed during publication")
        except BaseException:
            withdraw_own_link(candidate, destination)
            raise
    return {"schema": "hepta.hia.safe-core-build.v1", "ok": True, "output": str(destination),
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "compilation": compilation, "validation": report,
            "status": "smt_validated_not_executed", "claims": dict(CLAIMS)}

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
