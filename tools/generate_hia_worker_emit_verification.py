"""Author the retained verification receipt boundary used by the Emit Worker."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_machine_plan import LAYOUT_V1, MACHINE_V2, MACHINE_V3, MACHINE_V4, preservation_checks
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_build_custody import POLICY as BUILD_CUSTODY
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_proof_scope import METHODS
from tools.hia_retained_proof_method import FINITE_OBSERVATION

SOURCE = Path('examples/hia_bootstrap/worker_emit_verification.hepta')
NAMES = ('installation', 'context', 'candidate', 'validation_profile', 'candidate_core_sha256',
         'base_program', 'base_core_sha256', 'subject', 'checks', 'claim', 'status',
         'assumptions_artifact', 'evidence_artifact', 'schema', 'method', 'plan',
         'core_sha256', 'canonical_object_sha256', 'planned_object_sha256',
         'canonical_frame_bytes', 'planned_frame_bytes', 'same_slots', 'same_frame_sizes',
         'implicit_optimizer_used', 'choice_checks', 'choice', 'checked', 'rule', 'proof_binding',
         'kind', 'backend_profile', 'plan_profile', 'sha256', 'lowering_profile',
         'native_artifact', 'build_receipt', 'value_registers', 'witness', 'functions', 'trap_rule')
CLAIMS = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')
MACHINE_CHECKS = preservation_checks({'schema': MACHINE_V2})
SELECT_CHECKS = (
    ('value_registers', 'noninterfering scalar lifetimes; staged edge copies; all used callee-saved registers saved/restored'),
    ('scalar_select', 'explicit branch or register-only CMOV; all operands already defined scalars; MOV loads preserve TEST flags'),
)
LIFETIME_RULE = 'closed-block inclusive lifetimes; all edge sources staged before target writes'
LEAF_CHECK = ('caller_clobbered_leaf_values',
              'r8/r9 only; exact leaf opcode inventory; no returning call; no implicit r8/r9 scratch; scalar values; inclusive lifetimes; staged entry/edge copies')
LEAF_TRAP_RULE = 'all trap paths call abort then UD2 and have no returning continuation'

POLICY = r'''
# Identity input: canonical [installation, context, candidate or null,
# validation profile, retained receipt]. Canonicalization never changes the
# hash of the raw Store file. Returned spans refer to this sealed comparison
# frame; the caller must still recheck Core, subject, assumptions and evidence.
def emit_verification(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 5 or length(s) > 8388608 or length(o) < 256 or length(w) < 65536:
        return INVALID
    if length(s) >= 24:
        mode = input_word(s, 0)
        if mode == SCOPE_INPUT and length(s) == 72:
            return scope_effect(s, o)
        if mode == SCOPE_COMPLETE:
            return scope_complete(s, o)
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    count = get(w, 96)
    if count != 1 and count != 2 and count != 3 and count != 4 and count != 5 and count != 6 and count != 8 and count != 9:
        return INVALID
    first = 64 + get(w, 88) * 72
    if count == 1:
        if lookup(w, first, K_choice_checks) != NONE:
            return project_layout_witness(w, o, first)
        return verification_files(s, w, o, first)
    if count == 8 or count == 9:
        return layout_evidence(s, w, o, first, count == 9)
    second = next(w, first)
    explicit_plan = count == 5 and is_object(w, first) and plan_subject_kind(w, lookup(w, first, K_kind))
    if count == 2 or count == 4 or explicit_plan:
        observed = NONE
        canonical = NONE
        active_plan = NONE
        if count != 2:
            observed = next(w, second)
            canonical = next(w, observed)
            if explicit_plan:
                active_plan = next(w, canonical)
        return qualified_plan(w, o, s, first, second, observed, canonical, active_plan)
    if count == 3:
        return layout_subject(s, w, o, first, second, next(w, second))
    candidate = next(w, second)
    profile = next(w, candidate)
    receipt = next(w, profile)
    if is_object(w, first) == False or is_object(w, second) == False or is_object(w, receipt) == False:
        return INVALID
    if (get(w, candidate) != 0 and is_object(w, candidate) == False) or is_object(w, profile) == False:
        return INVALID
    result = bind_receipt(s, w, o, first, second, candidate, profile, receipt)
    if count == 5 or result != 112:
        return result
    return receipt_subject(s, w, o, receipt, next(w, receipt))

# [installation, Context, candidate or null, validation, receipt,
#  [installed backend, canonical lowering, machine plan]]. These are
#  subject read capabilities, not a finding about any retained proof.
def receipt_subject(s:readbuf, w:mutbuf, o:mutbuf, receipt:u64, profiles:u64) -> u64:
    if get(w, profiles) != 5 or get(w, profiles + 32) != 3:
        return INVALID
    backend = 64 + get(w, profiles + 24) * 72
    lowering = next(w, backend)
    plan_profile = next(w, lowering)
    subject = lookup(w, receipt, K_subject)
    if is_object(w, subject) == False:
        return refusal(o, 3)
    kind = lookup(w, subject, K_kind)
    fields = get(w, subject + 32)
    if fields == 1 and core_subject_kind(w, kind):
        put(o, 112, 1)
        return 120
    if matches_field(s, w, subject, K_backend_profile, backend) == False:
        return refusal(o, 3)
    if fields == 3 and canonical_subject_kind(w, kind) and matches_field(s, w, subject, K_lowering_profile, lowering):
        put(o, 112, 2)
        return 120
    if fields == 4 and plan_subject_kind(w, kind) and matches_field(s, w, subject, K_plan_profile, plan_profile):
        plan = lookup(w, subject, K_plan)
        if length(o) < 296 or exact_reference(s, w, plan) == False:
            return refusal(o, 3)
        put(o, 112, 3)
        copy_reference(s, o, get(w, plan + 56), 120)
        return 296
    if fields == 4 and native_subject_kind(w, kind):
        artifact = lookup(w, subject, K_native_artifact)
        build = lookup(w, subject, K_build_receipt)
        if length(o) < 472 or exact_reference(s, w, artifact) == False or exact_reference(s, w, build) == False:
            return refusal(o, 3)
        put(o, 112, 4)
        copy_reference(s, o, get(w, artifact + 56), 120)
        copy_reference(s, o, get(w, build + 56), 296)
        return 472
    return refusal(o, 3)

# An authorized scope result must agree with the typed physical receipt's
# projected claim. Its result names an effect; it does not discharge it.
# Effect 1 is already checked locally; 2 is exact layout rederivation;
# 3 reopens native build custody; 4–6 are the independent proof checkers.
def scope_effect(s:readbuf, o:mutbuf) -> u64:
    kind = input_word(s, 8)
    claim = input_word(s, 16)
    if kind < 1 or kind > 4 or input_word(s, 24) != SCOPE_RESULT or input_word(s, 32) != 0:
        return refusal(o, 4)
    method = input_word(s, 40)
    status = input_word(s, 56)
    effect = input_word(s, 64)
    if method < 1 or method > METHOD_COUNT or claim != input_word(s, 48) or claim < 1 or claim > 4 or status < 1 or status > 4:
        return refusal(o, 4)
    operation = 1
    if effect != 0:
        if effect > 3:
            return refusal(o, 4)
        if effect == 3 and (method != FINITE_METHOD or claim != 2 or status != 2):
            return refusal(o, 4)
        operation = effect + 3
    elif method == LAYOUT_METHOD:
        if kind != 3 or claim != 3 or status != 1:
            return refusal(o, 4)
        operation = 2
    elif method == ENCODING_METHOD:
        if kind != 4 or claim != 4:
            return refusal(o, 4)
        operation = 3
    put(o, 0, SCOPE_EFFECT)
    put(o, 8, 0)
    put(o, 16, operation)
    return 24

# Complete only after each selected HIA effect actually returned its
# expected typed disposition. A scope signal alone is not an effect.
def scope_complete(s:readbuf, o:mutbuf) -> u64:
    planned = input_word(s, 8)
    count = input_word(s, 16)
    if planned > 1 or count < 1 or count > 4 or length(s) != 24 + 48 * count:
        return INVALID
    at = 24
    while at < length(s):
        if input_word(s, at) != SCOPE_EFFECT or input_word(s, at + 8) != 0:
            return refusal(o, 4)
        operation = input_word(s, at + 16)
        tag = input_word(s, at + 24)
        if input_word(s, at + 32) != 0:
            return refusal(o, 4)
        outcome = input_word(s, at + 40)
        if operation == 1 and (tag != 0 or outcome != 0):
            return refusal(o, 4)
        if operation == 2 and (tag != RESULT or outcome != 0):
            return refusal(o, 4)
        if operation == 3 and (tag != BUILD_EFFECT or outcome < 1 or outcome > 2):
            return refusal(o, 4)
        if operation == 6 and (tag != FINITE_OBSERVATION or outcome != 2):
            return refusal(o, 4)
        if operation < 1 or operation == 4 or operation == 5 or operation > 6:
            return refusal(o, 4)
        at = at + 48
    if planned == 1:
        put(o, 0, PLAN_COMPLETE)
        put(o, 8, count)
        return 16
    return refusal(o, 0)

# Read-only plan issued after the caller has bound a real receipt to its
# Context, candidate and validation profile. Zero, missing or repeated
# claim slots cannot omit the proof files that the later scope check needs.
def verification_files(s:readbuf, w:mutbuf, o:mutbuf, receipt:u64) -> u64:
    if is_object(w, receipt) == False:
        return INVALID
    checks = lookup(w, receipt, K_checks)
    if checks == NONE or get(w, checks) != 5:
        return INVALID
    count = get(w, checks + 32)
    if count < 1 or count > 4 or length(o) < 16 + 360 * count:
        return INVALID
    node = 64 + get(w, checks + 24) * 72
    cursor = 16
    previous = 0
    index = 0
    while index < count:
        if is_object(w, node) == False:
            return INVALID
        claim = claim_kind(w, lookup(w, node, K_claim))
        if claim == 0 or previous & (1 << claim) != 0:
            return INVALID
        previous = previous | (1 << claim)
        assumptions = lookup(w, node, K_assumptions_artifact)
        evidence = lookup(w, node, K_evidence_artifact)
        if exact_reference(s, w, assumptions) == False or exact_reference(s, w, evidence) == False:
            return INVALID
        put(o, cursor, claim)
        copy_reference(s, o, get(w, assumptions + 56), cursor + 8)
        copy_reference(s, o, get(w, evidence + 56), cursor + 184)
        cursor = cursor + 360
        node = next(w, node)
        index = index + 1
    put(o, 0, FILES)
    put(o, 8, count)
    return cursor

# Project a physical retained witness without decoding it in the platform relay.
# The typed lifetime owner must independently check the returned immutable span.
def project_layout_witness(w:mutbuf, o:mutbuf, evidence:u64) -> u64:
    checks = lookup(w, evidence, K_choice_checks)
    if get(w, checks) != 5 or get(w, checks + 32) < SELECT_CHECK_COUNT:
        return INVALID
    row = 64 + get(w, checks + 24) * 72
    index = 0
    while index < MACHINE_CHECK_COUNT:
        row = next(w, row)
        index = index + 1
    witness = lookup(w, row, K_witness)
    if is_object(w, witness) == False:
        return INVALID
    put(o, 0, WITNESS_SPAN)
    put(o, 8, 0)
    span(w, o, witness, 16)
    return 32

# [verified Core digest, physically retained plan, plan digest, actual canonical and
#  planned object digests, independently extracted frame maps, proof evidence].
# The optional ninth frame is the exact immutable witness document already
# checked against Core by the pinned register lifetime owner. It must still
# match the particular evidence row below. This never claims general refinement.
def layout_evidence(s:readbuf, w:mutbuf, o:mutbuf, core:u64, registers_checked:bool) -> u64:
    plan = next(w, core)
    plan_digest = next(w, plan)
    canonical = next(w, plan_digest)
    planned = next(w, canonical)
    canonical_frames = next(w, planned)
    planned_frames = next(w, canonical_frames)
    evidence = next(w, planned_frames)
    if digest_text(w, core, False) == False or digest_text(w, plan_digest, False) == False:
        return INVALID
    if digest_text(w, canonical, False) == False or digest_text(w, planned, False) == False:
        return INVALID
    if is_object(w, plan) == False or is_object(w, canonical_frames) == False or is_object(w, planned_frames) == False or is_object(w, evidence) == False:
        return INVALID
    if matches_field(s, w, plan, K_core_sha256, core) == False or matches_field(s, w, evidence, K_core_sha256, core) == False:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_plan, plan) == False or get(w, evidence + 32) != 12:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_canonical_object_sha256, canonical) == False or matches_field(s, w, evidence, K_planned_object_sha256, planned) == False:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_canonical_frame_bytes, canonical_frames) == False or matches_field(s, w, evidence, K_planned_frame_bytes, planned_frames) == False:
        return refusal(o, 4)
    if proof_names_plan(s, w, evidence, plan_digest) == False:
        return refusal(o, 4)
    return layout_choices(s, w, o, plan, evidence, registers_checked,
                          equal_span(s, w, canonical_frames, planned_frames))

def layout_choices(s:readbuf, w:mutbuf, o:mutbuf, plan:u64, evidence:u64, registers_checked:bool, same_frames:bool) -> u64:
    schema = lookup(w, plan, K_schema)
    leaf = leaf_schema(w, schema)
    select = leaf or select_schema(w, schema)
    machine = select or machine_schema(w, schema)
    if (machine == False and layout_schema(w, schema) == False) or layout_method(w, lookup(w, evidence, K_method)) == False:
        return refusal(o, 4)
    witnessed = NONE
    if registers_checked:
        witnessed = next(w, evidence)
        if select == False or is_object(w, witnessed) == False:
            return refusal(o, 4)
    elif leaf or (select and empty_object(w, lookup(w, plan, K_value_registers)) == False):
        return refusal(o, 4)
    same_slots = True
    if registers_checked:
        same_slots = spill_only(w, lookup(w, plan, K_value_registers))
    elif same_frames == False:
        return refusal(o, 4)
    if tag_is(w, lookup(w, evidence, K_same_slots), choose(same_slots, 2, 1)) == False:
        return refusal(o, 4)
    if tag_is(w, lookup(w, evidence, K_same_frame_sizes), choose(same_frames, 2, 1)) == False:
        return refusal(o, 4)
    if tag_is(w, lookup(w, evidence, K_implicit_optimizer_used), 1) == False:
        return refusal(o, 4)
    checks = lookup(w, evidence, K_choice_checks)
    count = choose(select, SELECT_CHECK_COUNT + choose(leaf, 1, 0), choose(machine, MACHINE_CHECK_COUNT, 1))
    if checks == NONE or get(w, checks) != 5 or get(w, checks + 32) != count:
        return refusal(o, 4)
    choice = 64 + get(w, checks + 24) * 72
    index = 0
    while index < count:
        if checked_choice(s, w, choice, index, witnessed) == False:
            return refusal(o, 4)
        choice = next(w, choice)
        index = index + 1
    return refusal(o, 0)

def checked_choice(s:readbuf, w:mutbuf, record:u64, index:u64, witnessed:u64) -> bool:
    if is_object(w, record) == False or tag_is(w, lookup(w, record, K_checked), 2) == False:
        return False
    witness_expected = index == MACHINE_CHECK_COUNT
    leaf = index == SELECT_CHECK_COUNT
    if get(w, record + 32) != choose(witness_expected or leaf, 4, 3):
        return False
    if machine_choice(w, lookup(w, record, K_choice), lookup(w, record, K_rule), index) == False:
        return False
    if witness_expected:
        witness = lookup(w, record, K_witness)
        if is_object(w, witness) == False or get(w, witness + 32) != 2:
            return False
        if witnessed != NONE:
            return equal_span(s, w, witness, witnessed)
        return lifetime_rule(w, lookup(w, witness, K_rule)) and empty_object(w, lookup(w, witness, K_functions))
    if leaf:
        return leaf_trap_rule(w, lookup(w, record, K_trap_rule))
    return True

def spill_only(w:mutbuf, mappings:u64) -> bool:
    if is_object(w, mappings) == False:
        return False
    child = get(w, mappings + 24)
    while child != NONE:
        value = 64 + child * 72
        if empty_object(w, value) == False:
            return False
        child = get(w, value + 16)
    return True

def empty_object(w:mutbuf, node:u64) -> bool:
    return is_object(w, node) and get(w, node + 32) == 0

def tag_is(w:mutbuf, node:u64, tag:u64) -> bool:
    return node != NONE and get(w, node) == tag

def proof_names_plan(s:readbuf, w:mutbuf, evidence:u64, digest:u64) -> bool:
    proof = lookup(w, evidence, K_proof_binding)
    if is_object(w, proof) == False:
        return False
    subject = lookup(w, proof, K_subject)
    if is_object(w, subject) == False:
        return False
    ref = lookup(w, subject, K_plan)
    return exact_reference(s, w, ref) and matches_field(s, w, ref, K_sha256, digest)

# Subject lookup is independent of the proof verdict. The two profiles are
# the currently authorized discovery references, never taken from a receipt.
def layout_subject(s:readbuf, w:mutbuf, o:mutbuf, backend:u64, profile:u64, receipt:u64) -> u64:
    if is_object(w, backend) == False or is_object(w, profile) == False or is_object(w, receipt) == False:
        return INVALID
    subject = lookup(w, receipt, K_subject)
    if is_object(w, subject) == False or get(w, subject + 32) != 4:
        return refusal(o, 3)
    if plan_subject_kind(w, lookup(w, subject, K_kind)) == False:
        return refusal(o, 3)
    if matches_field(s, w, subject, K_backend_profile, backend) == False or matches_field(s, w, subject, K_plan_profile, profile) == False:
        return refusal(o, 3)
    ref = lookup(w, subject, K_plan)
    if exact_reference(s, w, ref) == False:
        return refusal(o, 3)
    put(o, 0, SUBJECT)
    put(o, 8, 0)
    copy_reference(s, o, get(w, ref + 56), 16)
    return 192

def bind_receipt(s:readbuf, w:mutbuf, o:mutbuf, installation:u64, context:u64, candidate:u64, profile:u64, receipt:u64) -> u64:
    observed = lookup(w, receipt, K_candidate)
    if is_object(w, observed) == False:
        return INVALID
    if matches_field(s, w, receipt, K_installation, installation) == False or matches_field(s, w, receipt, K_context, context) == False:
        return refusal(o, 1)
    if get(w, candidate) != 0 and equal_span(s, w, candidate, observed) == False:
        return refusal(o, 1)
    if matches_field(s, w, receipt, K_validation_profile, profile) == False:
        return refusal(o, 2)
    put(o, 0, RESULT)
    put(o, 8, 0)
    span(w, o, observed, 16)
    index = K_candidate_core_sha256
    while index <= K_checks:
        field = lookup(w, receipt, index)
        if field == NONE:
            return INVALID
        span(w, o, field, 32 + (index - K_candidate_core_sha256) * 16)
        index = index + 1
    return 112

# Only called after the retained proof chain has been fully rechecked. A proved
# lowering claim names the exact backend, plan profile and plan reference.
def qualified_plan(w:mutbuf, o:mutbuf, s:readbuf, expected:u64, receipt:u64, observed:u64, canonical:u64, active_plan:u64) -> u64:
    if is_object(w, expected) == False or is_object(w, receipt) == False:
        return INVALID
    if matches_field(s, w, receipt, K_subject, expected) == False:
        return refusal(o, 3)
    if get(w, expected + 32) != 4 or plan_subject_kind(w, lookup(w, expected, K_kind)) == False:
        return refusal(o, 3)
    plan = lookup(w, expected, K_plan)
    if exact_reference(s, w, plan) == False:
        return refusal(o, 3)
    if observed != NONE:
        if digest_text(w, observed, False) == False or digest_text(w, canonical, False) == False:
            return INVALID
        if matches_field(s, w, plan, K_sha256, observed) == False:
            return refusal(o, 3)
    tag = choose(canonical == NONE, QUALIFIED, NORMALIZED)
    if active_plan != NONE:
        if is_object(w, active_plan) == False:
            return INVALID
        schema = lookup(w, active_plan, K_schema)
        mappings = lookup(w, active_plan, K_value_registers)
        if leaf_schema(w, schema) or (select_schema(w, schema) and empty_object(w, mappings) == False):
            if is_object(w, mappings) == False:
                return INVALID
            tag = REGISTER_QUALIFIED
    checks = lookup(w, receipt, K_checks)
    if checks == NONE or get(w, checks) != 5:
        return INVALID
    count = get(w, checks + 32)
    check = 64 + get(w, checks + 24) * 72
    at = 0
    while at < count:
        if is_object(w, check) == False:
            return INVALID
        claim = lookup(w, check, K_claim)
        if claim_lowering_refinement(w, claim) and proved_status(w, lookup(w, check, K_status)):
            put(o, 0, tag)
            put(o, 8, 0)
            copy_digest(s, o, get(w, plan + 56) + 53, 16)
            if canonical == NONE:
                return 80
            copy_digest(s, o, get(w, canonical + 56) + 1, 80)
            return 144
        check = next(w, check)
        at = at + 1
    return refusal(o, 3)

def copy_digest(s:readbuf, o:mutbuf, start:u64, dest:u64) -> u64:
    index = 0
    while index < 64:
        store(o, dest + index, byte(s, start + index))
        index = index + 1
    return 0

def next(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 16) * 72

def is_object(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

def matches_field(s:readbuf, w:mutbuf, record:u64, key:u64, expected:u64) -> bool:
    actual = lookup(w, record, key)
    return actual != NONE and equal_span(s, w, actual, expected)

def span(w:mutbuf, o:mutbuf, node:u64, at:u64) -> u64:
    start = get(w, node + 56)
    extent = get(w, node + 64)
    if get(w, node) == 0:
        start = get(w, node + 24)
        extent = get(w, node + 32)
    put(o, at, start)
    put(o, at + 8, extent)
    return at + 16

def refusal(o:mutbuf, reason:u64) -> u64:
    put(o, 0, RESULT)
    put(o, 8, reason)
    return 16
'''


def key_table():
    groups = {}
    for ordinal, name in enumerate(NAMES, 1):
        encoded = name.encode('ascii')
        groups.setdefault(len(encoded), []).append((ordinal, encoded))
    lines = ['def key_id(w:mutbuf, at:u64, extent:u64) -> u64:']
    for width, fields in sorted(groups.items()):
        lines.append(f'    if extent == {width}:')
        for ordinal, encoded in fields:
            terms = []
            for offset in range(0, width, 8):
                cell = encoded[offset:offset + 8]
                terms.append(f'(match_word(w, at + {offset}, {len(cell)}) ^ {int.from_bytes(cell, "little")})')
            lines.extend((f'        if ({" | ".join(terms)}) == 0:', f'            return {ordinal}'))
    lines.append('    return 0')
    return '\n'.join(lines)


def literal_match(name, value):
    raw = value.encode('ascii')
    words = []
    for offset in range(0, len(raw), 8):
        word = raw[offset:offset + 8]
        words.append(f'(match_word(w, at + {offset}, {len(word)}) ^ {int.from_bytes(word, "little")})')
    return (f'def {name}(w:mutbuf, node:u64) -> bool:\n'
            f'    if node == {(1 << 64) - 1} or get(w, node) != 4 or get(w, node + 32) != {len(raw)}:\n'
            '        return False\n'
            '    at = get(w, node + 24)\n'
            f'    return ({" | ".join(words)}) == 0')


def program():
    constants = {f'K_{name}': index for index, name in enumerate(NAMES, 1)}
    constants.update(RESULT=int.from_bytes(b'HIAEVR01', 'little'),
                     FILES=int.from_bytes(b'HIAEVP01', 'little'), NONE=(1 << 64) - 1,
                     SUBJECT=int.from_bytes(b'HIAEVS01', 'little'),
                     QUALIFIED=int.from_bytes(b'HIAEVQ01', 'little'),
                     NORMALIZED=int.from_bytes(b'HIAEVQ02', 'little'),
                     REGISTER_QUALIFIED=int.from_bytes(b'HIAEVQ03', 'little'),
                     WITNESS_SPAN=int.from_bytes(b'HIAEVW01', 'little'),
                     SCOPE_INPUT=int.from_bytes(b'HIAEVT01', 'little'),
                     SCOPE_RESULT=int.from_bytes(b'HIAPSC01', 'little'),
                     SCOPE_EFFECT=int.from_bytes(b'HIAEVH01', 'little'),
                     SCOPE_COMPLETE=int.from_bytes(b'HIAEVA01', 'little'),
                     PLAN_COMPLETE=int.from_bytes(b'HIAPVR01', 'little'),
                     BUILD_EFFECT=int.from_bytes(b'HIABCO01', 'little'),
                     FINITE_OBSERVATION=FINITE_OBSERVATION,
                     MACHINE_CHECK_COUNT=len(MACHINE_CHECKS),
                     SELECT_CHECK_COUNT=len(MACHINE_CHECKS) + len(SELECT_CHECKS),
                     METHOD_COUNT=len(METHODS),
                     LAYOUT_METHOD=METHODS.index('checked_explicit_machine_choices') + 1,
                     ENCODING_METHOD=METHODS.index('complete_native_rederivation') + 1,
                     FINITE_METHOD=METHODS.index('finite_domain') + 1,
                     INVALID=4294967293)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    readers = authority()
    claims = ['def claim_kind(w:mutbuf, node:u64) -> u64:']
    for index, claim in enumerate(CLAIMS, 1):
        claims.extend((f'    if claim_{claim}(w, node):', f'        return {index}'))
    claims.append('    return 0')
    machine = ['def machine_choice(w:mutbuf, choice:u64, rule:u64, index:u64) -> bool:']
    rules = []
    table = tuple((row['choice'], row['rule']) for row in MACHINE_CHECKS) + SELECT_CHECKS + (LEAF_CHECK,)
    for index, (choice, rule) in enumerate(table):
        machine.extend((f'    if index == {index}:',
                        f'        return {choice}_choice(w, choice) and {choice}_rule(w, rule)'))
        rules.extend((literal_match(choice + '_choice', choice),
                      literal_match(choice + '_rule', rule)))
    machine.append('    return False')
    return '\n'.join((
        policy, function(CONTEXT, 'equal_span'),
        function(CONTEXT, 'digest_text').replace('NONE', str(constants['NONE'])),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        key_table(),
        literal_match('proved_status', 'proved'), '\n'.join(claims),
        *(literal_match('claim_' + claim, claim) for claim in CLAIMS),
        literal_match('layout_schema', LAYOUT_V1),
        literal_match('machine_schema', MACHINE_V2),
        literal_match('select_schema', MACHINE_V3),
        literal_match('leaf_schema', MACHINE_V4),
        literal_match('leaf_trap_rule', LEAF_TRAP_RULE),
        literal_match('lifetime_rule', LIFETIME_RULE),
        literal_match('plan_subject_kind', 'agent_machine_plan'),
        literal_match('core_subject_kind', 'core'),
        literal_match('canonical_subject_kind', 'canonical_lowering'),
        literal_match('native_subject_kind', 'native_artifact'),
        literal_match('layout_method', 'checked_explicit_machine_choices'),
        '\n'.join(machine), *rules,
        function(BUILD_CUSTODY, 'exact_reference').replace('NONE', str(constants['NONE'])),
        function(BUILD_CUSTODY, 'copy_reference'),
        *(function(readers, name) for name in ('artifact_reference', 'artifact_start', 'artifact_digest',
                                              'artifact_uri', 'valid_hex', 'input_word')),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
