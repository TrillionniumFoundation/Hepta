"""Generate exact Verify evidence records from typed, observed HIA facts."""
from pathlib import Path
import json
import re

from hepta.hia_machine_plan import LAYOUT_V1, MACHINE_V2, MACHINE_V3, MACHINE_V4
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_emit_verification import (
    LEAF_CHECK, LEAF_TRAP_RULE, LIFETIME_RULE, MACHINE_CHECKS, POLICY as VERIFICATION, SELECT_CHECKS,
    key_table, literal_match,
)
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_finite_reference import EVIDENCE, NONE
from tools.generate_hia_worker_inspection_effect import function, literal
from tools.hia_retained_proof_method import (
    MACHINE_EXPIRED, MACHINE_METHOD, MACHINE_UNKNOWN, MACHINE_UNSUPPORTED, NATIVE_CORE_CHECKER,
)

FIELDS = ('after', 'before', 'case', 'function', 'arguments', 'core_sha256', 'schema', 'value_registers')
SOURCE = Path('examples/hia_bootstrap/worker_verify_evidence.hepta')
PLAN_EVIDENCE_LIMIT = 65536

POLICY = r'''
# The caller owns the admitted Core and physically evaluated transcript
# descriptors. This image can render observations but cannot issue authority.
# 1: canonical Core identity, two equal admitted 64-byte digests.
# 2: full finite domain, two admitted Core SHA-256s, coverage word record,
#    and exact transcript hash returned by the installed hashing image.
# 3..5: distinct observations of finite deadline/budget exhaustion.
# JSON: checked count, required count, and exact first differing row; or
# ["plan", Core digest, Plan, two measured digests, two measured frame maps].
# 7: Core admission facts from the immutable, verified Core program.
# 8: canonical lowering has no independent refinement proof.
# 9: frozen Context deadline elapsed before evaluating behavior.
# 11/12: independently hashed retained and rebuilt ELF, exact byte result,
#        and the freshly validated, normalized rebuild report.
def verify_evidence(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 128 and byte(s, 0) == 91:
        if input_word(s, 0) == LAYOUT_PREFIX:
            return layout_evidence(s, o, w)
        return counterexample(s, o, w)
    if length(s) < 16 or length(o) < 1024 or input_word(s, 0) != REQUEST:
        return BAD
    mode = input_word(s, 8)
    if mode == 1:
        return identity(s, o)
    if mode == 2:
        return complete(s, o)
    if mode == 7:
        return admitted_core(s, o)
    if mode == 8 and length(s) == 16:
        return finish(o, unsupported(o, 32), 4, mode)
    if mode == 9 and length(s) == 16:
        return finish(o, expired(o, 32), 3, mode)
    if mode == 11 or mode == 12:
        return encoding_evidence(s, o, mode)
    if mode >= 13 and mode <= 18:
        return machine_evidence(s, o, mode)
    if mode < 3 or mode > 5:
        return BAD
    return unknown(s, o, mode)

def identity(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 144 or qualified_hash(s, 16) == False or qualified_hash(s, 80) == False:
        return BAD
    index = 0
    while index < 64:
        if byte(s, 16 + index) != byte(s, 80 + index):
            return BAD
        index = index + 1
    at = identity_start(o, 32)
    at = copy_input(s, o, 16, at, 64)
    at = identity_middle(o, at)
    at = copy_input(s, o, 80, at, 64)
    at = identity_end(o, at)
    return finish(o, at, 1, 1)

def complete(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 360 or qualified_hash(s, 16) == False or qualified_hash(s, 80) == False or qualified_hash(s, 144) == False:
        return BAD
    count = input_word(s, 224)
    required = input_word(s, 232)
    if input_word(s, 208) != DOMAIN_PLAN or input_word(s, 216) > 3 or count < 1 or count > 1024 or required < 1 or required > 4096:
        return BAD
    start = 240 + count * 56
    if length(s) != start + count * 64:
        return BAD
    checked = 0
    row = 0
    while row < count:
        expected = input_word(s, 264 + 56 * row)
        if expected == 0 or expected > required - checked or complete_row(s, start + 64 * row, expected) == False:
            return BAD
        checked = checked + expected
        row = row + 1
    if checked != required:
        return BAD
    at = finite_start(o, 32)
    at = copy_input(s, o, 16, at, 64)
    at = finite_candidate(o, at)
    at = copy_input(s, o, 80, at, 64)
    at = finite_checked(o, at)
    at = decimal(o, at, checked)
    at = finite_required(o, at)
    at = decimal(o, at, required)
    at = finite_transcript(o, at)
    at = copy_input(s, o, 144, at, 64)
    at = finite_end(o, at)
    return finish(o, at, 1, 2)

def unknown(s:readbuf, o:mutbuf, mode:u64) -> u64:
    if length(s) != 32:
        return BAD
    checked = input_word(s, 16)
    required = input_word(s, 24)
    if required < 1 or required > 4096 or checked > required:
        return BAD
    if checked == required and mode != 5:
        return BAD
    if mode == 5 and checked != required:
        return BAD
    at = unknown_start(o, 32)
    at = decimal(o, at, checked)
    at = unknown_complete(o, at)
    if mode == 5:
        at = unknown_late(o, at)
    at = unknown_required(o, at)
    at = decimal(o, at, required)
    store(o, at, 125)
    return finish(o, at + 1, 3, mode)

def admitted_core(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 152 or qualified_hash(s, 16) == False or qualified_hash(s, 80) == False:
        return BAD
    amount = input_word(s, 144)
    if amount == 0 or amount > 8388608:
        return BAD
    at = core_start(o, 32)
    at = decimal(o, at, amount)
    at = core_digests(o, at)
    at = copy_input(s, o, 16, at, 64)
    at = core_input(o, at)
    at = copy_input(s, o, 80, at, 64)
    at = core_end(o, at)
    return finish(o, at, 1, 7)

def counterexample(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 128 or length(s) > 2048 or length(o) < 65536 or length(w) < 65536:
        return BAD
    put(o, 48, 4096)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 3:
        return BAD
    first = 64 + get(w, 88) * 72
    second = next(w, first)
    checked = budget_integer(s, w, first, 1, 4096)
    required = budget_integer(s, w, second, 1, 4096)
    item = next(w, second)
    if required == NONE or checked > required or is_object(w, item) == False or get(w, item + 32) != 3:
        return BAD
    before = lookup(w, item, K_before)
    after = lookup(w, item, K_after)
    case = lookup(w, item, K_case)
    if is_object(w, before) == False or is_object(w, after) == False or is_object(w, case) == False:
        return BAD
    if equal_span(s, w, before, after) or get(w, case + 32) != 2:
        return BAD
    name = lookup(w, case, K_function)
    args = lookup(w, case, K_arguments)
    if name == NONE or get(w, name) != 4 or args == NONE or get(w, args) != 5:
        return BAD
    at = mismatch_after(o, 32)
    at = copy_value(s, w, o, after, at)
    at = mismatch_before(o, at)
    at = copy_value(s, w, o, before, at)
    at = mismatch_checked(o, at)
    at = decimal(o, at, checked)
    at = mismatch_case(o, at)
    at = copy_value(s, w, o, case, at)
    at = unknown_required(o, at)
    at = decimal(o, at, required)
    store(o, at, 125)
    return finish(o, at + 1, 2, 6)

def qualified_hash(s:readbuf, at:u64) -> bool:
    index = 0
    while index < 64:
        digit = byte(s, at + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return False
        index = index + 1
    return True

def layout_evidence(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) > PLAN_EVIDENCE_LIMIT - 4096 or length(o) < PLAN_EVIDENCE_LIMIT or length(w) < 65536:
        return BAD
    put(o, 48, 4096)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return BAD
    count = get(w, 96)
    if count != 7 and count != 8:
        return BAD
    mode = 64 + get(w, 88) * 72
    core = next(w, mode)
    plan = next(w, core)
    canonical = next(w, plan)
    planned = next(w, canonical)
    canonical_frames = next(w, planned)
    planned_frames = next(w, canonical_frames)
    if (layout_mode(w, mode) == False or is_object(w, plan) == False
            or digest_text(w, core, False) == False or digest_text(w, canonical, False) == False
            or digest_text(w, planned, False) == False or is_object(w, canonical_frames) == False
            or is_object(w, planned_frames) == False or equal_span(s, w, core, lookup(w, plan, K_core_sha256)) == False):
        return BAD
    schema = lookup(w, plan, K_schema)
    same_frames = equal_span(s, w, canonical_frames, planned_frames)
    same_slots = True
    witness = NONE
    if count == 8:
        witness = next(w, planned_frames)
        if is_object(w, witness) == False or (layout_v3(w, schema) == False and layout_v4(w, schema) == False):
            return BAD
        same_slots = spill_only(w, lookup(w, plan, K_value_registers))
    elif same_frames == False:
        return BAD
    at = layout_begin(o, 32)
    at = copy_value(s, w, o, canonical_frames, at)
    at = layout_canonical_digest(o, at)
    at = copy_value(s, w, o, canonical, at)
    at = layout_choices(o, at)
    if layout_v1(w, schema):
        at = layout_one(o, at)
    elif layout_v2(w, schema):
        at = layout_machine(o, at)
    elif witness != NONE:
        at = layout_witness(o, at)
        at = copy_value(s, w, o, witness, at)
        if layout_v4(w, schema):
            at = layout_leaf_end(o, at)
        else:
            at = layout_select_end(o, at)
    elif layout_v3(w, schema):
        if empty_object(w, lookup(w, plan, K_value_registers)) == False:
            return BAD
        at = layout_select(o, at)
    else:
        return BAD
    at = layout_core(o, at)
    at = copy_value(s, w, o, core, at)
    at = layout_plan(o, at)
    at = copy_value(s, w, o, plan, at)
    at = layout_planned_frames(o, at)
    at = copy_value(s, w, o, planned_frames, at)
    at = layout_planned_digest(o, at)
    at = copy_value(s, w, o, planned, at)
    at = layout_frame_equality(o, at)
    at = equality(o, at, same_frames)
    at = layout_slot_equality(o, at)
    at = equality(o, at, same_slots)
    store(o, at, 125)
    return finish(o, at + 1, 1, 10)

def encoding_evidence(s:readbuf, o:mutbuf, mode:u64) -> u64:
    size = length(s)
    if size <= 150 or size > PLAN_EVIDENCE_LIMIT - 256 or length(o) < size + 256:
        return BAD
    if (byte(s, 16) != 34 or byte(s, 81) != 34 or byte(s, 82) != 34 or byte(s, 147) != 34
            or byte(s, 148) != 123 or byte(s, size - 1) != 125
            or qualified_hash(s, 17) == False or qualified_hash(s, 83) == False):
        return BAD
    at = encoding_begin(o, 32)
    at = copy_input(s, o, 16, at, 66)
    at = encoding_bytes(o, at)
    at = equality(o, at, mode == 11)
    at = encoding_build(o, at)
    at = copy_input(s, o, 148, at, size - 148)
    at = encoding_digest(o, at)
    at = copy_input(s, o, 82, at, 66)
    store(o, at, 125)
    return finish(o, at + 1, mode - 10, mode)

def equality(o:mutbuf, at:u64, value:bool) -> u64:
    if value:
        put(o, at, TRUE_WORD)
        return at + 4
    put(o, at, FALSE_WORD)
    return at + 5

def machine_evidence(s:readbuf, o:mutbuf, mode:u64) -> u64:
    proof = mode == 13 or mode == 14
    if length(s) != choose(proof, 406, 230):
        return BAD
    profile = input_word(s, 16)
    rows = input_word(s, 24)
    if proof:
        if profile < 1 or profile > 6 or rows < 4 or rows > 5 or (mode == 13 and rows != 5):
            return BAD
        if byte(s, 230) != 123 or byte(s, 405) != 125:
            return BAD
    elif profile != 0 or rows != 0:
        return BAD
    index = 32
    while index < 230:
        if byte(s, index) != 34 or byte(s, index + 65) != 34 or qualified_hash(s, index + 1) == False:
            return BAD
        index = index + 66
    at = machine_begin(o, 32)
    if proof:
        at = copy_input(s, o, 230, at, 176)
    else:
        at = machine_null(o, at)
    at = machine_core(o, at)
    at = copy_input(s, o, 32, at, 66)
    at = machine_final(o, at)
    at = copy_input(s, o, 164, at, 66)
    at = machine_method(o, at, mode)
    at = machine_object(o, at)
    at = copy_input(s, o, 98, at, 66)
    at = machine_rows(o, at)
    at = decimal(o, at, rows)
    at = machine_profile(o, at)
    at = decimal(o, at, profile)
    at = machine_reason(o, at, mode)
    store(o, at, 125)
    status = choose(proof, mode - 12, choose(mode < 17, 4, 3))
    return finish(o, at + 1, status, mode)

def machine_method(o:mutbuf, at:u64, mode:u64) -> u64:
    if mode <= 14:
        return method_machine_proof(o, at)
    if mode <= 16:
        return method_machine_unsupported(o, at)
    if mode == 17:
        return method_machine_expired(o, at)
    return method_machine_incomplete(o, at)

def machine_reason(o:mutbuf, at:u64, mode:u64) -> u64:
    if mode == 15:
        return machine_layout_reason(o, at)
    if mode == 16:
        return machine_subject_reason(o, at)
    if mode == 17:
        return machine_budget_reason(o, at)
    if mode == 18:
        return machine_incomplete_reason(o, at)
    return at

def finish(o:mutbuf, end:u64, status:u64, domain:u64) -> u64:
    put(o, 0, RESPONSE)
    put(o, 8, status)
    put(o, 16, domain)
    put(o, 24, end - 32)
    return end
'''


def source_program():
    tags = {
        'REQUEST': int.from_bytes(b'HIAVEV01', 'little'),
        'RESPONSE': int.from_bytes(b'HIAVER01', 'little'),
        'LAYOUT_PREFIX': int.from_bytes(b'["plan",', 'little'),
        'DOMAIN_PLAN': int.from_bytes(b'HIAVFD01', 'little'),
        'TRUE_WORD': int.from_bytes(b'true', 'little'),
        'FALSE_WORD': int.from_bytes(b'false', 'little'),
        'TRANSCRIPT_ROW': int.from_bytes(b'HIAVFJ01', 'little'),
        'BAD': 4294967293, 'NONE': NONE, 'PLAN_EVIDENCE_LIMIT': PLAN_EVIDENCE_LIMIT,
    }
    tags.update({f'K_{key}': index for index, key in enumerate(FIELDS, 1)})
    select_checks = [{'choice': choice, 'checked': True, 'rule': rule}
                     for choice, rule in SELECT_CHECKS]
    def choices(items):
        return json.dumps(items, sort_keys=True, separators=(',', ':'))

    v3_checks = [*MACHINE_CHECKS, *select_checks]
    select_checks[0]['witness'] = None
    witness_prefix, select_suffix = choices(v3_checks).split('null', 1)
    leaf = {'choice': LEAF_CHECK[0], 'rule': LEAF_CHECK[1], 'checked': True, 'trap_rule': LEAF_TRAP_RULE}
    _, leaf_suffix = choices([*v3_checks, leaf]).split('null', 1)
    select_checks[0]['witness'] = {'functions': {}, 'rule': LIFETIME_RULE}
    literals = {
        'mismatch_after': '{"after":',
        'core_start': '{"canonical_bytes":"',
        'core_digests': '","checker":"' + NATIVE_CORE_CHECKER + '","core_sha256":"',
        'core_input': '","input_sha256":"',
        'core_end': '"}',
        'unsupported': '{"reason":"native qualification and deterministic reemission are not a universal semantic refinement proof"}',
        'expired': '{"method":"context_budget_exhausted","reason":"context wall budget exhausted"}',
        'mismatch_checked': ',"checked":',
        'mismatch_before': ',"before":',
        'mismatch_case': ',"complete":false,"counterexample":',
        'identity_start': '{"all_inputs":true,"base_sha256":"',
        'identity_middle': '","candidate_sha256":"',
        'identity_end': '","method":"canonical_core_identity"}',
        'finite_start': '{"all_inputs_in_declared_widths":true,"base_sha256":"',
        'finite_candidate': '","candidate_sha256":"',
        'finite_checked': '","checked":',
        'finite_required': ',"complete":true,"method":"finite_domain","required":',
        'finite_transcript': ',"transcript_sha256":"',
        'finite_end': '"}',
        'unknown_start': '{"checked":',
        'unknown_complete': ',"complete":false',
        'unknown_late': ',"deadline_met":false',
        'unknown_required': ',"method":"finite_domain","required":',
        'layout_begin': '{"canonical_frame_bytes":',
        'layout_canonical_digest': ',"canonical_object_sha256":',
        'layout_choices': ',"choice_checks":',
        'layout_one': choices(MACHINE_CHECKS[:1]),
        'layout_machine': choices(MACHINE_CHECKS),
        'layout_select': choices(v3_checks),
        'layout_witness': witness_prefix,
        'layout_select_end': select_suffix,
        'layout_leaf_end': leaf_suffix,
        'layout_core': ',"core_sha256":',
        'layout_plan': ',"implicit_optimizer_used":false,"method":"checked_explicit_machine_choices","plan":',
        'layout_planned_frames': ',"planned_frame_bytes":',
        'layout_planned_digest': ',"planned_object_sha256":',
        'layout_frame_equality': ',"same_frame_sizes":',
        'layout_slot_equality': ',"same_slots":',
        'encoding_begin': '{"actual_sha256":',
        'encoding_bytes': ',"bytes_equal":',
        'encoding_build': ',"method":"complete_native_rederivation","native_build":',
        'encoding_digest': ',"no_llvm_or_external_assembler":true,"object_identity_equal":true,"rederived_sha256":',
        'machine_begin': '{"certificate":', 'machine_null': 'null',
        'machine_core': ',"core_sha256":', 'machine_final': ',"final_sha256":',
        'machine_object': ',"object_sha256":', 'machine_rows': ',"obligations_observed":',
        'machine_profile': ',"profile":',
        'method_machine_proof': ',"method":"' + MACHINE_METHOD + '"',
        'method_machine_unsupported': ',"method":"' + MACHINE_UNSUPPORTED + '"',
        'method_machine_expired': ',"method":"' + MACHINE_EXPIRED + '"',
        'method_machine_incomplete': ',"method":"' + MACHINE_UNKNOWN + '"',
        'machine_layout_reason': ',"reason":"The supplied ELF contains an allocated loader section outside the independent checker profile."',
        'machine_subject_reason': ',"reason":"The supplied subject is not a bounded final shared ELF with scalar entries and no borrowed exports."',
        'machine_budget_reason': ',"reason":"The admitted verification budget is exhausted or below the minimum checker interval."',
        'machine_incomplete_reason': ',"reason":"The independent checker did not return a complete proof or a rechecked counterexample."',
    }
    source = '\n'.join((POLICY, function(EVIDENCE, 'complete_row'),
                        *(function(authority(), name) for name in ('input_word', 'copy_input')),
                        *(function(RELEASE, name) for name in ('decimal', 'divide10')),
                        *(function(CONTEXT, name) for name in ('copy_value', 'digest_text', 'equal_span', 'budget_integer')),
                        *(function(VERIFICATION, name) for name in ('is_object', 'next', 'spill_only', 'empty_object')), key_table(FIELDS),
                        WIRE_HELPERS.split('\ndef signed_id', 1)[0],
                        *(literal(name, value.encode('ascii')).replace('state_put(', 'put(')
                          for name, value in literals.items()),
                        *(literal_match(name, schema) for name, schema in (
                            ('layout_mode', 'plan'), ('layout_v1', LAYOUT_V1),
                            ('layout_v2', MACHINE_V2), ('layout_v3', MACHINE_V3), ('layout_v4', MACHINE_V4)))))
    return (re.sub(r'\b(' + '|'.join(tags) + r')\b', lambda match: str(tags[match[0]]), source)
            + '\n' + json_decoder(wire_spans=True))



if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
