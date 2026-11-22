"""Author the retained verification receipt boundary used by the Emit Worker."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_machine_plan import LAYOUT_V1
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_build_custody import POLICY as BUILD_CUSTODY
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_emit_verification.hepta')
NAMES = ('installation', 'context', 'candidate', 'validation_profile', 'candidate_core_sha256',
         'base_program', 'base_core_sha256', 'subject', 'checks', 'claim', 'status',
         'assumptions_artifact', 'evidence_artifact', 'schema', 'method', 'plan',
         'core_sha256', 'canonical_object_sha256', 'planned_object_sha256',
         'canonical_frame_bytes', 'planned_frame_bytes', 'same_slots', 'same_frame_sizes',
         'implicit_optimizer_used', 'choice_checks', 'choice', 'checked', 'rule', 'proof_binding')
CLAIMS = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')
LAYOUT_RULE = 'exact block permutations; every terminator transfers explicitly'

POLICY = r'''
# Identity input: canonical [installation, context, candidate or null,
# validation profile, retained receipt]. Canonicalization never changes the
# hash of the raw Store file. Returned spans refer to this sealed comparison
# frame; the caller must still recheck Core, subject, assumptions and evidence.
def emit_verification(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 5 or length(s) > 8388608 or length(o) < 256 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    count = get(w, 96)
    if count != 1 and count != 2 and count != 5 and count != 7:
        return INVALID
    first = 64 + get(w, 88) * 72
    if count == 1:
        return verification_files(s, w, o, first)
    if count == 7:
        return layout_evidence(s, w, o, first)
    second = next(w, first)
    if count == 2:
        return qualified_plan(w, o, s, first, second)
    candidate = next(w, second)
    profile = next(w, candidate)
    receipt = next(w, profile)
    if is_object(w, first) == False or is_object(w, second) == False or is_object(w, receipt) == False:
        return INVALID
    if (get(w, candidate) != 0 and is_object(w, candidate) == False) or is_object(w, profile) == False:
        return INVALID
    return bind_receipt(s, w, o, first, second, candidate, profile, receipt)

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

# [verified Core digest, physically retained plan, actual canonical and
#  planned object digests, independently extracted frame maps, proof evidence].
# This rechecks the v1 conditional block-layout claim, never general refinement.
def layout_evidence(s:readbuf, w:mutbuf, o:mutbuf, core:u64) -> u64:
    plan = next(w, core)
    canonical = next(w, plan)
    planned = next(w, canonical)
    canonical_frames = next(w, planned)
    planned_frames = next(w, canonical_frames)
    evidence = next(w, planned_frames)
    if digest_text(w, core, False) == False or digest_text(w, canonical, False) == False or digest_text(w, planned, False) == False:
        return INVALID
    if is_object(w, plan) == False or is_object(w, canonical_frames) == False or is_object(w, planned_frames) == False or is_object(w, evidence) == False:
        return INVALID
    if layout_schema(w, lookup(w, plan, K_schema)) == False or layout_method(w, lookup(w, evidence, K_method)) == False:
        return refusal(o, 4)
    if matches_field(s, w, plan, K_core_sha256, core) == False or matches_field(s, w, evidence, K_core_sha256, core) == False:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_plan, plan) == False or get(w, evidence + 32) != 12:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_canonical_object_sha256, canonical) == False or matches_field(s, w, evidence, K_planned_object_sha256, planned) == False:
        return refusal(o, 4)
    if matches_field(s, w, evidence, K_canonical_frame_bytes, canonical_frames) == False or matches_field(s, w, evidence, K_planned_frame_bytes, planned_frames) == False:
        return refusal(o, 4)
    if equal_span(s, w, canonical_frames, planned_frames) == False:
        return refusal(o, 4)
    if tag_is(w, lookup(w, evidence, K_same_slots), 2) == False or tag_is(w, lookup(w, evidence, K_same_frame_sizes), 2) == False:
        return refusal(o, 4)
    if tag_is(w, lookup(w, evidence, K_implicit_optimizer_used), 1) == False or is_object(w, lookup(w, evidence, K_proof_binding)) == False:
        return refusal(o, 4)
    checks = lookup(w, evidence, K_choice_checks)
    if checks == NONE or get(w, checks) != 5 or get(w, checks + 32) != 1:
        return refusal(o, 4)
    choice = 64 + get(w, checks + 24) * 72
    if is_object(w, choice) == False or get(w, choice + 32) != 3:
        return refusal(o, 4)
    if block_layout_choice(w, lookup(w, choice, K_choice)) == False or block_layout_rule(w, lookup(w, choice, K_rule)) == False:
        return refusal(o, 4)
    return refusal(o, choose(tag_is(w, lookup(w, choice, K_checked), 2), 0, 4))

def tag_is(w:mutbuf, node:u64, tag:u64) -> bool:
    return node != NONE and get(w, node) == tag

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
def qualified_plan(w:mutbuf, o:mutbuf, s:readbuf, expected:u64, receipt:u64) -> u64:
    if is_object(w, expected) == False or is_object(w, receipt) == False:
        return INVALID
    if matches_field(s, w, receipt, K_subject, expected) == False:
        return refusal(o, 3)
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
        if lowering_claim(w, claim) and proved_status(w, lookup(w, check, K_status)):
            return refusal(o, 0)
        check = next(w, check)
        at = at + 1
    return refusal(o, 3)

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


def program():
    constants = {f'K_{name}': index for index, name in enumerate(NAMES, 1)}
    constants.update(RESULT=int.from_bytes(b'HIAEVR01', 'little'),
                     FILES=int.from_bytes(b'HIAEVP01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    readers = authority()
    claims = ['def claim_kind(w:mutbuf, node:u64) -> u64:']
    for index, claim in enumerate(CLAIMS, 1):
        claims.extend((f'    if claim_{claim}(w, node):', f'        return {index}'))
    claims.append('    return 0')
    return '\n'.join((
        policy, function(CONTEXT, 'equal_span'),
        function(CONTEXT, 'digest_text').replace('NONE', str(constants['NONE'])),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        comparison_table('key_id', NAMES), literal_match('lowering_claim', 'lowering_refinement'),
        literal_match('proved_status', 'proved'), '\n'.join(claims),
        *(literal_match('claim_' + claim, claim) for claim in CLAIMS),
        literal_match('layout_schema', LAYOUT_V1),
        literal_match('layout_method', 'checked_explicit_machine_choices'),
        literal_match('block_layout_choice', 'block_layout'),
        literal_match('block_layout_rule', LAYOUT_RULE),
        function(BUILD_CUSTODY, 'exact_reference').replace('NONE', str(constants['NONE'])),
        function(BUILD_CUSTODY, 'copy_reference'),
        *(function(readers, name) for name in ('artifact_reference', 'artifact_start', 'artifact_digest',
                                              'artifact_uri', 'valid_hex')),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
