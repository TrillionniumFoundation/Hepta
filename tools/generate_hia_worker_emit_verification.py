"""Author the retained verification receipt boundary used by the Emit Worker."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_emit_verification.hepta')
NAMES = ('installation', 'context', 'candidate', 'validation_profile', 'candidate_core_sha256',
         'base_program', 'base_core_sha256', 'subject', 'checks', 'claim', 'status')

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
    if count != 2 and count != 5:
        return INVALID
    first = 64 + get(w, 88) * 72
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
    constants.update(RESULT=int.from_bytes(b'HIAEVR01', 'little'), NONE=(1 << 64) - 1,
                     INVALID=4294967293)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda match: str(constants[match[0]]), POLICY)
    return '\n'.join((
        policy, function(CONTEXT, 'equal_span'),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        comparison_table('key_id', NAMES), literal_match('lowering_claim', 'lowering_refinement'),
        literal_match('proved_status', 'proved'), json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
