"""Author native Verify replay ingress and retained-receipt binding."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_verify_request import CLAIMS, POLICY as REQUEST, enumerated

SOURCE = Path('examples/hia_bootstrap/worker_verify_replay.hepta')
KEYS = (
    'adopted', 'assumptions_artifact', 'base_core_sha256', 'base_program', 'candidate',
    'candidate_core_sha256', 'checks', 'claim', 'claims', 'context', 'contract_version',
    'evidence_artifact', 'execution_authority_granted', 'global_safety_proved', 'id',
    'installation', 'request_id', 'result', 'schema', 'sha256', 'status', 'subject',
    'uri', 'validation_profile', 'verification_receipt',
)

POLICY = r'''
# [Journal request id, admitted arguments, cached response] projects the
# retained authority and ordered check list. This does not accept a proof.
# [admitted installation, arguments, result, Store receipt, readmitted scope]
# matches the independent bindings and enumerates exact typed document refs.
def verify_replay(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(s) > 4194304 or length(o) < 262144 or length(w) < 1048576:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return BAD
    first = list_first(w, 64)
    count = get(w, 96)
    if count == 3:
        args = next(w, first)
        terminal = next(w, args)
        return index_terminal(s, o, w, first, args, terminal)
    if count == 5:
        args = next(w, first)
        result = next(w, args)
        receipt = next(w, result)
        return index_receipt(s, o, w, first, args, result, receipt, next(w, receipt))
    return BAD

def list_first(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 24) * 72

def index_terminal(s:readbuf, o:mutbuf, w:mutbuf, request:u64, args:u64, terminal:u64) -> u64:
    if is_object(w, terminal) == False or get(w, terminal + 32) != 4 or request_id(w, request) == False:
        return BAD
    if is_contract(w, lookup(w, terminal, K_contract_version)) == False or is_completed(w, lookup(w, terminal, K_status)) == False:
        return BAD
    if same(s, w, request, lookup(w, terminal, K_request_id)) == False:
        return BAD
    result = lookup(w, terminal, K_result)
    count = result_shape(s, w, args, result)
    if count == 0:
        return BAD
    put(o, 0, TERMINAL)
    put(o, 8, count)
    store_span(w, o, result, 16)
    store_span(w, o, lookup(w, result, K_verification_receipt), 32)
    return 48

def index_receipt(s:readbuf, o:mutbuf, w:mutbuf, installation:u64, args:u64, result:u64, receipt:u64, scope:u64) -> u64:
    count = result_shape(s, w, args, result)
    if count == 0 or is_object(w, receipt) == False or get(w, receipt + 32) != 10 or is_object(w, scope) == False:
        return BAD
    if is_receipt(w, lookup(w, receipt, K_schema)) == False or is_object(w, installation) == False or get(w, installation + 32) != 4:
        return BAD
    if same(s, w, lookup(w, receipt, K_installation), installation) == False:
        return BAD
    if (same_binding_key(s, w, receipt, args, K_base_program) == False
            or same_binding_key(s, w, receipt, args, K_candidate) == False
            or same_binding_key(s, w, receipt, args, K_context) == False
            or same_binding_key(s, w, receipt, args, K_subject) == False
            or same_binding_key(s, w, receipt, args, K_validation_profile) == False
            or same_binding_key(s, w, receipt, scope, K_base_core_sha256) == False
            or same_binding_key(s, w, receipt, scope, K_candidate_core_sha256) == False
            or same_binding_key(s, w, receipt, result, K_checks) == False):
        return BAD
    put(o, 0, RECEIPT)
    put(o, 8, count)
    check = list_first(w, lookup(w, receipt, K_checks))
    index = 0
    while index < count:
        offset = 16 + 48 * index
        store_span(w, o, check, offset)
        store_span(w, o, lookup(w, check, K_assumptions_artifact), offset + 16)
        store_span(w, o, lookup(w, check, K_evidence_artifact), offset + 32)
        index = index + 1
        check = next(w, check)
    return 16 + 48 * count

def result_shape(s:readbuf, w:mutbuf, args:u64, result:u64) -> u64:
    if is_object(w, args) == False or get(w, args + 32) != 8 or is_object(w, result) == False or get(w, result + 32) != 5:
        return 0
    if (false_key(w, result, K_adopted) == False or typed_ref(w, lookup(w, result, K_verification_receipt), True) == False
            or same_binding_key(s, w, result, args, K_candidate) == False or same_binding_key(s, w, result, args, K_subject) == False):
        return 0
    claims = lookup(w, args, K_claims)
    checks = lookup(w, result, K_checks)
    if claims == NONE or checks == NONE or get(w, claims) != 5 or get(w, checks) != 5:
        return 0
    count = get(w, claims + 32)
    if count < 1 or count > 4 or count != get(w, checks + 32):
        return 0
    claim = list_first(w, claims)
    check = list_first(w, checks)
    index = 0
    seen = 0
    while index < count:
        kind = claim_id(w, claim)
        if kind == 0 or (seen & (1 << kind)) != 0 or valid_check(s, w, check, claim) == False:
            return 0
        seen = seen | (1 << kind)
        claim = next(w, claim)
        check = next(w, check)
        index = index + 1
    return count

def valid_check(s:readbuf, w:mutbuf, check:u64, claim:u64) -> bool:
    if is_object(w, check) == False or get(w, check + 32) != 15:
        return False
    return (is_check(w, lookup(w, check, K_schema)) and same(s, w, lookup(w, check, K_claim), claim)
            and false_key(w, check, K_global_safety_proved) and false_key(w, check, K_execution_authority_granted)
            and typed_ref(w, lookup(w, check, K_assumptions_artifact), True)
            and typed_ref(w, lookup(w, check, K_evidence_artifact), True))

def false_key(w:mutbuf, record:u64, key:u64) -> bool:
    node = lookup(w, record, key)
    return node != NONE and get(w, node) == 1

def same_binding_key(s:readbuf, w:mutbuf, first:u64, second:u64, key:u64) -> bool:
    return same(s, w, lookup(w, first, key), lookup(w, second, key))

def same(s:readbuf, w:mutbuf, first:u64, second:u64) -> bool:
    return first != NONE and second != NONE and equal_span(s, w, first, second)

def store_span(w:mutbuf, o:mutbuf, node:u64, at:u64) -> u64:
    put(o, at, get(w, node + 56))
    put(o, at + 8, get(w, node + 64))
    return 0

def request_id(w:mutbuf, node:u64) -> bool:
    if node == NONE or get(w, node) != 4 or get(w, node + 32) != 66:
        return False
    at = get(w, node + 24)
    if byte(w, at) != 114 or byte(w, at + 1) != 45:
        return False
    index = 2
    while index < 66:
        digit = byte(w, at + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return False
        index = index + 1
    return True
'''


def program():
    names = {f'K_{name}': i for i, name in enumerate(KEYS, 1)}
    names.update(TERMINAL=int.from_bytes(b'HIAVRP01', 'little'),
                 RECEIPT=int.from_bytes(b'HIAVRP02', 'little'), NONE=(1 << 64) - 1, BAD=4294967293)
    literals = {'is_contract': 'hepta.hia.agent-native.v1', 'is_check': 'hepta.hia.agent.proof-result.v1',
                'is_receipt': 'hepta.hia.agent.verification.v1', 'is_completed': 'completed'}
    policy = '\n'.join((POLICY, key_table(KEYS), *(literal_match(k, v) for k, v in literals.items()),
                         enumerated('claim', CLAIMS),
                         *(function(REQUEST, name) for name in ('typed_ref', 'text')),
                         *(function(VERIFICATION, name) for name in ('is_object', 'next')),
                         *(function(CONTEXT, name) for name in ('digest_text', 'equal_span')),
                         WIRE_HELPERS.split('\ndef signed_id', 1)[0]))
    return re.sub(r'\b(' + '|'.join(names) + r')\b', lambda match: str(names[match[0]]), policy) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
