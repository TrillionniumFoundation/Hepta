"""Author the Adopt acceptance-claim schedule from verified, sealed documents."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import source_program as identity_source
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import CLAIMS, POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_adopt_claims.hepta')
FIELDS = ('required_claims', 'checks', 'claim', 'status', 'base_core_sha256', 'subject',
          'kind', 'native_artifact', 'plan')

POLICY = r'''
# The receipts in this packet have already been individually authenticated and
# replayed. This only determines whether they authorize the frozen objective,
# and returns the exact order of any additional native-build custody checks.
def adopt_claims(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 6 or length(s) > 8388608 or length(o) < 262144 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 5:
        return INVALID
    objective = 64 + get(w, 88) * 72
    candidate = next(w, objective)
    baseline = next(w, candidate)
    plan = next(w, baseline)
    receipts = next(w, plan)
    if is_object(w, objective) == False or is_object(w, candidate) == False:
        return INVALID
    if digest_text(w, baseline, False) == False or (get(w, plan) != 0 and is_object(w, plan) == False):
        return INVALID
    required = lookup(w, objective, K_required_claims)
    if required == NONE or get(w, required) != 5 or get(w, required + 32) > 4:
        return INVALID
    if get(w, receipts) != 5 or get(w, receipts + 32) > 16:
        return INVALID
    if known_claims(w, required) == False or collect_scopes(s, o, w, candidate, baseline, plan, receipts) == 0:
        return INVALID
    return schedule_claims(o, w, required, receipts, get(w, plan) != 0)

def known_claims(w:mutbuf, required:u64) -> bool:
    claim = 64 + get(w, required + 24) * 72
    index = 0
    while index < get(w, required + 32):
        if claim_id(w, claim) > 3:
            return False
        claim = next(w, claim)
        index = index + 1
    return True

def collect_scopes(s:readbuf, o:mutbuf, w:mutbuf, candidate:u64, baseline:u64, plan:u64, receipts:u64) -> u64:
    receipt = 64 + get(w, receipts + 24) * 72
    index = 0
    while index < get(w, receipts + 32):
        if is_object(w, receipt) == False:
            return 0
        checks = lookup(w, receipt, K_checks)
        subject = lookup(w, receipt, K_subject)
        if checks == NONE or get(w, checks) != 5 or is_object(w, subject) == False:
            return 0
        scope = proved_checks(w, checks)
        if scope == 128:
            return 0
        if matches_field(s, w, receipt, K_base_core_sha256, baseline):
            scope = scope | 16
        subject_kind = lookup(w, subject, K_kind)
        kind = 0
        if native_subject(w, subject_kind):
            kind = 1
            if matches_field(s, w, subject, K_native_artifact, candidate):
                scope = scope | 32
        elif plan_subject(w, subject_kind):
            kind = 2
            if matches_field(s, w, subject, K_plan, plan):
                scope = scope | 64
        store(o, 160 + index * 2, kind)
        store(o, 161 + index * 2, scope)
        receipt = next(w, receipt)
        index = index + 1
    return 1

def proved_checks(w:mutbuf, checks:u64) -> u64:
    count = get(w, checks + 32)
    if count > 4:
        return 128
    check = 64 + get(w, checks + 24) * 72
    index = 0
    scope = 0
    while index < count:
        if is_object(w, check) == False:
            return 128
        claim = claim_id(w, lookup(w, check, K_claim))
        status = lookup(w, check, K_status)
        if claim > 3 or status == NONE or get(w, status) != 4:
            return 128
        if proved(w, status):
            scope = scope | (1 << claim)
        check = next(w, check)
        index = index + 1
    return scope

def schedule_claims(o:mutbuf, w:mutbuf, required:u64, receipts:u64, planned:bool) -> u64:
    claim = 64 + get(w, required + 24) * 72
    count = get(w, required + 32)
    length = get(w, receipts + 32)
    index = 0
    rechecks = 0
    while index < count:
        code = claim_id(w, claim)
        receipt = 0
        qualified = False
        while receipt < length:
            kind = byte(o, 160 + receipt * 2)
            scope = byte(o, 161 + receipt * 2)
            decision = claim_decision(code, kind, choose(planned, 1, 0), scope)
            if decision == 2:
                store(o, 24 + rechecks, receipt)
                rechecks = rechecks + 1
            if decision != 0:
                qualified = True
            receipt = receipt + 1
        if qualified == False:
            return claim_reply(o, index, rechecks)
        claim = next(w, claim)
        index = index + 1
    return claim_reply(o, count, rechecks)

def claim_reply(o:mutbuf, missing:u64, rechecks:u64) -> u64:
    put(o, 0, CLAIM_RESULT)
    put(o, 8, missing)
    put(o, 16, rechecks)
    return 24 + rechecks
'''


def source_program():
    constants = {f'K_{key}': index for index, key in enumerate(FIELDS, 1)}
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     CLAIM_RESULT=int.from_bytes(b'HIAADK01', 'little'))
    lookup = (
        'def claim_id(w:mutbuf, node:u64) -> u64:\n'
        + ''.join(f'    if claim_{name}(w, node):\n        return {index}\n'
                  for index, name in enumerate(CLAIMS))
        + '    return 4\n'
    )
    source = '\n'.join((
        POLICY, lookup,
        *(literal_match(f'claim_{name}', name) for name in CLAIMS),
        literal_match('proved', 'proved'),
        literal_match('native_subject', 'native_artifact'),
        literal_match('plan_subject', 'agent_machine_plan'),
        *(function(VERIFICATION, name) for name in ('next', 'is_object', 'matches_field')),
        *(function(CONTEXT, name) for name in ('equal_span', 'digest_text')),
        function(identity_source(), 'claim_decision'),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0],
        key_table(FIELDS),
    ))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
