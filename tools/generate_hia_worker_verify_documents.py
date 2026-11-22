"""Author assumptions, evidence, and receipt check documents from a scoped finding."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_proof_contract import PROOF_SCHEMA
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function

ASSUMPTIONS_FIELDS = ('assumptions', 'checker', 'profile', 'property', 'subject')
RESULT_FIELDS = ('claim', 'domain', 'status', 'unproved_obligations', 'validator',
                 'schema', 'global_safety_proved', 'execution_authority_granted')
ADDED_FIELDS = ('assumptions_artifact', 'evidence_artifact', 'proof_binding')
KEYS = (*ASSUMPTIONS_FIELDS, *RESULT_FIELDS, *ADDED_FIELDS)
SOURCE = Path('examples/hia_bootstrap/worker_verify_documents.hepta')

POLICY = r'''
# A scoped finding is not established here. The caller has checked its
# authenticated evidence/effect against the exact installation and subject.
# [finding, method evidence] => assumptions/evidence files.
# [finding, published assumptions ref, published evidence ref] => final check.
def verify_documents(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(s) > 8388608 or length(o) < 131072 or length(o) < length(s) * 2 + 512 or length(w) < 1048576:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return BAD
    count = get(w, 96)
    if count != 2 and count != 3:
        return BAD
    finding = 64 + get(w, 88) * 72
    if finding_shape(w, finding) == False:
        return BAD
    second = next(w, finding)
    if is_object(w, second) == False:
        return BAD
    if count == 2:
        return files(s, o, w, finding, second)
    third = next(w, second)
    if is_object(w, third) == False:
        return BAD
    return attach(s, o, w, finding, second, third)

def finding_shape(w:mutbuf, finding:u64) -> bool:
    if is_object(w, finding) == False or get(w, finding + 32) != 13:
        return False
    if proof_schema(w, lookup(w, finding, K_schema)) == False:
        return False
    return node_kind(w, finding, K_global_safety_proved, 1) and node_kind(w, finding, K_execution_authority_granted, 1) and node_kind(w, finding, K_assumptions, 5) and node_kind(w, finding, K_unproved_obligations, 5) and node_kind(w, finding, K_checker, 6) and node_kind(w, finding, K_profile, 6) and node_kind(w, finding, K_property, 6) and node_kind(w, finding, K_subject, 6) and node_kind(w, finding, K_validator, 6) and node_kind(w, finding, K_claim, 4) and node_kind(w, finding, K_status, 4) and node_kind(w, finding, K_domain, 4)

def node_kind(w:mutbuf, document:u64, key:u64, kind:u64) -> bool:
    node = lookup(w, document, key)
    return node != NONE and get(w, node) == kind

def files(s:readbuf, o:mutbuf, w:mutbuf, finding:u64, evidence:u64) -> u64:
    if lookup(w, evidence, K_proof_binding) != NONE:
        return BAD
    cut = split_key(s, w, evidence, K_proof_binding)
    if cut == NONE:
        return BAD
    at = assumptions_open(o, 24)
    at = copy_value(s, w, o, lookup(w, finding, K_assumptions), at)
    at = assumptions_checker(o, at)
    at = copy_value(s, w, o, lookup(w, finding, K_checker), at)
    at = assumptions_profile(o, at)
    at = copy_value(s, w, o, lookup(w, finding, K_profile), at)
    at = assumptions_property(o, at)
    at = copy_value(s, w, o, lookup(w, finding, K_property), at)
    at = assumptions_subject(o, at)
    at = copy_value(s, w, o, lookup(w, finding, K_subject), at)
    at = assumptions_close(o, at)
    put(o, 0, FILES)
    put(o, 8, at - 24)
    start = at
    at = splice(s, o, w, evidence, cut, finding, K_proof_binding, at)
    put(o, 16, at - start)
    return at

def attach(s:readbuf, o:mutbuf, w:mutbuf, finding:u64, assumptions:u64, evidence:u64) -> u64:
    first = split_key(s, w, finding, K_assumptions_artifact)
    second = split_key(s, w, finding, K_evidence_artifact)
    if first == NONE or second == NONE or first >= second:
        return BAD
    start = get(w, finding + 56)
    end = start + get(w, finding + 64)
    at = copy_input(s, o, start, 16, first - start)
    at = field_append(s, o, w, assumptions, K_assumptions_artifact, at, True)
    at = copy_input(s, o, first, at, second - first)
    at = field_append(s, o, w, evidence, K_evidence_artifact, at, True)
    at = copy_input(s, o, second, at, end - second)
    put(o, 0, CHECK)
    put(o, 8, at - 16)
    return at

# A decoded key can be compared without reserializing it. The surrounding
# physical JSON is canonical, so each insertion point is the byte after an
# intact previous value, and its suffix starts with the original delimiter.
def split_key(s:readbuf, w:mutbuf, object:u64, wanted:u64) -> u64:
    at = get(w, object + 56) + 1
    finish = at + get(w, object + 64) - 2
    count = get(w, object + 32)
    node = 64 + get(w, object + 24) * 72
    index = 0
    cut = NONE
    while index < count:
        if byte(s, at) != choose(index == 0, 34, 44):
            return NONE
        if cut == NONE and key_after(w, node, wanted):
            cut = at
        if get(w, node) <= 3:
            at = get(w, node + 24) + get(w, node + 32)
        else:
            at = get(w, node + 56) + get(w, node + 64)
        node = next(w, node)
        index = index + 1
    if at != finish:
        return NONE
    if cut == NONE:
        return finish
    return cut

def splice(s:readbuf, o:mutbuf, w:mutbuf, object:u64, cut:u64, value:u64, key:u64, cursor:u64) -> u64:
    start = get(w, object + 56)
    end = start + get(w, object + 64)
    at = copy_input(s, o, start, cursor, cut - start)
    at = field_append(s, o, w, value, key, at, cut != start + 1)
    if cut == start + 1 and byte(s, cut) != 125:
        store(o, at, 44)
        at = at + 1
    return copy_input(s, o, cut, at, end - cut)

def field_append(s:readbuf, o:mutbuf, w:mutbuf, value:u64, key:u64, cursor:u64, comma:bool) -> u64:
    at = cursor
    if comma:
        store(o, at, 44)
        at = at + 1
    if key == K_assumptions_artifact:
        at = attach_assumptions(o, at)
    elif key == K_evidence_artifact:
        at = attach_evidence(o, at)
    else:
        at = attach_proof(o, at)
    return copy_value(s, w, o, value, at)
'''


def key_before():
    lines = [
        'def key_after(w:mutbuf, node:u64, wanted:u64) -> bool:',
        '    start = get(w, node + 40)', '    size = get(w, node + 48)',
    ]
    for key in ADDED_FIELDS:
        lines.extend((f'    if wanted == K_{key}:', f'        return after_{key}(w, start, size)'))
    lines.append('    return False')
    for key in ADDED_FIELDS:
        lines.append(f'def after_{key}(w:mutbuf, start:u64, size:u64) -> bool:')
        for i, byte in enumerate(key.encode()):
            lines.extend((f'    if size <= {i}:', '        return False',
                          f'    actual = byte(w, start + {i})',
                          f'    if actual != {byte}:', f'        return actual > {byte}'))
        lines.append(f'    return size > {len(key)}')
    return '\n'.join(lines)


def source_program():
    literals = {
        'assumptions_open': '{"assumptions":',
        'assumptions_checker': ',"assumptions_proved_here":false,"checker":',
        'assumptions_profile': ',"profile":',
        'assumptions_property': ',"property":',
        'assumptions_subject': ',"schema":"hepta.hia.agent.proof-assumptions.v1","subject":',
        'assumptions_close': ',"universal_core_to_machine_refinement_proved":false}',
        'attach_assumptions': '"assumptions_artifact":',
        'attach_evidence': '"evidence_artifact":',
        'attach_proof': '"proof_binding":',
    }
    constants = {f'K_{name}': index for index, name in enumerate(KEYS, 1)}
    constants.update(FILES=int.from_bytes(b'HIAVDF01', 'little'),
                     CHECK=int.from_bytes(b'HIAVDC01', 'little'),
                     NONE=(1 << 64) - 1, BAD=4294967293)
    source = '\n'.join((POLICY, key_before(), key_table(KEYS),
                        literal_match('proof_schema', PROOF_SCHEMA),
                        *(function(VERIFICATION, name) for name in ('is_object', 'next')),
                        function(CONTEXT, 'copy_value'), function(authority(), 'copy_input'),
                        WIRE_HELPERS.split('\ndef signed_id', 1)[0],
                        *(literal(name, value) for name, value in literals.items())))
    return (re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda m: str(constants[m[0]]), source)
            + '\n' + json_decoder(wire_spans=True))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
