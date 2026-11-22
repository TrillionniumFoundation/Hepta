"""Bind retained native Verify checks to the admitted capsule and proof scope."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_proof_contract import _PROPERTIES, PROOF_SCHEMA
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_proof_scope import (
    CLAIMS, KINDS, METHODS, KEYS as SCOPE_KEYS, POLICY as SCOPE, STATUSES, selector, split_key_table, wire_text,
)
from tools.hia_retained_proof_method import (
    NATIVE_CORE_CHECKER, NATIVE_VERIFY_EVIDENCE, NATIVE_VERIFY_PROFILE, POLICY as PROOF_METHODS,
)

SOURCE = Path('examples/hia_bootstrap/worker_verify_scope.hepta')
KEYS = SCOPE_KEYS
NATIVE_METHODS = ('core_admission', 'canonical_core_identity', 'finite_domain', 'context_budget_exhausted',
                  'canonical_lowering_unsupported')

NATIVE_CHECKER = r'''
# The authority holder (not a retained file) supplies the exact capsule
# digests in [Core checker digest, behavioral-observation checker digest].
def installed_checker(s:readbuf, w:mutbuf, receipt:u64, check:u64, selection:u64, runtime:u64) -> u64:
    checker = lookup(w, check, K_checker)
    property_node = lookup(w, check, K_property)
    if object(w, checker) == False or get(w, checker + 32) != 7 or object(w, property_node) == False or get(w, property_node + 32) != 2:
        return 0
    if list_node(w, lookup(w, check, K_unproved_obligations)) == False or list_node(w, lookup(w, check, K_assumptions)) == False:
        return 0
    if same(s, w, lookup(w, property_node, K_id), lookup(w, check, K_claim)) == False:
        return 0
    if same(s, w, lookup(w, checker, K_installation), lookup(w, receipt, K_installation)) == False:
        return 0
    if digest_text(w, selection, False) == False or same(s, w, lookup(w, checker, K_native_selection_sha256), selection) == False:
        return 0
    if list_node(w, runtime) == False or get(w, runtime + 32) != 2:
        return 0
    first = 64 + get(w, runtime + 24) * 72
    method = method_id(w, lookup(w, checker, K_method))
    expected = choose(method == M_core_admission, first, next(w, first))
    if method == 0 or status_id(w, lookup(w, check, K_status)) == 0:
        return 0
    if native_checker(s, w, expected, checker, property_node, method):
        return method
    return 0

def native_checker(s:readbuf, w:mutbuf, expected:u64, checker:u64, property_node:u64, method:u64) -> bool:
    identity = lookup(w, checker, K_native)
    if object(w, identity) == False or get(w, identity + 32) != 2:
        return False
    if lookup(w, checker, K_python) != NONE or native_profile(w, lookup(w, identity, K_profile)) == False:
        return False
    solver = lookup(w, checker, K_solver)
    auxiliary = lookup(w, checker, K_auxiliary_checker_sha256)
    if solver == NONE or get(w, solver) != 0 or auxiliary == NONE or get(w, auxiliary) != 0:
        return False
    image = lookup(w, identity, K_image_sha256)
    if digest_text(w, image, False) == False or same(s, w, image, expected) == False:
        return False
    name = lookup(w, checker, K_name)
    statement = lookup(w, property_node, K_statement)
    if method == M_core_admission:
        return native_core_name(w, name) and statement_1(w, statement)
    return native_observe_name(w, name) and native_observe_statement(w, statement, method)

def method_effect(s:readbuf, w:mutbuf, check:u64, evidence:u64, method:u64, claim:u64, status:u64) -> u64:
    scope = lookup(w, check, K_subject)
    core = lookup(w, scope, K_candidate_core_sha256)
    base = lookup(w, scope, K_base_core_sha256)
    if digest_text(w, core, False) == False:
        return BAD_METHOD
    if method == M_core_admission:
        if claim != 1 or status != 1 or native_core_name(w, lookup(w, evidence, K_checker)) == False:
            return BAD_METHOD
        return trust_if(same(s, w, core, lookup(w, evidence, K_core_sha256)))
    if method == M_canonical_lowering_unsupported:
        reason = lookup(w, evidence, K_reason)
        return trust_if(claim == 3 and status == 4 and subject_id(w, lookup(w, scope, K_kind)) == 2 and reason != NONE and get(w, reason) == 4)
    if claim != 2 or digest_text(w, base, False) == False or method_id(w, lookup(w, evidence, K_method)) != method:
        return BAD_METHOD
    if method == M_canonical_core_identity:
        return trust_if(status == 1 and same(s, w, base, core) and behavior_digests(s, w, evidence, base, core)
                        and true_field(w, evidence, K_all_inputs))
    if method == M_context_budget_exhausted:
        return trust_if(status == 3)
    if method == M_finite_domain:
        return finite_evidence(s, w, evidence, status, base, core)
    return BAD_METHOD
'''


def native_statements():
    code = 'def native_observe_statement(w:mutbuf, statement:u64, method:u64) -> bool:\n'
    for item in ('canonical_core_identity', 'finite_domain', 'context_budget_exhausted',
                 'canonical_lowering_unsupported'):
        ordinal = METHODS.index(item) + 1
        code += f'    if method == {ordinal}:\n        return statement_{ordinal}(w, statement)\n'
    return code + '    return False\n'



def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(KEYS, 1)}
    constants.update({f'M_{name}': index for index, name in enumerate(METHODS, 1)})
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     RESULT=int.from_bytes(b'HIAPSC01', 'little'), BAD_METHOD=255)
    source = SCOPE.replace(function(SCOPE, 'installed_checker'), '').replace(
        function(SCOPE, 'installed_native_checker'), '')
    source = source.replace(
        '    checker = lookup(w, check, K_checker)\n'
        '    effect = method_effect(s, w, check, evidence, method, claim, status, lookup(w, checker, K_native) != NONE)',
        '    effect = method_effect(s, w, check, evidence, method, claim, status)',
    ).replace('get(w, 96) != 9 and get(w, 96) != 10', 'get(w, 96) != 9')
    source += NATIVE_CHECKER
    source += '\n'.join(function(PROOF_METHODS, name) for name in (
        'finite_evidence', 'count4096', 'behavior_digests', 'trust_if',
        'true_field', 'false_field',
    ) if f'\ndef {name}(' in PROOF_METHODS and f'\ndef {name}(' not in source)
    code = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source)
    none = str(constants['NONE'])
    return '\n'.join((
        code,
        *(function(CONTEXT, name).replace('NONE', none) for name in ('equal_span', 'digest_text')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', none),
        split_key_table(KEYS[:36], KEYS[36:]), selector('method', METHODS),
        selector('subject', KINDS), selector('status', STATUSES), selector('claim', CLAIMS),
        native_statements(),
        *(wire_text(f'statement_{METHODS.index(method) + 1}', _PROPERTIES[method]) for method in NATIVE_METHODS),
        wire_text('result_schema', PROOF_SCHEMA),
        wire_text('assumptions_schema', 'hepta.hia.agent.proof-assumptions.v1'),
        wire_text('native_profile', NATIVE_VERIFY_PROFILE),
        wire_text('native_core_name', NATIVE_CORE_CHECKER),
        wire_text('native_observe_name', NATIVE_VERIFY_EVIDENCE),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
