"""Check the full immutable scope shared by a verification receipt and its proof files."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_proof_contract import _CHECKERS, _PROPERTIES, PROOF_SCHEMA
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_inspection_effect import function

from tools.hia_retained_proof_method import (
    EXTRA_KEYS, NATIVE_CORE_CHECKER, NATIVE_VERIFY_EVIDENCE, NATIVE_VERIFY_PROFILE, POLICY as METHODS_POLICY,
)

SOURCE = Path('examples/hia_bootstrap/worker_proof_scope.hepta')
SCOPE_FIELDS = ('candidate', 'candidate_core_sha256', 'base_program', 'base_core_sha256', 'context')
SUBJECT_FIELDS = ('kind', 'backend_profile', 'lowering_profile', 'plan_profile', 'plan',
                  'native_artifact', 'build_receipt')
ASSUMPTION_FIELDS = ('assumptions', 'checker', 'profile', 'property', 'subject')
CHECK_FIELDS = (*ASSUMPTION_FIELDS, 'claim', 'domain', 'execution_authority_granted',
                'global_safety_proved', 'schema', 'status', 'unproved_obligations', 'validator')
KINDS = ('core', 'canonical_lowering', 'agent_machine_plan', 'native_artifact')
KEYS = (*CHECK_FIELDS, *SCOPE_FIELDS, *SUBJECT_FIELDS, 'proof_binding', 'installation',
        'validation_profile', 'target_profile', 'checks', 'assumptions_artifact', 'evidence_artifact',
        'assumptions_proved_here', 'universal_core_to_machine_refinement_proved', 'id', 'statement',
        'name', 'method', 'python', 'native_selection_sha256', 'solver', 'auxiliary_checker_sha256',
        'native', 'image_sha256', *EXTRA_KEYS)
METHODS = tuple(_CHECKERS)
NATIVE_REPLAY_METHODS = ('core_admission', 'canonical_core_identity', 'finite_domain',
                         'context_budget_exhausted', 'canonical_lowering_unsupported',
                         'checked_explicit_machine_choices')
CLAIMS = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')
STATUSES = ('proved', 'refuted', 'unknown', 'unsupported')

POLICY = r'''
# The caller first admits the receipt's actual Core and selected subject.
# All five Store documents/references come from sealed authoritative reads:
# [receipt, target, ordinal, assumptions ref, assumptions, evidence ref, evidence,
#  installed selection digest, installed legacy checker runtime identity,
#  optional native checker image identities from the admitted capsule].
# This image relates the full scope; method-specific evidence must still pass
# the selected evidence checker before consumption or effect authorization.
def proof_scope(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 20 or length(s) > 8388608 or length(o) < 128 or length(w) < 65536:
        return INVALID
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return INVALID
    if get(w, 96) != 9 and get(w, 96) != 10:
        return INVALID
    receipt = 64 + get(w, 88) * 72
    target = next(w, receipt)
    index = next(w, target)
    if object(w, receipt) == False or object(w, target) == False or get(w, index) != 3:
        return INVALID
    if get(w, index + 32) != 1:
        return INVALID
    ordinal = byte(s, get(w, index + 24))
    check = selected_check(w, receipt, ordinal)
    if check == NONE:
        return INVALID
    if match_receipt(s, w, receipt, target, check) == False:
        return refused(o, 1)
    return retained_files(s, w, o, check, next(w, index))

def selected_check(w:mutbuf, receipt:u64, ordinal:u64) -> u64:
    checks = lookup(w, receipt, K_checks)
    if checks == NONE or get(w, checks) != 5 or ordinal < 48:
        return NONE
    amount = get(w, checks + 32)
    if amount > 4 or ordinal - 48 >= amount:
        return NONE
    seen = 0
    cursor = 64 + get(w, checks + 24) * 72
    selected = NONE
    index = 0
    while index < amount:
        if object(w, cursor) == False:
            return NONE
        claim = claim_id(w, lookup(w, cursor, K_claim))
        if claim == 0 or (seen & (1 << claim)) != 0:
            return NONE
        seen = seen | (1 << claim)
        if index == ordinal - 48:
            selected = cursor
        cursor = next(w, cursor)
        index = index + 1
    return selected

def match_receipt(s:readbuf, w:mutbuf, receipt:u64, target:u64, check:u64) -> bool:
    if get(w, check + 32) != 15 or result_schema(w, lookup(w, check, K_schema)) == False:
        return False
    if false_field(w, check, K_execution_authority_granted) == False or false_field(w, check, K_global_safety_proved) == False:
        return False
    scope = lookup(w, check, K_subject)
    claim_subject = lookup(w, receipt, K_subject)
    profile = lookup(w, receipt, K_validation_profile)
    if object(w, scope) == False or object(w, claim_subject) == False or object(w, profile) == False:
        return False
    if same(s, w, lookup(w, scope, K_target_profile), target) == False:
        return False
    if same(s, w, lookup(w, check, K_profile), profile) == False or same(s, w, lookup(w, check, K_validator), profile) == False:
        return False
    return subject_fields(s, w, receipt, scope, claim_subject)

def subject_fields(s:readbuf, w:mutbuf, receipt:u64, scope:u64, subject:u64) -> bool:
    field = K_candidate
    while field <= K_context:
        if same(s, w, lookup(w, receipt, field), lookup(w, scope, field)) == False:
            return False
        field = field + 1
    variant = subject_id(w, lookup(w, subject, K_kind))
    if variant == 0:
        return False
    count = 0
    field = K_kind
    while field <= K_build_receipt:
        original = lookup(w, subject, field)
        bound = lookup(w, scope, field)
        expected = subject_member(variant, field)
        if expected:
            if same(s, w, original, bound) == False:
                return False
            count = count + 1
        elif original != NONE or bound != NONE:
            return False
        field = field + 1
    return get(w, subject + 32) == count and get(w, scope + 32) == count + 6

def subject_member(variant:u64, field:u64) -> bool:
    if field == K_kind:
        return True
    if variant == 1:
        return False
    if field == K_backend_profile:
        return True
    if variant == 2:
        return field == K_lowering_profile
    if variant == 3:
        return field == K_plan_profile or field == K_plan
    return field == K_native_artifact or field == K_build_receipt

def retained_files(s:readbuf, w:mutbuf, o:mutbuf, check:u64, assumptions_ref:u64) -> u64:
    assumptions = next(w, assumptions_ref)
    evidence_ref = next(w, assumptions)
    evidence = next(w, evidence_ref)
    selection = next(w, evidence)
    runtime = next(w, selection)
    if object(w, assumptions_ref) == False or object(w, evidence_ref) == False or object(w, assumptions) == False or object(w, evidence) == False:
        return INVALID
    if same(s, w, lookup(w, check, K_assumptions_artifact), assumptions_ref) == False:
        return refused(o, 2)
    if same(s, w, lookup(w, check, K_evidence_artifact), evidence_ref) == False:
        return refused(o, 2)
    if assumptions_scope(w, s, check, assumptions) == False:
        return refused(o, 3)
    if evidence_scope(w, s, check, evidence) == False:
        return refused(o, 4)
    receipt = 64 + get(w, 88) * 72
    method = installed_checker(s, w, receipt, check, selection, runtime)
    if method == 0:
        return refused(o, 5)
    claim = claim_id(w, lookup(w, check, K_claim))
    status = status_id(w, lookup(w, check, K_status))
    checker = lookup(w, check, K_checker)
    effect = method_effect(s, w, check, evidence, method, claim, status, lookup(w, checker, K_native) != NONE)
    if effect == BAD_METHOD:
        return refused(o, 6)
    return scoped(o, method, claim, status, effect)

def assumptions_scope(w:mutbuf, s:readbuf, check:u64, assumptions:u64) -> bool:
    if get(w, assumptions + 32) != 8 or assumptions_schema(w, lookup(w, assumptions, K_schema)) == False:
        return False
    if false_field(w, assumptions, K_assumptions_proved_here) == False:
        return False
    if false_field(w, assumptions, K_universal_core_to_machine_refinement_proved) == False:
        return False
    field = K_assumptions
    while field <= K_subject:
        if same(s, w, lookup(w, check, field), lookup(w, assumptions, field)) == False:
            return False
        field = field + 1
    return True

def evidence_scope(w:mutbuf, s:readbuf, check:u64, evidence:u64) -> bool:
    proof = lookup(w, evidence, K_proof_binding)
    if object(w, proof) == False or get(w, proof + 32) != 13:
        return False
    field = K_assumptions
    while field <= K_validator:
        if same(s, w, lookup(w, check, field), lookup(w, proof, field)) == False:
            return False
        field = field + 1
    return True

def installed_checker(s:readbuf, w:mutbuf, receipt:u64, check:u64, selection:u64, runtime:u64) -> u64:
    checker = lookup(w, check, K_checker)
    claim = lookup(w, check, K_claim)
    property_node = lookup(w, check, K_property)
    clause = lookup(w, check, K_unproved_obligations)
    assumed = lookup(w, check, K_assumptions)
    if object(w, checker) == False or get(w, checker + 32) != 7:
        return 0
    if object(w, property_node) == False or get(w, property_node + 32) != 2:
        return 0
    if list_node(w, clause) == False or list_node(w, assumed) == False:
        return 0
    if same(s, w, lookup(w, property_node, K_id), claim) == False:
        return 0
    if same(s, w, lookup(w, checker, K_installation), lookup(w, receipt, K_installation)) == False:
        return 0
    if object(w, runtime) == False or digest_text(w, selection, False) == False:
        return 0
    if same(s, w, lookup(w, checker, K_native_selection_sha256), selection) == False:
        return 0
    method = method_id(w, lookup(w, checker, K_method))
    if method == 0 or status_id(w, lookup(w, check, K_status)) == 0:
        return 0
    native = lookup(w, checker, K_native)
    if native != NONE:
        return installed_native_checker(s, w, checker, property_node, runtime, native, method)
    if same(s, w, lookup(w, checker, K_python), runtime) == False:
        return 0
    if method_statement(w, lookup(w, checker, K_name), lookup(w, property_node, K_statement), method) == False:
        return 0
    return method

def installed_native_checker(s:readbuf, w:mutbuf, checker:u64, property_node:u64, runtime:u64, native:u64, method:u64) -> u64:
    # No receipt-supplied image digest can select its own checker.
    if get(w, 96) != 10 or object(w, native) == False or get(w, native + 32) != 2:
        return 0
    if lookup(w, checker, K_python) != NONE or native_profile(w, lookup(w, native, K_profile)) == False:
        return 0
    solver = lookup(w, checker, K_solver)
    aux = lookup(w, checker, K_auxiliary_checker_sha256)
    if solver == NONE or get(w, solver) != 0 or aux == NONE or get(w, aux) != 0:
        return 0
    pins = next(w, runtime)
    if list_node(w, pins) == False or get(w, pins + 32) != 2:
        return 0
    first = 64 + get(w, pins + 24) * 72
    core = method == M_core_admission
    expected = choose(core, first, next(w, first))
    image = lookup(w, native, K_image_sha256)
    if digest_text(w, image, False) == False or same(s, w, image, expected) == False:
        return 0
    name = lookup(w, checker, K_name)
    if (core and native_core_name(w, name) == False) or (core == False and native_observe_name(w, name) == False):
        return 0
    statement = lookup(w, property_node, K_statement)
    return choose(native_statement(w, statement, method), method, 0)

def object(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

def list_node(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 5

def next(w:mutbuf, node:u64) -> u64:
    return 64 + get(w, node + 16) * 72

def same(s:readbuf, w:mutbuf, left:u64, right:u64) -> bool:
    if left == NONE or right == NONE or get(w, left) != get(w, right):
        return False
    if get(w, left) <= 2:
        return True
    return equal_span(s, w, left, right)

def false_field(w:mutbuf, record:u64, field:u64) -> bool:
    node = lookup(w, record, field)
    return node != NONE and get(w, node) == 1

def scoped(o:mutbuf, method:u64, claim:u64, status:u64, effect:u64) -> u64:
    refused(o, 0)
    put(o, 16, method)
    put(o, 24, claim)
    put(o, 32, status)
    put(o, 40, effect)
    return 48

def refused(o:mutbuf, reason:u64) -> u64:
    put(o, 0, RESULT)
    put(o, 8, reason)
    return 16
'''


def wire_text(name, value):
    raw = value.encode('utf-8')
    lines = [f'def {name}(w:mutbuf, node:u64) -> bool:',
             f'    if node == {(1 << 64)-1} or get(w, node) != 4 or get(w, node + 32) != {len(raw)}:',
             '        return False', '    start = get(w, node + 24)', '    difference = 0']
    for offset in range(0, len(raw), 8):
        block = raw[offset:offset + 8]
        expected = int.from_bytes(block, 'little')
        lines.append(f'    difference = difference | (match_word(w, start + {offset}, {len(block)}) ^ {expected})')
    lines.append('    return difference == 0')
    return '\n'.join(lines)+'\n'


def selector(name, values):
    code = f'def {name}_id(w:mutbuf, node:u64) -> u64:\n'
    for ordinal, _ in enumerate(values, 1):
        code += f'    if {name}_{ordinal}(w, node):\n        return {ordinal}\n'
    code += '    return 0\n'
    return code + ''.join(wire_text(f'{name}_{ordinal}', item)
                          for ordinal, item in enumerate(values, 1))


def method_statements():
    code = 'def method_statement(w:mutbuf, name:u64, statement:u64, method:u64) -> bool:\n'
    for ordinal, _ in enumerate(METHODS, 1):
        code += f'    if method == {ordinal}:\n        return checker_{ordinal}(w, name) and statement_{ordinal}(w, statement)\n'
    code += '    return False\n'
    return code + ''.join(wire_text(f'checker_{ordinal}', _CHECKERS[item])
                          + wire_text(f'statement_{ordinal}', _PROPERTIES[item])
                          for ordinal, item in enumerate(METHODS, 1))

def native_statements():
    lines = ['def native_statement(w:mutbuf, statement:u64, method:u64) -> bool:']
    for method in NATIVE_REPLAY_METHODS:
        index = METHODS.index(method) + 1
        lines.append(f'    if method == {index}:\n        return statement_{index}(w, statement)')
    return '\n'.join((*lines, '    return False\n'))


def split_key_table(primary, remaining):
    source = """
def key_id(w:mutbuf, at:u64, extent:u64) -> u64:
    field = scope_key(w, at, extent)
    if field != 0:
        return field
    field = evidence_key(w, at, extent)
    if field == 0:
        return 0
    return field + KEY_OFFSET
"""
    return '\n'.join((source.replace('KEY_OFFSET', str(len(primary))),
                      comparison_table('scope_key', primary),
                      comparison_table('evidence_key', remaining)))


def program():
    constants = {f'K_{name}': ordinal for ordinal, name in enumerate(KEYS, 1)}
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     RESULT=int.from_bytes(b'HIAPSC01', 'little'))
    constants.update((f'M_{name}', index) for index, name in enumerate(METHODS, 1))
    constants.update(BAD_METHOD=255)
    methods = METHODS_POLICY.replace(
        'method:u64, claim:u64, status:u64) -> u64:',
        'method:u64, claim:u64, status:u64, native:bool) -> u64:', 1)
    methods = methods.replace(
        '        if claim != 1 or status != 1 or admission_checker(w, lookup(w, evidence, K_checker)) == False:',
        '        name = lookup(w, evidence, K_checker)\n'
        '        trusted = choose(native, native_core_name(w, name), admission_checker(w, name))\n'
        '        if claim != 1 or status != 1 or trusted == False:', 1)
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b',
                    lambda m: str(constants[m[0]]), POLICY + methods)
    return '\n'.join((
        policy,
        *(function(CONTEXT, name).replace('NONE', str(constants['NONE'])) for name in ('equal_span', 'digest_text')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(constants['NONE'])),
        split_key_table(KEYS[:36], KEYS[36:]), selector('method', METHODS),
        selector('subject', KINDS), selector('status', STATUSES), selector('claim', CLAIMS),
        method_statements(), native_statements(), wire_text('result_schema', PROOF_SCHEMA),
        wire_text('assumptions_schema', 'hepta.hia.agent.proof-assumptions.v1'),
        wire_text('admission_checker', _CHECKERS['core_admission']),
        wire_text('native_core_name', NATIVE_CORE_CHECKER),
        wire_text('native_observe_name', NATIVE_VERIFY_EVIDENCE),
        wire_text('native_profile', NATIVE_VERIFY_PROFILE),
        wire_text('optimization_schema', 'hepta.hia.optimization-verification.v1'),
        wire_text('optimization_proved', 'verified'),
        wire_text('optimization_refuted', 'rejected'),
        wire_text('optimization_unknown', 'unknown'),
        wire_text('optimization_timeout', 'timeout'),
        json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
