"""Author scoped findings from sealed native Verify observations."""

from pathlib import Path
import json
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_proof_contract import PROOF_SCHEMA, SAFE_CORE_DOMAIN, SAFE_CORE_METHOD, _PROPERTIES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_request import POLICY as CONTEXT
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table, literal_match
from tools.generate_hia_worker_inspection_effect import function, literal
from tools.hia_retained_proof_method import (
    MACHINE_EXPIRED, MACHINE_METHOD, MACHINE_UNKNOWN, MACHINE_UNSUPPORTED,
    NATIVE_CORE_CHECKER, NATIVE_VERIFY_EVIDENCE as EVIDENCE_ROLE, NATIVE_VERIFY_PROFILE as CHECKER_PROFILE,
)

SOURCE = Path('examples/hia_bootstrap/worker_verify_finding.hepta')
MACHINE_SOURCE = Path('examples/hia_bootstrap/worker_verify_machine_finding.hepta')
ENCODING_DOMAIN = ('Exact actual artifact equals reverified Core/plan reemission and linkage by the same installed '
                   'implementation, with checked closed symbol/ABI inventory; no independent semantic refinement claim')
OUTCOMES = (
    ('behavior_equivalence', 'proved', 'canonical_core_identity',
     'Reflexivity for the exact admitted canonical Core bytes, including resources and traps'),
    ('behavior_equivalence', 'proved', 'finite_domain',
     'Exhaustive complete pure acyclic scalar domain (at most 12 total input bits), including first trap and resource ledger'),
    ('behavior_equivalence', 'unknown', 'finite_domain',
     'Pure acyclic scalar finite domain; exhaustive enumeration deadline expired'),
    ('behavior_equivalence', 'unknown', 'finite_domain',
     'Pure acyclic scalar finite domain; reference budget prevented completeness'),
    ('behavior_equivalence', 'unknown', 'finite_domain',
     'Exhaustive scalar enumeration finished after its frozen verification deadline'),
    ('behavior_equivalence', 'refuted', 'finite_domain',
     'All scalar inputs in a finite pure acyclic domain; return/first-trap/resource observations'),
    ('core_admission', 'proved', 'core_admission',
     'Exact canonical Core accepted by the installed whole-program checker; no behavioral or native claim'),
    ('lowering_refinement', 'unsupported', 'canonical_lowering_unsupported',
     'Whole Core-to-x86 refinement of canonical lowering is not proved by this profile'),
    ('behavior_equivalence', 'unknown', 'context_budget_exhausted',
     'Verification cannot exceed the frozen context deadline'),
    ('lowering_refinement', 'proved', 'checked_explicit_machine_choices',
     'Checked explicit machine choices preserve canonical CFG, scalar value lifetimes and path effects, conditional on canonical lowering/encoder correctness'),
    ('encoding_check', 'proved', 'complete_native_rederivation', ENCODING_DOMAIN),
    ('encoding_check', 'refuted', 'complete_native_rederivation', ENCODING_DOMAIN),
    ('lowering_refinement', 'proved', MACHINE_METHOD, SAFE_CORE_DOMAIN),
    ('lowering_refinement', 'refuted', MACHINE_METHOD, SAFE_CORE_DOMAIN),
    ('lowering_refinement', 'unsupported', MACHINE_UNSUPPORTED, SAFE_CORE_DOMAIN),
    ('lowering_refinement', 'unsupported', MACHINE_UNSUPPORTED, SAFE_CORE_DOMAIN),
    ('lowering_refinement', 'unknown', MACHINE_EXPIRED, SAFE_CORE_DOMAIN),
    ('lowering_refinement', 'unknown', MACHINE_UNKNOWN, SAFE_CORE_DOMAIN),
)
STATUS_IDS = {'proved': 1, 'refuted': 2, 'unknown': 3, 'unsupported': 4}
FIELDS = ('candidate_core_sha256', 'base_core_sha256', 'kind', 'id', 'sha256',
          'worker_sha256', 'backend_sha256', 'catalog_sha256', 'native_helpers_sha256')
COMMON_ASSUMPTION = (
    'identified_checker_execution',
    'The identified HIA checker images and hashing implementation execute their specified checks faithfully.',
)
BEHAVIOR_ASSUMPTION = (
    'same_core_environment',
    'Both programs use the same declared Core semantics and external-effect/allocation environment; this does not prove a deployed environment implements that model.',
)
FINITE_ASSUMPTION = (
    'complete_finite_domain',
    'The input domain is the complete declared-width domain of the checked pure scalar acyclic functions, limited to 12 input bits and 4096 enumerated cases; the reference interpreter defines the observations.',
)
LAYOUT_ASSUMPTIONS = (
    ('canonical_lowering_correctness', 'The canonical Core lowering implements Core semantics.'),
    ('encoder_and_relocation_correctness', 'The x86 encoder and relocation machinery implement their declared instructions.'),
)
LAYOUT_OBLIGATION = (
    'canonical_lowering_correctness',
    'The canonical lowering and encoder assumptions are not discharged by checking explicit machine choices.',
)
ENCODING_ASSUMPTION = (
    'same_implementation_rederivation',
    'The retained Core/plan is rechecked and emitted with the same identified lowering, encoder and linkage '
    'implementation; matching bytes can preserve a common implementation defect.',
)
ENCODING_OBLIGATION = (
    'independent_encoding_semantics',
    'Reemission equality is not an independent decoder/ISA semantics check or a verified backend.',
)
MACHINE_ASSUMPTION = (
    'closed_supplied_machine_model',
    'The scoped Core, x86 and ELF models and native obligation checker faithfully model the exact retained bytes, caller ABI and reviewed immediate-binding abort layout.',
)
MACHINE_OBLIGATION = (
    'supplied_machine_scope',
    'The machine check covers only the exact retained Core/object/final triple and the stated model, not arbitrary linkers, other exports or execution authorization.',
)
REFUTED_OBLIGATION = (
    'requested_property',
    'The requested property is not established; this result is refuted and cannot satisfy a required proof.',
)
COMMON_OBLIGATIONS = (
    ('checker_soundness', 'No machine-checked soundness proof of the HIA checker or its models is supplied.'),
    ('whole_language_soundness', 'No safety theorem for the complete HIA language or arbitrary programs is established.'),
    ('core_to_machine_refinement', 'No independent semantic refinement from this Core to actual executed machine instructions is established by this check.'),
    ('abi_ffi_loading', 'Native caller validity, ABI/FFI implementations, loader mapping, symbol interposition and external memory liveness are not proved.'),
    ('native_resources', 'Native stack, heap, wall-time and process resource bounds, including exhaustion behavior, are not proved.'),
    ('termination_outside_profile', "Termination outside the checker's stated domain is not established."),
    ('concurrency_and_side_channels', 'Concurrency, signals, hardware faults, timing and side-channel properties are not established.'),
)

POLICY = r'''
# An authenticated Worker assembles this packet only from the sealed evidence
# role's result and the already admitted subject. The two digests are from the
# pinned capsule (selection and method's checker role), never caller arguments.
# It renders a finding, not authority. Method-specific replay is mandatory.
def verify_finding(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 131072 or length(o) < length(s) + 8192 or length(o) < 65536 or length(w) < 65536:
        return BAD
    put(o, 48, 32768)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 7:
        return BAD
    mode_node = 64 + get(w, 88) * 72
    status_node = next(w, mode_node)
    status = budget_integer(s, w, status_node, 1, 4)
    mode = budget_integer(s, w, mode_node, FIRST_MODE, LAST_MODE)
    if mode == NONE or status != observed_status(mode):
        return BAD
    scope = next(w, status_node)
    profile = next(w, scope)
    installation = next(w, profile)
    selection = next(w, installation)
    image = next(w, selection)
    if scope_valid(s, w, scope, mode) == False or profile_valid(w, profile) == False or installation_valid(w, installation) == False:
        return BAD
    if digest_text(w, selection, False) == False or digest_text(w, image, False) == False:
        return BAD
    at = finding_common(o, 16)
    at = finding_assumptions(o, at, mode)
    at = finding_checker_begin(o, at)
    at = copy_value(s, w, o, installation, at)
    at = checker_method(o, at, mode)
    at = copy_value(s, w, o, image, at)
    at = checker_native(o, at, mode)
    at = copy_value(s, w, o, selection, at)
    at = finding_domain(o, at, mode)
    at = copy_value(s, w, o, profile, at)
    at = finding_property(o, at, mode)
    at = copy_value(s, w, o, scope, at)
    obligations = choose(mode == 11 or mode == 12, mode - 5, choose(mode == 10, 5, status))
    if mode == 13 or mode == 14:
        obligations = mode - 5
    at = finding_obligations(o, at)
    if mode != 13 and mode != 14:
        at = finding_no_refinement(o, at)
    at = finding_remaining(o, finding_common_tail(o, at), obligations)
    at = copy_value(s, w, o, profile, at)
    store(o, at, 125)
    put(o, 0, FINDING)
    put(o, 8, at + 1 - 16)
    return at + 1

def scope_valid(s:readbuf, w:mutbuf, scope:u64, mode:u64) -> bool:
    if is_object(w, scope) == False or digest_text(w, lookup(w, scope, K_candidate_core_sha256), False) == False:
        return False
    if mode == 7:
        return True
    if mode == 8:
        return canonical_subject(w, lookup(w, scope, K_kind))
    if mode == 10:
        return plan_subject(w, lookup(w, scope, K_kind))
    if mode >= 11:
        return native_subject(w, lookup(w, scope, K_kind))
    base = lookup(w, scope, K_base_core_sha256)
    if digest_text(w, base, False) == False:
        return False
    if mode == 1:
        return equal_span(s, w, base, lookup(w, scope, K_candidate_core_sha256))
    return True

def profile_valid(w:mutbuf, profile:u64) -> bool:
    if is_object(w, profile) == False or get(w, profile + 32) != 2:
        return False
    name = lookup(w, profile, K_id)
    if name == NONE or get(w, name) != 4 or get(w, name + 32) == 0:
        return False
    return digest_text(w, lookup(w, profile, K_sha256), False)

def installation_valid(w:mutbuf, installation:u64) -> bool:
    if is_object(w, installation) == False or get(w, installation + 32) != 4:
        return False
    key = K_worker_sha256
    while key <= K_native_helpers_sha256:
        if digest_text(w, lookup(w, installation, key), False) == False:
            return False
        key = key + 1
    return True
'''


def json_wire(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True)


def proof_items(items):
    return json_wire([{'id': ident, 'statement': text} for ident, text in items])


def branching_renderer(name, values, argument='mode'):
    unique = tuple(dict.fromkeys(values.values()))
    distinct = {value: index for index, value in enumerate(unique)}
    lines = [f'def {name}(o:mutbuf, at:u64, {argument}:u64) -> u64:']
    modes = tuple(values)
    for value, index in tuple(distinct.items())[:-1]:
        condition = ' or '.join(f'{argument} == {key}' for key in modes if values[key] == value)
        lines.extend((f'    if {condition}:', f'        return {name}_{index}(o, at)'))
    lines.append(f'    return {name}_{len(distinct) - 1}(o, at)')
    for value, index in distinct.items():
        lines.append(literal(f'{name}_{index}', value.encode('ascii')).replace('state_put(', 'put('))
    return '\n'.join(lines)


def source_program(*, machine=False):
    first, last = (13, 18) if machine else (1, 12)
    policy = POLICY
    if not machine:
        policy = policy.replace('choose(mode == 11 or mode == 12, mode - 5,',
                                'choose(mode >= 11, mode - 5,')
        policy = policy.replace(
            '    if mode == 13 or mode == 14:\n        obligations = mode - 5\n'
            '    at = finding_obligations(o, at)\n'
            '    if mode != 13 and mode != 14:\n        at = finding_no_refinement(o, at)\n'
            '    at = finding_remaining(o, finding_common_tail(o, at), obligations)',
            '    at = finding_remaining(o, finding_obligations(o, at), obligations)',
        )
    statuses = ['def observed_status(mode:u64) -> u64:']
    additions, methods, names, domains, properties = {}, {}, {}, {}, {}
    for mode in range(first, last + 1):
        claim, status, method, domain = OUTCOMES[mode - 1]
        statuses.extend((f'    if mode == {mode}:', f'        return {STATUS_IDS[status]}'))
        assumptions = []
        if claim == 'behavior_equivalence':
            assumptions.append(BEHAVIOR_ASSUMPTION)
        if method == 'finite_domain':
            assumptions.append(FINITE_ASSUMPTION)
        if method == 'checked_explicit_machine_choices':
            assumptions.extend(LAYOUT_ASSUMPTIONS)
        if method == 'complete_native_rederivation':
            assumptions.append(ENCODING_ASSUMPTION)
        if method == MACHINE_METHOD:
            assumptions.append(MACHINE_ASSUMPTION)
        additions[mode] = ',' + proof_items(assumptions)[1:-1] if assumptions else ''
        checker = NATIVE_CORE_CHECKER if method == 'core_admission' else EVIDENCE_ROLE
        if 13 <= mode <= 15:
            checker = 'hia-safe-core-prove'
        methods[mode] = ',"method":' + json_wire(method) + ',"name":' + json_wire(checker) + ',"native":{"image_sha256":'
        names[mode] = ',"profile":' + json_wire(CHECKER_PROFILE) + '},"native_selection_sha256":'
        domains[mode] = (',"solver":null},"claim":' + json_wire(claim) + ',"domain":' +
                         json_wire(domain) + ',"execution_authority_granted":false,"global_safety_proved":false,"profile":')
        property_key = SAFE_CORE_METHOD if mode >= 13 else method
        properties[mode] = (',"property":' + json_wire({'id': claim, 'statement': _PROPERTIES[property_key]}) +
                            ',"schema":' + json_wire(PROOF_SCHEMA) + ',"status":' + json_wire(status) + ',"subject":')
    statuses.append('    return 0')
    obligations = {1: '],"validator":'}
    for status, ident in STATUS_IDS.items():
        if status != 'proved':
            item = ('requested_property', f'The requested property is not established; this result is {status} and cannot satisfy a required proof.')
            obligations[ident] = ',' + proof_items((item,))[1:] + ',"validator":'
    obligations[5] = ',' + proof_items((LAYOUT_OBLIGATION,))[1:] + ',"validator":'
    obligations[6] = ',' + proof_items((ENCODING_OBLIGATION,))[1:] + ',"validator":'
    obligations[7] = ',' + proof_items((ENCODING_OBLIGATION, REFUTED_OBLIGATION))[1:] + ',"validator":'
    obligations[8] = ',' + proof_items((MACHINE_OBLIGATION,))[1:] + ',"validator":'
    obligations[9] = ',' + proof_items((MACHINE_OBLIGATION, REFUTED_OBLIGATION))[1:] + ',"validator":'
    obligations = {key: value for key, value in obligations.items()
                   if key in ((3, 4, 8, 9) if machine else range(1, 8))}
    common = COMMON_OBLIGATIONS[:2] if machine else COMMON_OBLIGATIONS
    common_suffix = (
        literal('finding_no_refinement', (',' + proof_items(COMMON_OBLIGATIONS[2:3])[1:-1]).encode('ascii'))
        .replace('state_put(', 'put('),
        literal('finding_common_tail', (',' + proof_items(COMMON_OBLIGATIONS[3:])[1:-1]).encode('ascii'))
        .replace('state_put(', 'put('),
    ) if machine else ()
    constants = {f'K_{key}': index for index, key in enumerate(FIELDS, 1)}
    constants.update(FINDING=int.from_bytes(b'HIAVFN01', 'little'), NONE=(1 << 64) - 1, BAD=4294967293,
                     FIRST_MODE=first, LAST_MODE=last)
    source = '\n'.join((policy, '\n'.join(statuses), key_table(FIELDS),
                        literal_match('canonical_subject', 'canonical_lowering'),
                        literal_match('plan_subject', 'agent_machine_plan'),
                        literal_match('native_subject', 'native_artifact'),
                        *(branching_renderer(name, values) for name, values in (
                            ('finding_assumptions', additions), ('checker_method', methods), ('checker_native', names),
                            ('finding_domain', domains), ('finding_property', properties))),
                        literal('finding_common', ('{"assumptions":' + proof_items((COMMON_ASSUMPTION,))[:-1]).encode('ascii')
                               ).replace('state_put(', 'put('),
                        literal('finding_checker_begin', b'],"checker":{"auxiliary_checker_sha256":null,"installation":'
                               ).replace('state_put(', 'put('),
                        literal('finding_obligations',
                                (',"unproved_obligations":' + proof_items(common)[:-1]).encode('ascii')
                               ).replace('state_put(', 'put('),
                        *common_suffix,
                        branching_renderer('finding_remaining', obligations, 'status'),
                        *(function(CONTEXT, name) for name in ('copy_value', 'digest_text', 'budget_integer', 'equal_span')),
                        *(function(VERIFICATION, name) for name in ('is_object', 'next')),
                        WIRE_HELPERS.split('\ndef signed_id', 1)[0]))
    return re.sub(r'\b(' + '|'.join(constants) + r')\b',
                  lambda match: str(constants[match[0]]), source) + '\n' + json_decoder(wire_spans=True)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
    MACHINE_SOURCE.write_text(render_assembly(document(source_program(machine=True), MACHINE_SOURCE.stem)), encoding='utf-8')
