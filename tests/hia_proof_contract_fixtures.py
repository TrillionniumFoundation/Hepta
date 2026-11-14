"""New recovery differential corpus; exact 4b oracle is separate from runtime.

The controlled rows label external checker observations explicitly. Real solver,
SQLite, proof production and receipt consumption remain the unchanged original
22 + 18 caller gate, which is run separately.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import ModuleType

from hepta import hia_proof_contract as api

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_proof_contract_original_v78.py.txt'
ORIGINAL_SHA = '126f24922e1a652efeb317a512b0a6e082dbe0b215a51e1b75c7399095f54539'
ENTRIES = ('_item', '_require', '_safe_core_method', 'proof_subject', '_method',
           'proof_result', 'assumptions_document', 'proof_contract_description')


def reference_module():
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA:
        raise AssertionError('exact original eight-function oracle changed')
    module = ModuleType('hepta._proof_contract_recovery_reference')
    module.__package__ = 'hepta'
    exec(compile(raw, str(ORIGINAL), 'exec'), vars(module))
    return module


def subject(kind='core', *, base=True):
    return {'kind': kind, 'candidate_core_sha256': 'c' * 64,
            'base_core_sha256': 'c' * 64 if base else None,
            'base_program': {'kind': 'program', 'sha256': 'c' * 64} if base else None,
            'native_artifact': {'kind': 'native', 'sha256': 'e' * 64},
            'build_receipt': {'kind': 'build', 'sha256': 'b' * 64}}


def record():
    return {'subject': {'kind': 'core', 'details': [1, 2]}, 'context': {'sha256': '0' * 64},
            'candidate': {'sha256': 'c' * 64}, 'candidate_core_sha256': 'c' * 64,
            'base_program': {'sha256': 'c' * 64}, 'base_core_sha256': 'c' * 64}


def safe_core_case(status, *, validation=True):
    from hepta import hia_safe_core as safe
    import z3
    s = subject('native_artifact')
    identity = safe._checker_source_identity()
    binding = {'candidate_core_sha256': s['candidate_core_sha256'],
               'native_artifact': s['native_artifact'], 'build_receipt': s['build_receipt'],
               'final_image_sha256': s['native_artifact']['sha256'],
               'object_artifact': {'sha256': 'a' * 64}, 'object_sha256': 'a' * 64,
               'output_kind': 'shared', 'foreign_buffer_exports': [], 'entry_symbols': ['f'],
               'input_sha256': 'd' * 64}
    e = {'method': api.SAFE_CORE_METHOD, 'outcome': status, 'profile': safe.ARTIFACT_PROFILE,
         'service_profile': api.SAFE_CORE_SERVICE_PROFILE, 'artifact_binding': binding,
         'source_identity': identity, 'checker_sha256': api.digest(identity),
         'validation': None, 'reason': 'controlled external checker observation',
         'solver': None, 'deadline_met': True, 'native_checker_selection': {}}
    if not validation:
        return s, e
    solver = safe._solver_identity(z3)
    rows = [{'name': name, 'expected': expected, 'result': expected,
             'query_sha256': 'f' * 64, 'query_file': f'{index:02d}-{name}.smt2'}
            for index, (name, expected) in enumerate(safe.ARTIFACT_OBLIGATIONS)]
    if status == 'refuted':
        stop = next(index for index, row in enumerate(rows) if index >= 1 and row['expected'] == 'unsat')
        rows = rows[:stop + 1]; rows[-1]['result'] = 'sat'
        e['counterexample'] = {'obligation': rows[-1]['name'], 'abi_words': [0], 'initial_rsp': 4096}
    raw_subject = {'core_sha256': s['candidate_core_sha256'], 'input_sha256': 'd' * 64,
                   'object_sha256': 'a' * 64, 'final_image_sha256': 'e' * 64,
                   'entry_symbol': 'f', 'foreign_buffer_exports': []}
    e['solver'] = solver
    e['validation'] = {
        'schema': safe.SCHEMA, 'profile': safe.ARTIFACT_PROFILE, 'artifact_input_profile': safe.ARTIFACT_PROFILE,
        'validation_mode': 'independent_supplied_bytes', 'subject': raw_subject,
        'property': safe.ARTIFACT_PROPERTY, 'core_sha256': raw_subject['core_sha256'],
        'input_sha256': raw_subject['input_sha256'], 'function': 'f', 'foreign_buffer_exports': [],
        'backend_implementation_sha256': None, 'source_identity': identity,
        'checker': {'name': api._CHECKERS[api.SAFE_CORE_METHOD], 'source_identity': identity,
                    'native_selection': {}, 'solver': solver, 'producer_reemission_used': False},
        'assumptions': safe.ASSUMPTIONS, 'limits': safe.LIMITS,
        'unproved_obligations': safe.UNPROVED_OBLIGATIONS,
        'image_binding': {'object_sha256': 'a' * 64, 'final_image_sha256': 'e' * 64, 'entry_symbol': 'f'},
        'obligations': rows, 'solver': solver, 'ok': status == 'proved', 'complete': status == 'proved',
        'status': 'smt_validated' if status == 'proved' else status,
        'claims': safe.CLAIMS if status == 'proved' else {},
    }
    return s, e


def cases():
    rows = []
    def add(label, name, *args):
        rows.append((label, name, args))
    add('item', '_item', 'identity', {'statement': [1]})
    add('require-true', '_require', True, 'allowed')
    add('require-false', '_require', False, 'controlled rejection')
    add('subject', 'proof_subject', record(), {'target': ['x86_64']})
    add('description', 'proof_contract_description')
    add('assumptions', 'assumptions_document',
        {'subject': {'a': 1}, 'property': {}, 'profile': {}, 'checker': {}, 'assumptions': []})
    methods = [
        ('core', 'core_admission', 'proved', subject(),
         {'checker': api._CHECKERS['core_admission'], 'core_sha256': 'c' * 64}),
        ('core-reject', 'core_admission', 'unknown', subject(), {}),
        ('identity', 'behavior_equivalence', 'proved', subject(),
         {'method': 'canonical_core_identity', 'base_sha256': 'c' * 64,
          'candidate_sha256': 'c' * 64, 'all_inputs': True}),
        ('finite-proved', 'behavior_equivalence', 'proved', subject(),
         {'method': 'finite_domain', 'checked': 4, 'required': 4, 'complete': True,
          'all_inputs_in_declared_widths': True, 'base_sha256': 'c' * 64,
          'candidate_sha256': 'c' * 64, 'transcript_sha256': 't'}),
        ('finite-refuted', 'behavior_equivalence', 'refuted', subject(),
         {'method': 'finite_domain', 'checked': 1, 'required': 4,
          'counterexample': [0], 'before': 0, 'after': 1}),
        ('finite-unknown', 'behavior_equivalence', 'unknown', subject(),
         {'method': 'finite_domain', 'checked': 1, 'required': 4, 'complete': False}),
        ('finite-bool-count', 'behavior_equivalence', 'proved', subject(),
         {'method': 'finite_domain', 'checked': True, 'required': 4}),
        ('budget', 'behavior_equivalence', 'unknown', subject(), {'method': 'context_budget_exhausted'}),
        ('no-base', 'behavior_equivalence', 'proved', subject(base=False), {}),
        ('compositional', 'behavior_equivalence', 'proved', subject(),
         {'schema': 'hepta.hia.optimization-verification.v1', 'status': 'verified',
          'base_sha256': 'c' * 64, 'candidate_sha256': 'c' * 64, 'checker_sha256': 'k',
          'solver': {'name': 'z3', 'version': 'controlled', 'binding_sha256': 'b', 'library_sha256': 'l'},
          'claims': {'core_scalar_effect_equivalence_checked': True},
          'resource_delta': {'resource_trace_equivalence_checked': True},
          'obligations': [{'result': 'unsat'}, {'result': 'unsat'}]}),
        ('canonical', 'lowering_refinement', 'unsupported', subject('canonical_lowering'), {'reason': 'profile'}),
        ('plan', 'lowering_refinement', 'proved', subject('agent_machine_plan'),
         {'method': 'checked_explicit_machine_choices', 'core_sha256': 'c' * 64,
          'plan': {'core_sha256': 'c' * 64}}),
        ('encoding-proved', 'encoding_check', 'proved', subject('native_artifact'),
         {'method': 'complete_native_rederivation', 'actual_sha256': 'e' * 64,
          'bytes_equal': True, 'object_identity_equal': True}),
        ('encoding-refuted', 'encoding_check', 'refuted', subject('native_artifact'),
         {'method': 'complete_native_rederivation', 'actual_sha256': 'e' * 64,
          'bytes_equal': False, 'object_identity_equal': True}),
        ('unknown-property', 'not-a-property', 'proved', subject(), {}),
        ('not-an-object', 'core_admission', 'proved', subject(), []),
    ]
    for label, claim, status, s, evidence in methods:
        add('method-' + label, '_method', claim, status, s, evidence)
        if type(evidence) is dict:
            evidence = dict(evidence, native_checker_selection={})
            add('result-' + label, 'proof_result', claim, status, 'controlled domain', s, {}, {}, evidence, ())
    for status in ('proved', 'refuted', 'unknown'):
        s, e = safe_core_case(status)
        add('safe-' + status, '_safe_core_method', status, s, e)
        add('result-safe-' + status, 'proof_result', 'lowering_refinement', status,
            api.SAFE_CORE_DOMAIN, s, {}, {}, e, ())
    for status in ('unknown', 'unsupported'):
        s, e = safe_core_case(status, validation=False)
        add('safe-no-validation-' + status, '_safe_core_method', status, s, e)
    s, e = safe_core_case('proved')
    for label, mutation in (
        ('reordered', lambda value: value['validation']['obligations'].reverse()),
        ('invalid-query', lambda value: value['validation']['obligations'][0].update(query_file='wrong')),
        ('wrong-result', lambda value: value['validation']['obligations'][-1].update(result='sat')),
        ('missing-solver', lambda value: value.update(solver={})),
    ):
        bad = deepcopy(e); mutation(bad)
        add('safe-reject-' + label, '_safe_core_method', 'proved', deepcopy(s), bad)
    return rows


def call_reference(module, name, arguments):
    if name == 'proof_result':
        return module.proof_result(**dict(zip(('claim', 'status', 'domain', 'subject', 'profile',
                                               'installation', 'evidence', 'held_native_owners'), arguments)))
    return getattr(module, name)(*arguments)


def observe(call):
    try:
        return {'kind': 'return', 'value': call()}
    except BaseException as error:
        return {'kind': 'raise', 'type': type(error).__module__ + '.' + type(error).__qualname__,
                'args': error.args, 'message': str(error),
                'cause': None if error.__cause__ is None else type(error.__cause__).__qualname__,
                'context': None if error.__context__ is None else type(error.__context__).__qualname__,
                'suppress_context': error.__suppress_context__}
