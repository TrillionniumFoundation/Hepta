"""Complete source-only controls for the five exact terminal caller admissions.

These controls copy file bytes into private roots and call the five actual
admission functions. They do not execute the copied tests, compile an image,
or replace any original caller, Core, Source, Native or delivery gate.
"""
from contextlib import contextmanager, nullcontext
from hashlib import sha256
from importlib import import_module
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_caller_terminal_admission as admission

ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = 'tests/test_hia_native_transport_failures.py'
DELIVERY = 'tests/test_hia_native_delivery.py'
EVALUATION = 'tests/test_hia_evaluation_native.py'
WORKER = 'tests/test_hia_worker_native_helpers.py'
PAIR_PROOF = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
EVALUATION_PROOF = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
NATIVE_ORIGINAL = 'tests/fixtures/native_delivery_original_9c46166.json'
STORE_ORIGINAL = 'tests/fixtures/store_native_delivery_original_c019.json'
BUILD_ORIGINAL = 'tests/fixtures/hia_native_build_admission_callers_aac7550.json'
EMISSION_ORIGINAL = 'tests/fixtures/hia_emission_original_73f1634/original-freeze.json'
PROFILE_ORIGINAL = 'tests/fixtures/hia_store_artifact_profile_callers_73f1634.json'
OLD = {
    TRANSPORT: {'bytes': 32859, 'sha256': '6c9505646078ebc03f4f44b35526d31b5534d9766ffbf408f69b9fc12ee7b484'},
    DELIVERY: {'bytes': 12700, 'sha256': 'cd56657339898843d78f705872be63625395f58479c11f9784e7e0e7ccccd541'},
    EVALUATION: {'bytes': 43338, 'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede'},
}
CURRENT = {
    TRANSPORT: {'bytes': 37466, 'sha256': '6c7dfe5f723a951fe0c24d05f4f52b579149de71c3e112ba735af2c496d9a084'},
    DELIVERY: {'bytes': 13263, 'sha256': '09692f4ce91da30ad3aac0b009e15e520058022cd01af8fdf1a7dd8811aab64b'},
    EVALUATION: {'bytes': 49105, 'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'},
}
AUTHORITIES = {
    BUILD_ORIGINAL: {'bytes': 124039, 'sha256': '262c3df1e051fe52797c91dd053f2d79c0704fe5b20a85f799d6d40c1c4bb2a9'},
    EMISSION_ORIGINAL: {'bytes': 59973, 'sha256': 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048'},
    PROFILE_ORIGINAL: {'bytes': 166078, 'sha256': 'acbb8c221d80788ef96eb4b596c24fc1c3eb410229e605b2f01ef77e5530b7d6'},
    NATIVE_ORIGINAL: {'bytes': 71708, 'sha256': 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'},
    STORE_ORIGINAL: {'bytes': 173802, 'sha256': '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'},
    PAIR_PROOF: {'bytes': 38004, 'sha256': '15f48d98210006523a800be1a743a7f6ce8e427838fc24d157d9bf317d680957'},
    EVALUATION_PROOF: {'bytes': 16316, 'sha256': '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'},
}
GATES = (
    ('build', 'tools.qualify_hia_native_build_admission_callers', BUILD_ORIGINAL, 17, 36),
    ('emission', 'tools.qualify_hia_emission_callers', EMISSION_ORIGINAL, 17, 37),
    ('store', 'tools.qualify_hia_store_artifact_profile_callers', PROFILE_ORIGINAL, 18, 37),
    ('read', 'tools.qualify_hia_service_read_callers', EMISSION_ORIGINAL, 17, 37),
    ('inspection', 'tools.qualify_hia_service_inspection_callers', EMISSION_ORIGINAL, 17, 37),
)
STATES = (
    ('legacy-pair-and-evaluation', 'EXACT_LEGACY_PAIR', ()),
    ('terminal-pair-and-legacy-evaluation', 'EXACT_TERMINAL_V2_PAIR', (TRANSPORT,)),
    ('terminal-pair-and-evaluation', 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2',
     (TRANSPORT, EVALUATION)),
)
NEGATIVES = (
    'transport-old-delivery-new',
    'transport-new-delivery-old',
    'evaluation-new-with-legacy-pair',
    'transport-new-extra-byte',
    'delivery-new-extra-byte',
    'evaluation-new-extra-byte',
    'caller-inventory-extra-byte',
    'native-original-extra-byte',
    'store-original-extra-byte',
    'pair-provenance-extra-byte',
    'evaluation-provenance-extra-byte',
    'unreviewed-caller-extra-byte',
    'helper-count-with-unrelated-byte',
    'argument-transport-pin-refreshed',
    'argument-evaluation-pin-refreshed',
    'argument-original-record-omitted',
    'argument-extra-production-record',
    'terminal-reread-transport-drift',
    'terminal-reread-evaluation-drift',
    'terminal-reread-caller-inventory-drift',
    'terminal-reread-native-authority-drift',
    'terminal-reread-pair-provenance-drift',
    'terminal-reread-evaluation-provenance-drift',
    'terminal-reread-unreviewed-caller-drift',
    'terminal-reread-helper-count-drift',
)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                               indent=2) + '\n', encoding='utf-8')


def source_records(value, kind):
    if kind == 'build':
        return {item['path']: item['sha256'] for item in value['modules'].values()}
    if kind == 'store':
        names = {*value['prior_ordinary_9_modules'], *value['prior_separate_8_modules'],
                 'tests.test_hia_agent_artifact_store_native'}
        return {value['modules'][name]['source']: value['modules'][name]['sha256']
                for name in sorted(names)}
    return {item['path']: item['sha256'] for item in value['callers'].values()}


def gate_argument(value, kind):
    return source_records(value, kind) if kind == 'build' else json.loads(json.dumps(value))


def changed_argument(original, kind, fault):
    value = gate_argument(original, kind)
    target = EVALUATION if fault == 'argument-evaluation-pin-refreshed' else TRANSPORT
    extra_path = 'hepta/native/slot_mechanical.c'
    if kind == 'build':
        if fault == 'argument-original-record-omitted':
            del value[target]
        elif fault == 'argument-extra-production-record':
            value[extra_path] = '0' * 64
        else:
            value[target] = CURRENT[target]['sha256']
        return value
    field, path_field = ('modules', 'source') if kind == 'store' else ('callers', 'path')
    entry = next(name for name, row in value[field].items() if row.get(path_field) == target)
    if fault == 'argument-original-record-omitted':
        if kind == 'store':
            for group in ('prior_ordinary_9_modules', 'prior_separate_8_modules'):
                value[group] = [name for name in value[group] if name != entry]
        else:
            del value[field][entry]
    elif fault == 'argument-extra-production-record':
        name = 'hepta.native.slot_mechanical'
        value[field][name] = {path_field: extra_path, 'sha256': '0' * 64}
        if kind == 'store':
            value['prior_ordinary_9_modules'].append(name)
    else:
        value[field][entry]['sha256'] = CURRENT[target]['sha256']
    return value


class CallerTerminalAdmissionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get('HEPTA_HIA_CALLER_TERMINAL_SOURCE_EVIDENCE')
        cls._temporary_evidence = None
        if configured:
            cls.evidence = Path(configured)
            cls.evidence.mkdir(parents=True, exist_ok=False)
        else:
            cls._temporary_evidence = tempfile.TemporaryDirectory(
                prefix='hia-caller-terminal-source-evidence-')
            cls.evidence = Path(cls._temporary_evidence.name)
        cls.planned = [
            kind + '/accept/' + state[0] for kind, _, _, _, _ in GATES for state in STATES
        ] + [
            kind + '/refuse/' + fault for kind, _, _, _, _ in GATES for fault in NEGATIVES
        ]
        if len(cls.planned) != 140 or len(set(cls.planned)) != 140:
            raise AssertionError('the complete fixed caller control inventory differs')
        cls.started, cls.stopped, cls.actual = [], [], []
        write_json(cls.evidence / 'planned.json', {
            'schema': 'hepta.hia.caller-terminal-source-controls-plan.v1',
            'ordered_ids': cls.planned, 'count': 140,
            'accept_count': 15, 'refusal_count': 125,
            'source_methods': 2, 'original_gate_replacement': False})
        cls.seed = {}
        for name, expected in AUTHORITIES.items():
            raw = (ROOT / name).read_bytes()
            if pin(raw) != expected:
                raise AssertionError('fixed control authority differs: ' + name)
            cls.seed[name] = raw
        cls.originals = {name: json.loads(cls.seed[name])
                         for name in (BUILD_ORIGINAL, EMISSION_ORIGINAL, PROFILE_ORIGINAL)}
        for kind, _, inventory, count, _ in GATES:
            records = source_records(cls.originals[inventory], kind)
            if len(records) != count:
                raise AssertionError('complete original caller source count differs: ' + kind)
            for name in records:
                if name not in cls.seed:
                    cls.seed[name] = (ROOT / name).read_bytes()
        for name, expected in CURRENT.items():
            cls.seed[name] = (ROOT / name).read_bytes()
            if pin(cls.seed[name]) != expected:
                raise AssertionError('reviewed current source differs: ' + name)
        # Build old test bytes as data, independently of the admission implementation.
        pair = json.loads(cls.seed[PAIR_PROOF])
        cls.legacy = {}
        for name in (TRANSPORT, DELIVERY):
            record = pair['files'][name]
            offset = record['offset']
            before, after = bytes.fromhex(record['old_hex']), bytes.fromhex(record['new_hex'])
            raw = cls.seed[name]
            if raw[offset:offset + len(after)] != after:
                raise AssertionError('control pair splice differs: ' + name)
            cls.legacy[name] = raw[:offset] + before + raw[offset + len(after):]
        raw = cls.seed[EVALUATION]
        evaluation = json.loads(cls.seed[EVALUATION_PROOF])['record']
        for record in reversed(evaluation['splices']):
            offset = record['new_offset']
            before, after = bytes.fromhex(record['old_hex']), bytes.fromhex(record['new_hex'])
            if raw[offset:offset + len(after)] != after:
                raise AssertionError('control evaluation splice differs')
            raw = raw[:offset] + before + raw[offset + len(after):]
        cls.legacy[EVALUATION] = raw
        if {name: pin(raw) for name, raw in cls.legacy.items()} != OLD:
            raise AssertionError('complete original test bytes were not restored')
        code_paths = ['tests/hia_caller_terminal_admission.py',
                      'tests/test_hia_caller_terminal_admission.py']
        code_paths += [module.replace('.', '/') + '.py' for _, module, _, _, _ in GATES]
        cls.code = {name: (ROOT / name).read_bytes() for name in code_paths}
        cls.modules = {kind: import_module(module) for kind, module, _, _, _ in GATES}
        write_json(cls.evidence / 'inputs.json', {
            'schema': 'hepta.hia.caller-terminal-source-controls-inputs.v1',
            'actual_source_root': str(ROOT),
            'actual_input_files': {name: pin(raw) for name, raw in cls.seed.items()},
            'actual_control_code': {name: pin(raw) for name, raw in cls.code.items()},
            'original_test_bytes_restored': {name: pin(raw) for name, raw in cls.legacy.items()},
            'copied_source_execution': False})

    @classmethod
    def tearDownClass(cls):
        stable, drift = True, []
        for name, raw in {**cls.seed, **cls.code}.items():
            try:
                same = (ROOT / name).read_bytes() == raw
            except OSError:
                same = False
            if not same:
                stable = False
                drift.append(name)
        complete = (cls.started == cls.planned and cls.stopped == cls.planned
                    and [row['id'] for row in cls.actual] == cls.planned
                    and all(row['status'] == 'PASS' for row in cls.actual))
        write_json(cls.evidence / 'report.json', {
            'schema': 'hepta.hia.caller-terminal-source-controls.v1',
            'status': 'PASS' if complete and stable else 'HOLD',
            'planned': cls.planned, 'started': cls.started, 'stopped': cls.stopped,
            'actual': cls.actual, 'complete_ordered_ids': complete,
            'source_stable': stable, 'source_drift': drift,
            'original_source_inventories_unchanged': True,
            'original_gate_replacement': False, 'production_source_exceptions': [],
            'whole_native_qualification': False})
        if cls._temporary_evidence is not None:
            cls._temporary_evidence.cleanup()
        if not complete or not stable:
            raise AssertionError('complete caller controls or original source custody differ')

    @contextmanager
    def observed(self, control_id):
        cls = type(self)
        if control_id != cls.planned[len(cls.started)]:
            raise AssertionError('caller control order differs')
        cls.started.append(control_id)
        detail = {}
        row = {'id': control_id, 'status': 'RUNNING', 'detail': detail}
        write_json(cls.evidence / 'progress.json', {
            'planned': cls.planned, 'started': cls.started, 'stopped': cls.stopped,
            'actual': cls.actual, 'current': row})
        try:
            yield detail
        except BaseException as error:
            row['status'] = 'FAIL'
            row['error'] = {'module': type(error).__module__, 'name': type(error).__name__,
                            'text': str(error)}
            raise
        else:
            row['status'] = 'PASS'
        finally:
            cls.stopped.append(control_id)
            cls.actual.append(row)
            write_json(cls.evidence / 'progress.json', {
                'planned': cls.planned, 'started': cls.started, 'stopped': cls.stopped,
                'actual': cls.actual})

    @contextmanager
    def private_root(self, state='terminal-pair-and-evaluation'):
        with tempfile.TemporaryDirectory(prefix='hia-caller-terminal-private-') as temporary:
            root = Path(temporary)
            contents = dict(self.seed)
            if state == 'legacy-pair-and-evaluation':
                contents.update(self.legacy)
            elif state == 'terminal-pair-and-legacy-evaluation':
                contents[EVALUATION] = self.legacy[EVALUATION]
            elif state != 'terminal-pair-and-evaluation':
                raise AssertionError('unknown positive control state')
            for name, raw in contents.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            yield root

    def test_01_all_five_original_admissions_and_three_exact_states(self):
        from hepta.hia_native_helpers import HELPERS
        for kind, _, inventory, count, old_count in GATES:
            original = self.originals[inventory]
            records = source_records(original, kind)
            for state, expected_state, changed in STATES:
                control_id = kind + '/accept/' + state
                with self.subTest(id=control_id), self.observed(control_id) as detail, \
                        self.private_root(state) as root:
                    proof = []
                    actual = self.modules[kind].admit_original_sources(
                        root, gate_argument(original, kind), terminal_evidence=proof)
                    self.assertEqual(len(actual), 1)
                    self.assertEqual(actual[0], {
                        'path': WORKER, 'original_sha256': records[WORKER],
                        'current_sha256': pin(self.seed[WORKER])['sha256'],
                        'original_helper_count': old_count, 'current_helper_count': len(HELPERS),
                        'sole_permitted_change': 'one exact registry-count assertion decimal literal',
                        'all_other_source_bytes_unchanged': True})
                    self.assertEqual(len(proof), 1)
                    value = proof[0]
                    self.assertEqual(value['schema'], 'hepta.hia.caller-terminal-source-admission.v1')
                    self.assertEqual(value['authority'], {'path': inventory, **AUTHORITIES[inventory]})
                    self.assertEqual(value['state'], expected_state)
                    self.assertEqual(value['original_source_count'], count)
                    self.assertEqual(value['ordered_consumed_original_sources'], list(records))
                    self.assertEqual(set(value['reviewed_test_source_adjustments']), set(changed))
                    self.assertEqual(value['production_composition_source_count'], 13)
                    self.assertEqual(value['production_source_exceptions'], [])
                    self.assertIs(value['terminal_reread_identical'], True)
                    self.assertIs(value['original_inventory_bytes_unchanged'], True)
                    for name in changed:
                        adjustment = value['reviewed_test_source_adjustments'][name]
                        self.assertEqual(adjustment['path'], name)
                        self.assertEqual(adjustment['original'], OLD[name])
                        self.assertEqual(adjustment['current'], CURRENT[name])
                        self.assertIs(adjustment['production_source_exception'], False)
                        self.assertIs(adjustment['complete_original_inverse_verified'], True)
                    for name in records:
                        self.assertEqual(value['captured_files'][name], pin((root / name).read_bytes()))
                    self.assertEqual(self.modules[kind].admit_original_sources(
                        root, gate_argument(original, kind)), actual)
                    detail.update({'registry_adjustments': actual, 'terminal_admission': value,
                                   'legacy_two_argument_api_preserved': True})

    def test_02_complete_refusal_table_and_terminal_readback_races(self):
        for kind, _, inventory, _, _ in GATES:
            original = self.originals[inventory]
            records = source_records(original, kind)
            ordinary = next(name for name in records
                            if name not in (TRANSPORT, DELIVERY, EVALUATION, WORKER))
            early_paths = {
                'transport-new-extra-byte': TRANSPORT,
                'delivery-new-extra-byte': DELIVERY,
                'evaluation-new-extra-byte': EVALUATION,
                'caller-inventory-extra-byte': inventory,
                'native-original-extra-byte': NATIVE_ORIGINAL,
                'store-original-extra-byte': STORE_ORIGINAL,
                'pair-provenance-extra-byte': PAIR_PROOF,
                'evaluation-provenance-extra-byte': EVALUATION_PROOF,
                'unreviewed-caller-extra-byte': ordinary,
                'helper-count-with-unrelated-byte': WORKER,
            }
            late_paths = {
                'terminal-reread-transport-drift': TRANSPORT,
                'terminal-reread-evaluation-drift': EVALUATION,
                'terminal-reread-caller-inventory-drift': inventory,
                'terminal-reread-native-authority-drift': NATIVE_ORIGINAL,
                'terminal-reread-pair-provenance-drift': PAIR_PROOF,
                'terminal-reread-evaluation-provenance-drift': EVALUATION_PROOF,
                'terminal-reread-unreviewed-caller-drift': ordinary,
                'terminal-reread-helper-count-drift': WORKER,
            }
            for fault in NEGATIVES:
                control_id = kind + '/refuse/' + fault
                with self.subTest(id=control_id), self.observed(control_id) as detail, \
                        self.private_root() as root:
                    argument = gate_argument(original, kind)
                    mutated_path = None
                    before = after = None
                    if fault == 'transport-old-delivery-new':
                        mutated_path = TRANSPORT
                        before = (root / mutated_path).read_bytes()
                        after = self.legacy[TRANSPORT]
                    elif fault == 'transport-new-delivery-old':
                        mutated_path = DELIVERY
                        before = (root / mutated_path).read_bytes()
                        after = self.legacy[DELIVERY]
                    elif fault == 'evaluation-new-with-legacy-pair':
                        for name in (TRANSPORT, DELIVERY):
                            (root / name).write_bytes(self.legacy[name])
                        detail['legacy_pair'] = {name: OLD[name] for name in (TRANSPORT, DELIVERY)}
                    elif fault in early_paths:
                        mutated_path = early_paths[fault]
                        before = (root / mutated_path).read_bytes()
                        after = before + b'\n'
                    elif fault.startswith('argument-'):
                        argument = changed_argument(original, kind, fault)
                        detail['changed_original_argument'] = argument
                    elif fault not in late_paths:
                        raise AssertionError('unimplemented refusal control')
                    if mutated_path is not None:
                        (root / mutated_path).write_bytes(after)
                        detail['mutation'] = {'path': mutated_path, 'before': pin(before),
                                              'after': pin(after)}
                    late_path = late_paths.get(fault)
                    real_finish = admission._CapturedAdmission.finish
                    finish_calls = []
                    def finish_with_real_file_drift(instance):
                        path = root / late_path
                        raw = path.read_bytes()
                        path.write_bytes(raw + b'\n')
                        finish_calls.append({'path': late_path, 'before': pin(raw),
                                             'after': pin(raw + b'\n')})
                        return real_finish(instance)
                    context = (patch.object(admission._CapturedAdmission, 'finish',
                                            finish_with_real_file_drift)
                               if late_path is not None else nullcontext())
                    proof = []
                    with context, self.assertRaises(ValueError) as caught:
                        self.modules[kind].admit_original_sources(
                            root, argument, terminal_evidence=proof)
                    self.assertEqual(proof, [])
                    if late_path is not None:
                        self.assertEqual(len(finish_calls), 1)
                        self.assertIn('captured bytes changed', str(caught.exception))
                    detail.update({'refused': True, 'error_type': type(caught.exception).__name__,
                                   'error_text': str(caught.exception),
                                   'terminal_proof_count': len(proof),
                                   'actual_late_file_mutations': finish_calls})
        self.assertEqual(len(self.actual), 140)


if __name__ == '__main__':
    unittest.main()
