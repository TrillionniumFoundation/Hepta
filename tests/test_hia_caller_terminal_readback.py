"""Independent source-admission controls; never replace the complete112 caller reader."""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from tools import read_hia_store_file_capture_callers as reader

ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = 'tests/test_hia_native_transport_failures.py'
DELIVERY = 'tests/test_hia_native_delivery.py'
EVALUATION = 'tests/test_hia_evaluation_native.py'
WORKER = 'tests/test_hia_worker_native_helpers.py'
PAIR_PROOF = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
EVALUATION_PROOF = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
NATIVE_ORIGINAL = 'tests/fixtures/native_delivery_original_9c46166.json'
STORE_ORIGINAL = 'tests/fixtures/store_native_delivery_original_c019.json'
EMISSION_ORIGINAL = 'tests/fixtures/hia_emission_original_73f1634/original-freeze.json'
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
FIXED = {
    'tests/fixtures/caller_deadline_diagnostics_v1.json': {
        'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'},
    EMISSION_ORIGINAL: {'bytes': 59973, 'sha256': 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048'},
    NATIVE_ORIGINAL: {'bytes': 71708, 'sha256': 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'},
    STORE_ORIGINAL: {'bytes': 173802, 'sha256': '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'},
    PAIR_PROOF: {'bytes': 38004, 'sha256': '15f48d98210006523a800be1a743a7f6ce8e427838fc24d157d9bf317d680957'},
    EVALUATION_PROOF: {'bytes': 16316, 'sha256': '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'},
}

STATES = (
    ('legacy-pair-and-evaluation', 'EXACT_LEGACY_PAIR', ()),
    ('terminal-pair-and-legacy-evaluation', 'EXACT_TERMINAL_V2_PAIR', (TRANSPORT,)),
    ('terminal-pair-and-evaluation', 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2',
     (TRANSPORT, EVALUATION)),
)

INVENTORY = EMISSION_ORIGINAL
PAIR = PAIR_PROOF
EVAL_PROOF = EVALUATION_PROOF
REGISTRY = 'hepta/hia_native_helpers.py'
FIXED[REGISTRY] = {'bytes': 23966, 'sha256': 'ee84fb3f778adcab884906cc7c41c52adecdd1f5ed794da9f4d49a2a1cda5b90'}
BAD_ROOTS = (
    'transport-old-delivery-new', 'transport-new-delivery-old', 'evaluation-new-old-pair',
    'transport-extra-byte', 'delivery-extra-byte', 'evaluation-extra-byte',
    'caller-authority-extra-byte', 'native-authority-extra-byte', 'store-authority-extra-byte',
    'pair-provenance-extra-byte', 'evaluation-provenance-extra-byte',
    'unreviewed-caller-extra-byte', 'helper-count-unrelated-byte', 'helper-registry-lost-owner',
    'caller-transport-pin-refreshed', 'caller-evaluation-pin-refreshed',
    'caller-original-record-omitted', 'caller-production-record-added',
    'caller-symlink', 'caller-directory', 'caller-missing',
)
BAD_INVERSES = (
    'raw-byte', 'old-pin', 'current-pin', 'missing-splice', 'duplicate-splice',
    'old-offset', 'new-offset', 'boolean-old-offset', 'boolean-new-offset',
    'overlap-old', 'overlap-new', 'empty-hex', 'uppercase-hex', 'odd-hex',
)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                               indent=2) + '\n', encoding='utf-8')


REGISTRY_CURRENT = {'bytes': 24300, 'sha256': 'b3a84910ad6acc115b21955a727537ed45623512af1f7ca92e7a823fb8e570bc'}
REGISTRY_OLD_BRANCH = b"        if type(record) is dict and record.get('schema') == 'hepta.hia.native-helpers.v5':\n"
REGISTRY_V6_BRANCH = b"        if type(record) is dict and record.get('schema') == 'hepta.hia.native-helpers.v6':\n            _MECHANICAL_SELECTED = True\n            from .hia_native_carrier_worker_bundle import NativeCarrierWorkerBinding\n            binding = NativeCarrierWorkerBinding(captured, expected_sha256)\n            _MECHANICAL_SCOPE = binding\n        elif type(record) is dict and record.get('schema') == 'hepta.hia.native-helpers.v5':\n"

def registry_control_source(raw):
    """Stage the exact retained registry for the unchanged original63 domain."""
    if type(raw) is not bytes:
        raise ValueError('registry preparation requires complete immutable bytes')
    if pin(raw) == FIXED[REGISTRY]:
        return raw
    if pin(raw) != REGISTRY_CURRENT or raw.count(REGISTRY_V6_BRANCH) != 1:
        raise ValueError('unreviewed registry cannot seed original controls')
    original = raw.replace(REGISTRY_V6_BRANCH, REGISTRY_OLD_BRANCH, 1)
    if (pin(original) != FIXED[REGISTRY] or original.count(REGISTRY_OLD_BRANCH) != 1
            or original.replace(REGISTRY_OLD_BRANCH, REGISTRY_V6_BRANCH, 1) != raw):
        raise ValueError('complete registry inverse or forward replay differs')
    return original


class CallerTerminalReadbackSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get('HEPTA_HIA_CALLER_TERMINAL_READBACK_SOURCE_EVIDENCE')
        cls._temporary = None
        if configured is None:
            cls._temporary = tempfile.TemporaryDirectory(prefix='hia-caller-reader-evidence-')
            cls.evidence = Path(cls._temporary.name)
        else:
            if configured == '':
                raise ValueError('empty explicit caller reader evidence directory')
            cls.evidence = Path(configured)
            cls.evidence.mkdir(parents=True, exist_ok=False)
        cls.seed = {name: (ROOT / name).read_bytes() for name in FIXED}
        cls.actual_registry = cls.seed[REGISTRY]
        cls.seed[REGISTRY] = registry_control_source(cls.actual_registry)
        for name, expected in FIXED.items():
            if pin(cls.seed[name]) != expected:
                raise AssertionError('fixed reader control source differs: ' + name)
        cls.original = json.loads(cls.seed[INVENTORY])
        cls.records = {row['path']: row['sha256'] for row in cls.original['callers'].values()}
        if len(cls.records) != 17:
            raise AssertionError('original17 reader control inventory differs')
        for name in (*cls.records, DELIVERY):
            cls.seed[name] = (ROOT / name).read_bytes()
        for name, expected in CURRENT.items():
            if pin(cls.seed[name]) != expected:
                raise AssertionError('reviewed current reader source differs: ' + name)
        cls.actual_sources = {**cls.seed, REGISTRY: cls.actual_registry}
        cls.late_paths = sorted(cls.seed)
        cls.planned = (['accept/' + row[0] for row in STATES]
                       + ['refuse/' + name for name in BAD_ROOTS]
                       + ['late-drift/' + name for name in cls.late_paths]
                       + ['inverse-refusal/' + name for name in BAD_INVERSES])
        if len(cls.seed) != 25 or len(cls.planned) != 63 or len(set(cls.planned)) != 63:
            raise AssertionError('complete independent reader control inventory differs')
        cls.started, cls.stopped, cls.actual = [], [], []
        write_json(cls.evidence / 'planned.json', {
            'schema': 'hepta.hia.caller-terminal-readback-controls-plan.v1',
            'ordered_ids': cls.planned, 'count': 63, 'source_methods': 2,
            'positive': 3, 'bad_roots': 21, 'captured_file_drifts': 25, 'inverse_refusals': 14,
            'ordinary112_replaced': False, 'native_or_cold_result_inferred': False})
        # Construct complete old source data without calling the reader's inverse.
        cls.legacy = {}
        pair = json.loads(cls.seed[PAIR])
        for name in (TRANSPORT, DELIVERY):
            item = pair['files'][name]
            raw = cls.seed[name]
            at = item['offset']
            before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
            if raw[at:at + len(after)] != after:
                raise AssertionError('pair data splice differs')
            cls.legacy[name] = raw[:at] + before + raw[at + len(after):]
        raw = cls.seed[EVALUATION]
        cls.evaluation_record = json.loads(cls.seed[EVAL_PROOF])['record']
        for item in reversed(cls.evaluation_record['splices']):
            at = item['new_offset']
            before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
            if raw[at:at + len(after)] != after:
                raise AssertionError('evaluation data splice differs')
            raw = raw[:at] + before + raw[at + len(after):]
        cls.legacy[EVALUATION] = raw
        if {name: pin(raw) for name, raw in cls.legacy.items()} != OLD:
            raise AssertionError('independent controls did not restore complete old data')
        cls.code = {name: (ROOT / name).read_bytes() for name in (
            'tools/read_hia_store_file_capture_callers.py',
            'tests/test_hia_caller_terminal_readback.py')}
        write_json(cls.evidence / 'inputs.json', {
            'schema': 'hepta.hia.caller-terminal-readback-controls-inputs.v1',
            'source_root': str(ROOT), 'actual_sources': {n: pin(r) for n, r in cls.actual_sources.items()},
            'control_seed_sources': {n: pin(r) for n, r in cls.seed.items()},
            'registry_control_preparation': 'EXACT_OLD_LITERAL_OR_SINGLE_V6_BRANCH_INVERSE',
            'control_code': {n: pin(r) for n, r in cls.code.items()},
            'restored_originals': OLD, 'copied_test_execution': False})

    @classmethod
    def tearDownClass(cls):
        drift = []
        for name, raw in {**cls.actual_sources, **cls.code}.items():
            try:
                same = (ROOT / name).read_bytes() == raw
            except OSError:
                same = False
            if not same:
                drift.append(name)
        complete = (cls.started == cls.planned and cls.stopped == cls.planned
                    and [row['id'] for row in cls.actual] == cls.planned
                    and all(row['status'] == 'PASS' for row in cls.actual))
        write_json(cls.evidence / 'report.json', {
            'schema': 'hepta.hia.caller-terminal-readback-controls.v1',
            'status': 'PASS' if complete and not drift else 'HOLD',
            'planned': cls.planned, 'started': cls.started, 'stopped': cls.stopped,
            'actual': cls.actual, 'complete_ordered_ids': complete,
            'source_stable': not drift, 'source_drift': drift,
            'scope': 'SOURCE_ADMISSION_AND_RAW_CAPTURE_CONTROLS_ONLY',
            'ordinary112_replaced': False, 'whole_native_qualification': False})
        if cls._temporary is not None:
            cls._temporary.cleanup()
        if not complete or drift:
            raise AssertionError('complete independent reader controls or source custody differ')

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

    def test_01_three_complete_original_source_states_and_old_return_api(self):
        for state, expected_state, changed in STATES:
            control_id = 'accept/' + state
            with self.subTest(id=control_id), self.observed(control_id) as detail, \
                    self.private_root(state) as root:
                captured, proof = reader.Captures(), []
                actual = reader.original_callers(root, captured, terminal_evidence=proof)
                self.assertIs(type(actual), tuple)
                self.assertEqual(len(actual), 4)
                original, planned, sources, adjustments = actual
                self.assertEqual(original, self.original)
                self.assertEqual(planned, self.original['ordinary_ordered_ids'])
                self.assertEqual(len(planned), 112)
                self.assertEqual(sources, {
                    name: pin((root / name).read_bytes())['sha256'] for name in self.records})
                self.assertEqual(adjustments, [{
                    'path': WORKER, 'original_sha256': self.records[WORKER],
                    'current_sha256': pin(self.seed[WORKER])['sha256'],
                    'original_helper_count': 37, 'current_helper_count': 50,
                    'sole_permitted_change': 'one exact registry-count assertion decimal literal',
                    'all_other_source_bytes_unchanged': True}])
                self.assertEqual(len(proof), 1)
                value = proof[0]
                self.assertEqual(value['schema'], 'hepta.hia.caller-terminal-source-readback.v1')
                self.assertEqual(value['state'], expected_state)
                self.assertEqual(value['original_expected_sha256'], self.records)
                self.assertEqual(value['actual_original_source_sha256'], sources)
                self.assertEqual(value['original_source_count'], 17)
                self.assertEqual(value['production_composition_source_count'], 13)
                self.assertEqual(value['production_source_exceptions'], [])
                self.assertEqual(set(value['reviewed_test_source_adjustments']), set(changed))
                diagnostic = value['reviewed_diagnostic_source_adjustments']
                self.assertEqual(set(diagnostic), {'tests/test_hia_agent_native_tools.py'})
                self.assertEqual(diagnostic['tests/test_hia_agent_native_tools.py']['original']['sha256'],
                    self.records['tests/test_hia_agent_native_tools.py'])
                self.assertEqual(diagnostic['tests/test_hia_agent_native_tools.py']['current'],
                    pin(self.seed['tests/test_hia_agent_native_tools.py']))
                self.assertIs(value['producer_or_test_helper_imported'], False)
                self.assertIs(value['terminal_reread_deferred_to_outer_captures'], True)
                self.assertNotIn('terminal_reread_identical', value)
                self.assertIs(value['whole_caller_readback_qualified'], False)
                for name in changed:
                    self.assertEqual(value['reviewed_test_source_adjustments'][name]['original'], OLD[name])
                    self.assertEqual(value['reviewed_test_source_adjustments'][name]['current'], CURRENT[name])
                expected_names = set(self.seed)
                if state == 'legacy-pair-and-evaluation':
                    expected_names.difference_update((PAIR, EVAL_PROOF))
                elif state == 'terminal-pair-and-legacy-evaluation':
                    expected_names.remove(EVAL_PROOF)
                self.assertEqual({path.relative_to(root).as_posix() for path in captured.raw},
                                 expected_names)
                captured.unchanged()
                second = reader.Captures()
                self.assertEqual(reader.original_callers(root, second), actual)
                second.unchanged()
                detail.update({'returned_source_count': len(sources),
                               'returned_original_method_count': len(planned),
                               'registry_adjustments': adjustments, 'terminal_admission': value,
                               'consumed_files': {p.relative_to(root).as_posix(): pin(r)
                                                  for p, r in captured.raw.items()},
                               'complete_raw_capture_reread': True,
                               'old_two_argument_four_result_api_preserved': True})

    def test_02_complete_refusals_all_captured_file_drifts_and_inverse_bad_data(self):
        ordinary = next(name for name in self.records
                        if name not in (TRANSPORT, EVALUATION, WORKER))
        extra_paths = {
            'transport-extra-byte': TRANSPORT, 'delivery-extra-byte': DELIVERY,
            'evaluation-extra-byte': EVALUATION, 'caller-authority-extra-byte': INVENTORY,
            'native-authority-extra-byte': NATIVE_ORIGINAL, 'store-authority-extra-byte': STORE_ORIGINAL,
            'pair-provenance-extra-byte': PAIR, 'evaluation-provenance-extra-byte': EVAL_PROOF,
            'unreviewed-caller-extra-byte': ordinary, 'helper-count-unrelated-byte': WORKER}
        for fault in BAD_ROOTS:
            control_id = 'refuse/' + fault
            with self.subTest(id=control_id), self.observed(control_id) as detail, \
                    self.private_root() as root:
                changed = []
                def replace(name, raw):
                    path = root / name
                    before = path.read_bytes()
                    path.write_bytes(raw)
                    changed.append({'path': name, 'before': pin(before), 'after': pin(raw)})
                if fault == 'transport-old-delivery-new':
                    replace(TRANSPORT, self.legacy[TRANSPORT])
                elif fault == 'transport-new-delivery-old':
                    replace(DELIVERY, self.legacy[DELIVERY])
                elif fault == 'evaluation-new-old-pair':
                    for name in (TRANSPORT, DELIVERY):
                        replace(name, self.legacy[name])
                elif fault in extra_paths:
                    name = extra_paths[fault]
                    replace(name, (root / name).read_bytes() + b'\n')
                elif fault == 'helper-registry-lost-owner':
                    data = 'HELPERS = {\n' + ''.join(
                        '    "test-' + str(i) + '": ("x", "y"),\n' for i in range(36)) + '}\n'
                    replace(REGISTRY, data.encode('ascii'))
                elif fault in ('caller-transport-pin-refreshed', 'caller-evaluation-pin-refreshed',
                               'caller-original-record-omitted', 'caller-production-record-added'):
                    value = json.loads(self.seed[INVENTORY])
                    name = EVALUATION if fault == 'caller-evaluation-pin-refreshed' else TRANSPORT
                    key = next(k for k, row in value['callers'].items() if row['path'] == name)
                    if fault == 'caller-original-record-omitted':
                        del value['callers'][key]
                    elif fault == 'caller-production-record-added':
                        value['callers']['hepta.native.slot_mechanical'] = {
                            'path': 'hepta/native/slot_mechanical.c', 'sha256': '0' * 64,
                            'recorded_ids': []}
                    else:
                        value['callers'][key]['sha256'] = CURRENT[name]['sha256']
                    replace(INVENTORY, (json.dumps(value, sort_keys=True) + '\n').encode('ascii'))
                elif fault in ('caller-symlink', 'caller-directory', 'caller-missing'):
                    path = root / ordinary
                    changed.append({'path': ordinary, 'before': pin(path.read_bytes()),
                                    'after_kind': fault})
                    path.unlink()
                    if fault == 'caller-symlink':
                        os.symlink(root / TRANSPORT, path)
                    elif fault == 'caller-directory':
                        path.mkdir()
                else:
                    raise AssertionError('missing independent reader refusal control')
                proof = []
                with self.assertRaises((ValueError, OSError)) as caught:
                    reader.original_callers(root, reader.Captures(), terminal_evidence=proof)
                self.assertEqual(proof, [])
                detail.update({'mutations': changed, 'refused': True,
                               'error_type': type(caught.exception).__name__,
                               'error': str(caught.exception), 'terminal_proof_count': 0})
        for name in self.late_paths:
            control_id = 'late-drift/' + name
            with self.subTest(id=control_id), self.observed(control_id) as detail, \
                    self.private_root() as root:
                captured, proof = reader.Captures(), []
                reader.original_callers(root, captured, terminal_evidence=proof)
                self.assertEqual(len(captured.raw), 25)
                self.assertEqual(len(proof), 1)
                self.assertIs(proof[0]['terminal_reread_deferred_to_outer_captures'], True)
                self.assertNotIn('terminal_reread_identical', proof[0])
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(raw + b'\n')
                with self.assertRaises(ValueError) as caught:
                    captured.unchanged()
                detail.update({'path': name, 'before': pin(raw), 'after': pin(raw + b'\n'),
                               'source_admission_only_proof_count': 1,
                               'outer_terminal_refused': True,
                               'error': str(caught.exception)})
        for fault in BAD_INVERSES:
            control_id = 'inverse-refusal/' + fault
            with self.subTest(id=control_id), self.observed(control_id) as detail:
                raw = self.seed[EVALUATION]
                before, after = dict(OLD[EVALUATION]), dict(CURRENT[EVALUATION])
                splices = json.loads(json.dumps(self.evaluation_record['splices']))
                if fault == 'raw-byte':
                    raw = bytes((raw[0] ^ 1,)) + raw[1:]
                elif fault == 'old-pin':
                    before['bytes'] += 1
                elif fault == 'current-pin':
                    after['sha256'] = '0' * 64
                elif fault == 'missing-splice':
                    splices.pop()
                elif fault == 'duplicate-splice':
                    splices.append(dict(splices[-1]))
                elif fault == 'old-offset':
                    splices[0]['old_offset'] += 1
                elif fault == 'new-offset':
                    splices[0]['new_offset'] += 1
                elif fault == 'boolean-old-offset':
                    splices[0]['old_offset'] = True
                elif fault == 'boolean-new-offset':
                    splices[0]['new_offset'] = True
                elif fault == 'overlap-old':
                    splices[1]['old_offset'] = splices[0]['old_offset']
                elif fault == 'overlap-new':
                    splices[1]['new_offset'] = splices[0]['new_offset']
                elif fault == 'empty-hex':
                    splices[0]['old_hex'] = ''
                elif fault == 'uppercase-hex':
                    splices[0]['old_hex'] = splices[0]['old_hex'].upper()
                elif fault == 'odd-hex':
                    splices[0]['new_hex'] = splices[0]['new_hex'][:-1]
                else:
                    raise AssertionError('missing inverse refusal control')
                with self.assertRaises(ValueError) as caught:
                    reader.terminal_inverse(raw, before, after, splices)
                detail.update({'actual_raw': pin(raw), 'original_pin_argument': before,
                               'current_pin_argument': after, 'splices_argument': splices,
                               'refused': True, 'error': str(caught.exception)})
        self.assertEqual(len(self.actual), 63)


class NativeCarrierRegistryPreparationSourceTests(unittest.TestCase):
    def test_exact_old_current_and_full_unmodified_helper_registry(self):
        import ast
        current = (ROOT / REGISTRY).read_bytes()
        original = registry_control_source(current)
        self.assertEqual(pin(original), FIXED[REGISTRY])
        self.assertEqual(registry_control_source(original), original)
        expected = original.replace(REGISTRY_OLD_BRANCH, REGISTRY_V6_BRANCH, 1)
        self.assertEqual(pin(expected), REGISTRY_CURRENT)
        self.assertEqual(registry_control_source(expected), original)
        def declared(raw):
            node = next(node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'HELPERS' for target in node.targets))
            return ast.literal_eval(node.args[0] if isinstance(node, ast.Call) else node)
        self.assertEqual(declared(expected), declared(original))
        self.assertEqual(len(declared(expected)), 50)
        for bad in (True, bytearray(expected), expected + b' ', expected[:-1],
                    expected.replace(b'hepta.hia.native-helpers.v6', b'hepta.hia.native-helpers.v7'),
                    expected.replace(REGISTRY_V6_BRANCH, REGISTRY_V6_BRANCH * 2, 1)):
            with self.subTest(type=type(bad).__name__), self.assertRaises(ValueError):
                registry_control_source(bad)
        self.assertEqual((ROOT / REGISTRY).read_bytes(), current)


if __name__ == '__main__':
    unittest.main()
