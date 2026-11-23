"""Exact historical caller admission for the reviewed terminal test successors.

This is a test/source gate. It never adds a production source exception, changes
an original inventory, or substitutes adjusted bytes for a file actually read.
The old helper-count checks remain in their five original caller gates.
"""
from hashlib import sha256
import json
from pathlib import Path

FIXTURE = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
FIXTURE_SHA256 = '15f48d98210006523a800be1a743a7f6ce8e427838fc24d157d9bf317d680957'
TRANSPORT = 'tests/test_hia_native_transport_failures.py'
DELIVERY = 'tests/test_hia_native_delivery.py'
PATHS = (TRANSPORT, DELIVERY)
EVALUATION = 'tests/test_hia_evaluation_native.py'
EVALUATION_DEFINITION = 'EvaluationNativeTests.test_actual_installed_worker_replay_process_loss_and_source_pinning'
EVALUATION_FIXTURE = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
EVALUATION_FIXTURE_SHA256 = '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'
EVALUATION_OLD = {'bytes': 43338, 'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede'}
EVALUATION_NEW = {'bytes': 49105, 'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'}
ORIGINALS = {
    'native': ('tests/fixtures/native_delivery_original_9c46166.json', {
        'bytes': 71708, 'sha256': 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'}),
    'store': ('tests/fixtures/store_native_delivery_original_c019.json', {
        'bytes': 173802, 'sha256': '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'}),
}
OLD = {
    TRANSPORT: {'bytes': 32859, 'sha256': '6c9505646078ebc03f4f44b35526d31b5534d9766ffbf408f69b9fc12ee7b484'},
    DELIVERY: {'bytes': 12700, 'sha256': 'cd56657339898843d78f705872be63625395f58479c11f9784e7e0e7ccccd541'},
}


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def _hex(value):
    if type(value) is not str:
        raise ValueError('transport successor patch is not exact text')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('transport successor patch is not hexadecimal') from error
    if raw.hex() != value:
        raise ValueError('transport successor patch is not canonical')
    return raw


def reverse_one(raw, record, original):
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old', 'new', 'definition', 'offset', 'old_hex', 'new_hex'}
            or _canonical(record['old']) != _canonical(original)
            or type(record['new']) is not dict or set(record['new']) != {'bytes', 'sha256'}
            or type(record['new']['bytes']) is not int
            or type(record['new']['sha256']) is not str
            or _pin(raw) != record['new']
            or type(record['offset']) is not int or record['offset'] < 0):
        raise ValueError('transport successor whole-source identity differs')
    before, after = _hex(record['old_hex']), _hex(record['new_hex'])
    at = record['offset']
    if (before == after or not before or not after
            or at + len(after) > len(raw) or raw[at:at + len(after)] != after):
        raise ValueError('transport successor exact definition patch differs')
    restored = raw[:at] + before + raw[at + len(after):]
    if _pin(restored) != original:
        raise ValueError('transport successor does not restore the complete original')
    return restored


def reverse_evaluation(raw, record):
    """Restore the full fixed original through seven exact, disjoint splices."""
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old', 'new', 'definition', 'splices'}
            or _canonical(record['old']) != _canonical(EVALUATION_OLD)
            or _canonical(record['new']) != _canonical(EVALUATION_NEW)
            or record['definition'] != EVALUATION_DEFINITION
            or _pin(raw) != EVALUATION_NEW
            or type(record['splices']) is not list or len(record['splices']) != 7):
        raise ValueError('evaluation successor whole-source identity differs')
    entries = []
    old_end = new_end = displacement = 0
    for item in record['splices']:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('evaluation successor splice positions differ')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        if (not before or not after or before == after
                or at + displacement != target
                or target + len(after) > len(raw)
                or raw[target:target + len(after)] != after):
            raise ValueError('evaluation successor exact splice differs')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    restored = raw
    for at, target, before, after in reversed(entries):
        restored = restored[:target] + before + restored[target + len(after):]
    if _pin(restored) != EVALUATION_OLD:
        raise ValueError('evaluation successor does not restore the complete original')
    replay = restored
    for at, target, before, after in reversed(entries):
        if replay[at:at + len(before)] != before:
            raise ValueError('evaluation successor original splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise ValueError('evaluation successor forward replay differs')
    return restored



CALLER_AUTHORITIES = {
    'tests/fixtures/hia_native_build_admission_callers_aac7550.json': {
        'bytes': 124039, 'sha256': '262c3df1e051fe52797c91dd053f2d79c0704fe5b20a85f799d6d40c1c4bb2a9',
        'kind': 'build', 'sources': 17},
    'tests/fixtures/hia_emission_original_73f1634/original-freeze.json': {
        'bytes': 59973, 'sha256': 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048',
        'kind': 'emission', 'sources': 17},
    'tests/fixtures/hia_store_artifact_profile_callers_73f1634.json': {
        'bytes': 166078, 'sha256': 'acbb8c221d80788ef96eb4b596c24fc1c3eb410229e605b2f01ef77e5530b7d6',
        'kind': 'store', 'sources': 18},
}


def _records(value, kind):
    if kind == 'build':
        return {row['path']: row['sha256'] for row in value['modules'].values()}
    if kind == 'emission':
        return {row['path']: row['sha256'] for row in value['callers'].values()}
    names = {*value['prior_ordinary_9_modules'], *value['prior_separate_8_modules'],
             'tests.test_hia_agent_artifact_store_native'}
    return {value['modules'][name]['source']: value['modules'][name]['sha256']
            for name in sorted(names)}


class _CapturedAdmission:
    def __init__(self, root, records, authority):
        if type(authority) is not str or authority not in CALLER_AUTHORITIES:
            raise ValueError('caller terminal authority is not one of the three fixed originals')
        if type(records) is not dict:
            raise ValueError('caller terminal records must be the complete original mapping')
        self._root = Path(root)
        self._captured = {}
        self._physical = {}
        self._consumed = []
        self._accepted = set()
        self._accepted_distribution = set()
        self._allowed = {}
        self._diagnostics = {}
        self._accepted_diagnostics = set()
        self._finished = False
        self._authority = authority
        rule = CALLER_AUTHORITIES[authority]
        inventory_raw = self._capture(authority)
        if _pin(inventory_raw) != {key: rule[key] for key in ('bytes', 'sha256')}:
            raise ValueError('caller terminal original inventory bytes differ')
        expected = _records(json.loads(inventory_raw), rule['kind'])
        if (len(expected) != rule['sources']
                or _canonical(records) != _canonical(expected)
                or expected.get(TRANSPORT) != OLD[TRANSPORT]['sha256']
                or expected.get(EVALUATION) != EVALUATION_OLD['sha256']):
            raise ValueError('caller terminal complete original source map differs')
        self._records = dict(expected)
        for name in self._records:
            self._capture(name)
        self._admit_pair_and_evaluation()
        self._admit_deadline_diagnostics()
        self._admit_machine_receipt()
        self._admit_reviewed_components()
        self._admit_store_admin_helpers()

    def _capture(self, name):
        from tests.hia_installed_distribution_history import predecessor
        if name not in self._captured:
            self._physical[name] = (self._root / name).read_bytes()
            self._captured[name] = predecessor(name, self._physical[name])
        return self._captured[name]

    def _admit_pair_and_evaluation(self):
        from tests import hia_native_transport_worker_successor as delivery

        authorities = {}
        for kind, (path, expected) in ORIGINALS.items():
            raw = self._capture(path)
            if _pin(raw) != expected:
                raise ValueError('caller terminal independent original authority differs')
            authorities[kind] = json.loads(raw)
        if (any(_canonical(value['unchanged_files'][TRANSPORT]) != _canonical(OLD[TRANSPORT])
                or _canonical(value['unchanged_files'][EVALUATION]) != _canonical(EVALUATION_OLD)
                for value in authorities.values())
                or _canonical(authorities['store']['shared_dependency_review'][DELIVERY])
                   != _canonical(OLD[DELIVERY])):
            raise ValueError('caller terminal independent old source pins differ')
        captured = {name: self._capture(name) for name in PATHS}
        legacy = all(_pin(captured[name]) == OLD[name] for name in PATHS)
        pair = None
        frozen = None
        self._state = 'EXACT_LEGACY_PAIR'
        if not legacy:
            frozen = self._capture(FIXTURE)
            if sha256(frozen).hexdigest() != FIXTURE_SHA256:
                raise ValueError('caller terminal pair provenance changed')
            pair = json.loads(frozen)
            if (pair.get('schema') != 'hepta.hia.native-transport-terminal-source.v2'
                    or pair.get('state') != 'FROZEN_EXACT_TWO_SOURCE_SUCCESSOR'
                    or type(pair.get('source_count')) is not int or pair['source_count'] != 2
                    or type(pair.get('production_composition_source_count')) is not int
                    or pair['production_composition_source_count'] != 13
                    or set(pair.get('files', {})) != set(PATHS)
                    or pair['files'][TRANSPORT]['definition'] != '_child_store_worker'
                    or pair['files'][DELIVERY]['definition'] != 'admit_originals'):
                raise ValueError('caller terminal pair provenance scope differs')
            for name in PATHS:
                raw = captured[name]
                if name == TRANSPORT and _pin(raw) == delivery.SQLITE_BOUNDARY_SOURCES[name]:
                    raw = delivery._reverse_sqlite_boundary(name, raw,
                        self._capture(delivery.SQLITE_BOUNDARY_FIXTURE), FIXTURE, frozen,
                        pair['files'][name]['new'])
                if name == DELIVERY and _pin(raw) != pair['files'][name]['new']:
                    raw = delivery.restore_sql_source(name, raw, self._capture, pair['files'][name]['new'])
                reverse_one(raw, pair['files'][name], OLD[name])
            self._state = 'EXACT_TERMINAL_V2_PAIR'
            self._allowed[TRANSPORT] = self._adjustment(
                TRANSPORT, OLD[TRANSPORT], _pin(captured[TRANSPORT]),
                FIXTURE, FIXTURE_SHA256, '_child_store_worker')
            if _pin(captured[TRANSPORT]) != pair['files'][TRANSPORT]['new']:
                self._allowed[TRANSPORT]['sqlite_boundary_provenance'] = {
                    'path': delivery.SQLITE_BOUNDARY_FIXTURE, **delivery.SQLITE_BOUNDARY_FIXTURE_PIN}
        evaluation = self._capture(EVALUATION)
        if _pin(evaluation) != EVALUATION_OLD:
            if legacy:
                raise ValueError('caller evaluation successor requires the complete terminal pair')
            raw = self._capture(EVALUATION_FIXTURE)
            if sha256(raw).hexdigest() != EVALUATION_FIXTURE_SHA256:
                raise ValueError('caller evaluation provenance changed')
            value = json.loads(raw)
            if (type(value) is not dict
                    or set(value) != {'schema', 'state', 'test_source_count',
                        'production_composition_source_count', 'path', 'original_inventories',
                        'pair_fixture', 'required_pair', 'record'}
                    or value['schema'] != 'hepta.hia.evaluation-terminal-test-source.v2'
                    or value['state'] != 'FROZEN_EXACT_EVALUATION_TEST_SUCCESSOR'
                    or type(value['test_source_count']) is not int or value['test_source_count'] != 3
                    or type(value['production_composition_source_count']) is not int
                    or value['production_composition_source_count'] != 13
                    or value['path'] != EVALUATION
                    or _canonical(value['original_inventories']) != _canonical({
                        kind: {'path': row[0], **row[1]} for kind, row in ORIGINALS.items()})
                    or _canonical(value['pair_fixture']) != _canonical({
                        'path': FIXTURE, 'bytes': len(frozen), 'sha256': FIXTURE_SHA256})
                    or _canonical(value['required_pair']) != _canonical({
                        name: pair['files'][name]['new'] for name in PATHS})):
                raise ValueError('caller evaluation provenance scope differs')
            approved = evaluation
            if _pin(evaluation) != EVALUATION_NEW:
                approved = delivery.restore_evaluation_store(evaluation, self._capture(delivery.EVALUATION_STORE_FIXTURE))
            reverse_evaluation(approved, value['record'])
            self._state = 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2'
            self._allowed[EVALUATION] = self._adjustment(
                EVALUATION, EVALUATION_OLD, _pin(evaluation),
                EVALUATION_FIXTURE, EVALUATION_FIXTURE_SHA256, EVALUATION_DEFINITION)
            if evaluation != approved:
                self._allowed[EVALUATION]['typed_store_provenance'] = {
                    'path': delivery.EVALUATION_STORE_FIXTURE,
                    'sha256': delivery.EVALUATION_STORE_FIXTURE_SHA256}
        if set(self._allowed) - {TRANSPORT, EVALUATION}:
            raise ValueError('caller terminal source exception exceeds the reviewed two test paths')

    def _admit_deadline_diagnostics(self):
        from tests import hia_caller_diagnostics_admission as diagnostics
        from tests import hia_native_transport_worker_successor as delivery
        name = diagnostics.PATH
        if name not in self._records:
            return
        raw = self._capture(name)
        if _pin(raw) == diagnostics.ORIGINAL:
            return
        approved = raw
        if _pin(raw) == delivery.SQLITE_BOUNDARY_SOURCES[name]:
            approved = delivery._reverse_sqlite_boundary(name, raw,
                self._capture(delivery.SQLITE_BOUNDARY_FIXTURE), delivery.DIAGNOSTIC_FIXTURE,
                self._capture(delivery.DIAGNOSTIC_FIXTURE), diagnostics.CURRENT)
        proof = diagnostics.admit(name, approved, self._records[name], self._capture(diagnostics.FIXTURE))
        if raw != approved:
            proof.update(current=_pin(raw), sqlite_boundary_provenance={
                'path': delivery.SQLITE_BOUNDARY_FIXTURE, **delivery.SQLITE_BOUNDARY_FIXTURE_PIN})
        self._diagnostics[name] = proof

    def _admit_machine_receipt(self):
        from tests import hia_native_transport_worker_successor as delivery
        name = delivery.MACHINE_RECEIPT_CALLER
        if name not in self._records:
            return
        raw = self._capture(name)
        if _pin(raw)['sha256'] == self._records[name]:
            return
        original = json.loads(self._capture(ORIGINALS['store'][0]))['unchanged_files'][name]
        if original['sha256'] != self._records[name]:
            raise ValueError('machine receipt cannot change this original caller authority')
        fixture = delivery.MACHINE_RECEIPT_FIXTURE
        self._capture(fixture)
        delivery.restore_machine_receipt_caller(self._root, raw, original)
        self._allowed[name] = self._adjustment(name, original, _pin(raw), fixture,
            delivery.MACHINE_RECEIPT_FIXTURE_PIN['sha256'], 'retained native machine proof receipt')

    def _original_worker_count(self, name, raw, expected):
        if name != 'tests/test_hia_worker_native_helpers.py':
            return False
        from hepta.hia_native_helpers import HELPERS
        count = 36 if CALLER_AUTHORITIES[self._authority]['kind'] == 'build' else 37
        template = b'        self.assertEqual(len(HELPERS), %d)\n'
        current = template % len(HELPERS)
        return raw.count(current) == 1 and _pin(raw.replace(current, template % count, 1))['sha256'] == expected

    def _admit_reviewed_components(self):
        from tests import hia_native_transport_worker_successor as delivery
        from tests.hia_store_delivery_successor import reverse_exact

        for name in delivery.COMPONENT_PATHS:
            expected = self._records.get(name)
            if expected is None:
                continue
            raw = self._capture(name)
            if _pin(raw)['sha256'] == expected or self._original_worker_count(name, raw, expected):
                continue
            fixture = delivery.COMPONENT_FIXTURE
            frozen = self._capture(fixture)
            if sha256(frozen).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
                raise ValueError('caller component authority differs')
            record = json.loads(frozen)['files'][name].get(expected)
            if record is None:
                continue
            original = {'bytes': record['old_bytes'], 'sha256': expected}
            reverse_exact(raw, record, original)
            self._allowed[name] = self._adjustment(name, original, _pin(raw), fixture,
                delivery.COMPONENT_FIXTURE_SHA256, 'retained native component caller')

    def _admit_store_admin_helpers(self):
        from tests.hia_store_delivery_successor import reverse_exact

        name = 'tests/test_hia_worker_native_helpers.py'
        if name not in self._records:
            return
        kind = CALLER_AUTHORITIES[self._authority]['kind']
        expected = self._records[name]
        raw = self._capture(name)
        current = _pin(raw)
        if current['sha256'] == expected or self._original_worker_count(name, raw, expected):
            return
        if kind == 'build' and current['sha256'] != '4fef9e2f0a8188f5f3a6c81e522b5babd3a1f0c0a88f58e286cdf762433caab3':
            # The build qualifier separately admits its original count-only change.
            return
        fixture = 'tests/fixtures/store_caller_worker_helpers_successor.json'
        digest = '168ef69fadf672e41f3dd717d3d79e54fcd1af70105d2e3552687b72af824904'
        frozen = self._capture(fixture)
        if sha256(frozen).hexdigest() != digest:
            raise ValueError('Store administrator-helper caller provenance differs')
        value = json.loads(frozen)
        if (set(value) != {'schema', 'path', 'original_commit', 'record'}
                or value['schema'] != 'hepta.hia.store-caller-worker-helpers-successor.v1'
                or value['path'] != name or value['original_commit'] != '73f16346'):
            raise ValueError('Store administrator-helper caller provenance scope differs')
        record = value['record']
        retained = reverse_exact(raw, record, {'bytes': record['old_bytes'], 'sha256': record['old_sha256']})
        if kind == 'build':
            # Between aac7550 and 73f16346 this exact row was the only difference.
            row = b'        self.assertEqual(len(HELPERS), 37)\n'
            if retained.count(row) != 1:
                raise ValueError('original Build helper count row differs')
            retained = retained.replace(row, row.replace(b'37', b'36'), 1)
        original = _pin(retained)
        if original['sha256'] != expected:
            raise ValueError('helper reconstruction differs from the complete caller source')
        self._allowed[name] = self._adjustment(name, original, current, fixture, digest,
            'address-space regression, expanded exact helper inventory and pinned journal fixture')

    @staticmethod
    def _adjustment(name, before, after, fixture, digest, definition):
        return {'path': name, 'original': dict(before), 'current': dict(after),
                'provenance_path': fixture, 'provenance_sha256': digest,
                'definition': definition, 'complete_original_inverse_verified': True,
                'production_source_exception': False}

    def raw(self, name):
        if self._finished or name not in self._records or name in self._consumed:
            raise ValueError('caller original source consumption is missing, duplicate or closed')
        self._consumed.append(name)
        # Return the exact captured current bytes, never the reconstructed old bytes.
        return self._physical[name]

    def permits(self, name, expected_sha256, raw):
        if (self._finished or name not in self._consumed
                or type(raw) is not bytes or raw != self._physical[name]
                or expected_sha256 != self._records[name]):
            raise ValueError('caller terminal consumed bytes or expected old identity differ')
        previous = self._captured[name]
        if raw != previous and _pin(previous)['sha256'] == expected_sha256:
            if name in self._accepted_distribution:
                raise ValueError('duplicate installed distribution caller admission')
            self._accepted_distribution.add(name)
            return True
        raw = previous
        if name in self._diagnostics:
            reviewed = self._diagnostics[name]
            if (expected_sha256 != reviewed['original']['sha256']
                    or _pin(raw) != reviewed['current'] or name in self._accepted_diagnostics):
                raise ValueError('caller diagnostics exact current source differs')
            self._accepted_diagnostics.add(name)
            return True
        reviewed = self._allowed.get(name)
        if reviewed is None:
            return False
        if (expected_sha256 != reviewed['original']['sha256']
                or _pin(raw) != reviewed['current'] or name in self._accepted):
            raise ValueError('caller terminal exact current source differs')
        self._accepted.add(name)
        return True

    def finish(self):
        required_distribution = {name for name, digest in self._records.items()
                                 if self._physical[name] != self._captured[name]
                                 and _pin(self._captured[name])['sha256'] == digest}
        if (self._finished or set(self._consumed) != set(self._records)
                or len(self._consumed) != len(self._records)
                or self._accepted_distribution != required_distribution
                or self._accepted != set(self._allowed)
                or self._accepted_diagnostics != set(self._diagnostics)):
            raise ValueError('caller terminal original source consumption is incomplete')
        for name, raw in self._physical.items():
            if (self._root / name).read_bytes() != raw:
                raise ValueError('caller terminal captured bytes changed: ' + name)
        self._finished = True
        return {'schema': 'hepta.hia.caller-terminal-source-admission.v1',
                'authority': {'path': self._authority, **_pin(self._captured[self._authority])},
                'state': self._state, 'original_source_count': len(self._records),
                'ordered_consumed_original_sources': list(self._consumed),
                'reviewed_test_source_adjustments': dict(self._allowed),
                'reviewed_diagnostic_source_adjustments': dict(self._diagnostics),
                'captured_files': {name: _pin(raw) for name, raw in self._physical.items()},
                'installed_distribution_predecessors': {name: _pin(raw) for name, raw in self._captured.items()
                                                       if raw != self._physical[name]},
                'terminal_reread_identical': True,
                'production_composition_source_count': 13,
                'production_source_exceptions': [],
                'original_inventory_bytes_unchanged': True}


def capture_caller_terminal_admission(root, records, *, authority):
    return _CapturedAdmission(root, records, authority)
