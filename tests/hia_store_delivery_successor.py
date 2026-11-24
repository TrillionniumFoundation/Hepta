"""Exact, reversible provenance for reviewed Store, service and protocol successors.

The original c019 inventory is never rewritten. A draft is never an admission;
final composition needs a fixed fixture hash, all old/new hashes and the exact
byte splice patch. Every other original file still uses its old byte check.
"""
import ast
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/store_delivery_successor_provenance.json'
FIXTURE_SHA256 = '29e30b81ef5f38646ed4bbec5df18db5043f989575bec00cab6a200e56874e42'
COMPOSITION_SUCCESSOR = ROOT / 'tests/fixtures/store_delivery_composition_successor.json'
COMPOSITION_SUCCESSOR_SHA256 = '4d52c953af4df5f115580871700265297f5b8069d31ee8fa2f22c718f4311090'
WORKER_TRANSPORT_SUCCESSOR = ROOT / 'tests/fixtures/worker_report_stream_successor.json'
WORKER_TRANSPORT_SHA256 = '49602d227e86a74d0de3b68e07e54b09de1c87feb607d4f9c2de5896daeb20d7'
WORKER_REPORT_PATH = 'hepta/hia_worker_report_native.py'
STORE_COST = ROOT / 'tests/fixtures/store_worker_cost_successor.json'
STORE_COST_SHA256 = '80c94ce363b84aedc57a60d29c1b175cab298901d5cf1c6e72adb74eafa16a57'
STORE_PATH = 'hepta/hia_agent_store.py'
RETAINED_READ = ROOT / 'tests/fixtures/store_retained_read_successor.json'
RETAINED_READ_SHA256 = '55067c36abaae147d7eebf4932df4df99d8ebf0cb4e9a851c79ab4e4f1dbab9e'
SERVICE_PATH = 'hepta/hia_agent_service.py'
EVALUATION_PATH = 'hepta/hia_evaluation_native.py'
QUALIFIER_PATH = 'tests/hia_caller_terminal_admission.py'
EVALUATE_FIXTURE = 'tests/fixtures/store_evaluate_delivery_successor.json'
EVALUATE_FIXTURE_SHA256 = '6a239a623d3bb296e98f31e709eebb63330f79855cb3316b4ef08409df834a2f'
EVALUATION_PLANNER_SHA256 = 'd30d4f0796535ba524746a2e8a07f76fe253e9799745cf8458fedf526bce0a70'
JOURNAL_COST = ROOT / 'tests/fixtures/worker_journal_cost_successor.json'
JOURNAL_COST_SHA256 = '97f1c36e9f12af0ffe96b3c789603365e74a3df0b8b5b52fa2be9dca9b7c3cd1'
COMPOSITION_EXTENSIONS = {
    'hepta/hia_agent_journal_native.py': (JOURNAL_COST, JOURNAL_COST_SHA256, 'hepta.hia.worker-journal-cost-successor.v1'),
    SERVICE_PATH: (RETAINED_READ, RETAINED_READ_SHA256, 'hepta.hia.store-retained-read-successor.v1'),
    WORKER_REPORT_PATH: (WORKER_TRANSPORT_SUCCESSOR, WORKER_TRANSPORT_SHA256,
                         'hepta.hia.worker-report-stream-successor.v1'),
    STORE_PATH: (STORE_COST, STORE_COST_SHA256, 'hepta.hia.store-worker-cost-successor.v1'),
}
ORIGINAL = ROOT / 'tests/fixtures/store_native_delivery_original_c019.json'
ORIGINAL_SHA256 = '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'
ORIGINAL_SOURCE_PATHS = ('hepta/artifact_publication_native.py', 'hepta/hia_agent_store.py',
                'hepta/hia_store_lifecycle_selection.py')
WORKER_PATH = 'hepta/hia_agent_worker.py'
SOURCE_PATHS = ORIGINAL_SOURCE_PATHS + (WORKER_PATH,)
SHARED_PATHS = ('hepta/hia_native_delivery.py', 'hepta/hia_store_lifecycle_native.py',
                'hepta/hia_agent_service.py', 'hepta/hia_emission_native.py',
                'hepta/hia_agent_journal_native.py',
                'hepta/hia_candidate_budget_native.py', 'hepta/hia_execution_budget_native.py')
ADAPTER_PATH = 'hepta/hia_store_artifact_profile_native.py'
# Actual c019 Git bytes independently pin this whole file. The original JSON
# pins its 21 definitions, rather than the complete adapter source.
ADAPTER_ORIGINAL = {'bytes': 32417,
    'sha256': 'fccf236d69462b833b7c8e466bcde716738c13be7095aa675c9427022839b7fc'}
# This companion was not in c019's 89 originals or its 22 shared sources.
# Its independent original is the exact frozen R17b source, not a c019 claim.
COMPANION_ORIGINALS = {WORKER_REPORT_PATH: {
    'bytes': 20176, 'sha256': 'c8539747922892195722f72f9b763eb1d9503b4fe80318eee33ee88a812ed597'}}
# Preserve the original eleven-bit order; append the worker and report bits.
PATHS = ORIGINAL_SOURCE_PATHS + SHARED_PATHS + (ADAPTER_PATH, WORKER_PATH) + tuple(COMPANION_ORIGINALS)
LATER_SHARED_PATHS = ('hepta/hia_cost_ledger_native.py', 'hepta/hia_evaluation_native.py',
                      'hepta/hia_service_context_native.py', 'tools/build_hia_evaluation.py')
FINAL_SOURCE_HELPER = 'tests/hia_final_source_successor.py'
FINAL_SOURCE_HELPER_PIN = {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}
FINITE_PROOF_SHA256 = 'd85ded0610fc7ee3443340f5892e705f24768492100ee1f69af05eb336f8a8c5'
FINAL_COMPOSITION_SHA256 = {'hepta/hia_agent_service.py': 'd85ded0610fc7ee3443340f5892e705f24768492100ee1f69af05eb336f8a8c5', 'hepta/hia_store_lifecycle_native.py': 'c800f2d9701698147b4702401908dc37625cdea1ee21d550b5154ea10c9806f1', 'hepta/hia_emission_native.py': '2dffce808cccef4f5632d10c63dbb22b523aeed867142d64a142e44b2d4a86ba'}


def final_source_predecessor(name, raw, captured=None, original_sha256=None):
    """Bind one fixed final relation and reread every source it actually uses."""
    from tests import hia_final_source_successor as final

    captured = {} if captured is None else captured
    def capture(path):
        data = (ROOT / path).read_bytes()
        if path in captured and captured[path] != data:
            raise ValueError('final source changed between captures: ' + path)
        captured[path] = data
        return data
    helper = capture(FINAL_SOURCE_HELPER)
    if (final.pin(helper) != FINAL_SOURCE_HELPER_PIN
            or Path(final.__file__).read_bytes() != helper):
        raise ValueError('final source admission helper changed')
    restored, relation = final.admit(capture, name, raw, original_sha256)
    if any((ROOT / path).read_bytes() != data for path, data in captured.items()):
        raise ValueError('final source changed during admission')
    return restored, relation


def _bytes(value):
    if type(value) is not str or len(value) % 2 or value != value.lower():
        raise ValueError('successor byte patch encoding differs')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('successor byte patch encoding invalid') from error
    if raw.hex() != value:
        raise ValueError('successor byte patch is not canonical')
    return raw


def reverse_exact(raw, record, original):
    """Rebuild the complete original bytes from one fixed new file and patch."""
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old_sha256', 'new_sha256', 'old_bytes', 'new_bytes', 'hunks'}
            or record['old_sha256'] != original['sha256']
            or record['old_bytes'] != original['bytes']
            or type(record['new_bytes']) is not int or record['new_bytes'] != len(raw)
            or sha256(raw).hexdigest() != record['new_sha256']
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('successor whole-file identity differs')
    new_at = old_at = 0
    pieces = []
    for hunk in record['hunks']:
        if (type(hunk) is not dict or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int or type(hunk['new_offset']) is not int
                or hunk['new_offset'] < new_at):
            raise ValueError('successor patch coordinates differ')
        old, new = _bytes(hunk['old_hex']), _bytes(hunk['new_hex'])
        gap = hunk['new_offset'] - new_at
        if (old == new or hunk['old_offset'] != old_at + gap
                or hunk['new_offset'] + len(new) > len(raw)
                or raw[hunk['new_offset']:hunk['new_offset'] + len(new)] != new):
            raise ValueError('successor patch does not describe the actual bytes')
        pieces.extend((raw[new_at:hunk['new_offset']], old))
        new_at, old_at = hunk['new_offset'] + len(new), hunk['old_offset'] + len(old)
    pieces.append(raw[new_at:])
    restored = b''.join(pieces)
    if len(restored) != original['bytes'] or sha256(restored).hexdigest() != original['sha256']:
        raise ValueError('successor patch does not restore the complete original identity')
    return restored


def evaluate_records(frozen):
    if sha256(frozen).hexdigest() != EVALUATE_FIXTURE_SHA256:
        raise ValueError('Store Evaluate source provenance changed')
    value = json.loads(frozen)
    if (set(value) != {'schema', 'files', 'service_followups', 'build_qualifier', 'build_inventory_test', 'evaluation_qualifier'}
            or type(value['service_followups']) is not list or len(value['service_followups']) != 6
            or value['schema'] != 'hepta.hia.store-evaluate-delivery-successor.v1'
            or set(value['files']) != {SERVICE_PATH, EVALUATION_PATH, QUALIFIER_PATH}):
        raise ValueError('Store Evaluate source provenance scope differs')
    return value



def retained_bootstrap_service(raw):
    """Verify and reverse each physical service update back to the original Bootstrap prefix."""
    captures = {ROOT / EVALUATE_FIXTURE: (ROOT / EVALUATE_FIXTURE).read_bytes(),
                RETAINED_READ: RETAINED_READ.read_bytes(),
                COMPOSITION_SUCCESSOR: COMPOSITION_SUCCESSOR.read_bytes()}
    checked = evaluate_records(captures[ROOT / EVALUATE_FIXTURE])
    if (sha256(captures[RETAINED_READ]).hexdigest() != RETAINED_READ_SHA256
            or sha256(captures[COMPOSITION_SUCCESSOR]).hexdigest() != COMPOSITION_SUCCESSOR_SHA256):
        raise ValueError('Bootstrap service source provenance differs')
    records = [json.loads(captures[COMPOSITION_SUCCESSOR])['files'][SERVICE_PATH],
               json.loads(captures[RETAINED_READ])['patch'],
               checked['files'][SERVICE_PATH], *checked['service_followups']]
    restored = raw
    if sha256(restored).hexdigest() == FINITE_PROOF_SHA256:
        final_captures = {}
        restored, _relation = final_source_predecessor(SERVICE_PATH, restored, final_captures)
        captures.update({ROOT / path: value for path, value in final_captures.items()})
    for record in reversed(records):
        restored = reverse_exact(restored, record, {
            'bytes': record['old_bytes'], 'sha256': record['old_sha256']})
    if ((ROOT / SERVICE_PATH).read_bytes() != raw
            or any(path.read_bytes() != value for path, value in captures.items())):
        raise ValueError('Bootstrap service source changed during admission')
    return restored


def _adapter_definitions(raw):
    module, lines = ast.parse(raw), raw.splitlines(keepends=True)
    def pin(node):
        first = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
        body = b''.join(lines[first:node.end_lineno])
        return {'bytes': len(body), 'sha256': sha256(body).hexdigest()}
    result = {node.name: pin(node) for node in module.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    frame = next(node for node in module.body
                 if isinstance(node, ast.ClassDef) and node.name == 'StoreArtifactProfileFrame')
    for node in frame.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                '_global', 'argument', 'effect', '_release', '_confirmed_foreign_failure'):
            result['StoreArtifactProfileFrame.' + node.name] = pin(node)
    return result


def _review_adapter(original, restored, current, records):
    expected = dict(original['unchanged_adapter_definitions'])
    if len(expected) != 21 or _adapter_definitions(restored) != expected:
        raise ValueError('restored complete adapter differs from original definition inventory')
    if type(records) is not dict or set(records) != {'_context_special'}:
        raise ValueError('adapter definition successor changes its exact reviewed scope')
    item = records['_context_special']
    if (type(item) is not dict or set(item) != {'old', 'new'}
            or item['old'] != expected['_context_special']
            or type(item['new']) is not dict or set(item['new']) != {'bytes', 'sha256'}):
        raise ValueError('adapter definition successor original identity differs')
    expected['_context_special'] = item['new']
    if _adapter_definitions(current) != expected:
        raise ValueError('adapter changes a definition beyond the exact protocol successor')
    # Expected values come from the immutable original and fixed-hash fixture.
    # Actual source is compared only; it is never normalized or used as expected.
    return expected, {'_context_special': item}


def _restore_composition_successor(captured, approved, shared):
    """Admit only the complete later composition and invert it to the fixed predecessor."""
    unchanged = {ADAPTER_PATH, 'hepta/hia_store_lifecycle_selection.py'}
    changed = set(PATHS) - unchanged
    fixture = COMPOSITION_SUCCESSOR.read_bytes()
    if sha256(fixture).hexdigest() != COMPOSITION_SUCCESSOR_SHA256:
        raise ValueError('reviewed later Store composition fixture changed')
    value = json.loads(fixture)
    if (type(value) is not dict
            or set(value) != {'schema', 'prior_fixture_sha256', 'files', 'shared_dependencies'}
            or value['schema'] != 'hepta.hia.store-delivery-composition-successor.v1'
            or value['prior_fixture_sha256'] != FIXTURE_SHA256
            or type(value['files']) is not dict or set(value['files']) != changed
            or type(value['shared_dependencies']) is not dict
            or set(value['shared_dependencies']) != set(LATER_SHARED_PATHS)):
        raise ValueError('later Store composition changes its reviewed scope')
    for name in LATER_SHARED_PATHS:
        captured[name] = (ROOT / name).read_bytes()
    source = dict(captured)
    final_relations = {}
    for name, expected in FINAL_COMPOSITION_SHA256.items():
        if sha256(source[name]).hexdigest() == expected:
            source[name], final_relations[name] = final_source_predecessor(
                name, source[name], captured)
    evaluate_fixture = None
    evaluate_current = {}
    if sha256(source[EVALUATION_PATH]).hexdigest() == EVALUATION_PLANNER_SHA256:
        # The installed planner is reviewed together with the service providers.
        # Invert both whole files before running their complete prior admissions.
        evaluate_fixture = (ROOT / EVALUATE_FIXTURE).read_bytes()
        reviewed = evaluate_records(evaluate_fixture)
        for name in (SERVICE_PATH, EVALUATION_PATH):
            record = reviewed['files'][name]
            latest = record
            if name == SERVICE_PATH:
                # Each exact service stage adds one reviewed capability in order:
                # Inspect, SQL cost ledgers, cursor paging, build inputs and Evaluate providers.
                stages = [record, *reviewed['service_followups']]
                for prior, step in reversed(list(zip(stages, stages[1:]))):
                    if sha256(source[name]).hexdigest() == step['new_sha256']:
                        if latest is record:
                            latest = step
                        source[name] = reverse_exact(source[name], step, {
                            'bytes': prior['new_bytes'], 'sha256': prior['new_sha256']})
            source[name] = reverse_exact(source[name], record, {
                'bytes': record['old_bytes'], 'sha256': record['old_sha256']})
            evaluate_current[name] = latest
    restored = dict(source)
    current = dict(approved)
    extensions = {}
    for name in changed:
        record = value['files'][name]
        previous = approved[name]
        raw = source[name]
        current[name] = record
        if name in COMPOSITION_EXTENSIONS and sha256(raw).hexdigest() != record['new_sha256']:
            raw, current[name], extensions[name] = _restore_extension(name, raw, record)
        restored[name] = reverse_exact(raw, record,
                                       {'sha256': previous['new_sha256'], 'bytes': previous['new_bytes']})
    for name in LATER_SHARED_PATHS:
        record = value['shared_dependencies'][name]
        reverse_exact(source[name], record, shared[name])
        current[name] = record
    current.update(evaluate_current)
    for name, relation in final_relations.items():
        current[name] = {'new_bytes': relation['current']['bytes'],
                         'new_sha256': relation['current']['sha256']}
    return restored, current, fixture, extensions, evaluate_fixture, final_relations


def _restore_extension(path, raw, predecessor):
    source, expected, schema = COMPOSITION_EXTENSIONS[path]
    fixture = source.read_bytes()
    if sha256(fixture).hexdigest() != expected:
        raise ValueError('Store composition extension fixture changed: ' + path)
    value = json.loads(fixture)
    if (type(value) is not dict or set(value) != {'schema', 'prior_fixture_sha256', 'path', 'patch'}
            or value['schema'] != schema
            or value['prior_fixture_sha256'] != COMPOSITION_SUCCESSOR_SHA256
            or value['path'] != path):
        raise ValueError('Store composition extension changes its reviewed scope: ' + path)
    record = value['patch']
    previous = {'bytes': predecessor['new_bytes'], 'sha256': predecessor['new_sha256']}
    return reverse_exact(raw, record, previous), record, fixture


def admit_composition(original_value):
    original_bytes = ORIGINAL.read_bytes()
    if sha256(original_bytes).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('original Store successor inventory changed')
    inventory = json.loads(original_bytes)
    if original_value != inventory:
        raise ValueError('successor caller original inventory differs')
    originals = {path: inventory['unchanged_files'][path] for path in SOURCE_PATHS}
    originals.update({path: inventory['shared_dependency_review'][path] for path in SHARED_PATHS})
    originals[ADAPTER_PATH] = ADAPTER_ORIGINAL
    originals.update(COMPANION_ORIGINALS)
    captured = {path: (ROOT / path).read_bytes() for path in PATHS}
    if all(len(captured[path]) == originals[path]['bytes']
           and sha256(captured[path]).hexdigest() == originals[path]['sha256'] for path in PATHS):
        definitions = dict(inventory['unchanged_adapter_definitions'])
        if _adapter_definitions(captured[ADAPTER_PATH]) != definitions:
            raise ValueError('original complete adapter differs from its definition inventory')
        if (ORIGINAL.read_bytes() != original_bytes
                or any((ROOT / path).read_bytes() != captured[path] for path in PATHS)):
            raise ValueError('original Store composition changed during admission')
        return {'source_adjustments': {}, 'shared_adjustments': {},
                'shared_dependency_review': dict(inventory['shared_dependency_review']),
                'adapter_source_adjustments': {}, 'companion_source_adjustments': {},
                'adapter_definition_adjustments': {},
                'adapter_definition_review': definitions}
    frozen = FIXTURE.read_bytes()
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('reviewed Store successor provenance fixture changed')
    value = json.loads(frozen)
    if (value.get('schema') != 'hepta.hia.store-delivery-successor.v2'
            or value.get('state') != 'FROZEN_COMPOSED_SOURCE'
            or value.get('original_commit') != 'c0195643083e1d4c68679237edfa77143dc7b1c6'
            or type(value.get('files')) is not dict or set(value['files']) != set(PATHS)
            or any(type(value.get(name)) is not int or value[name] != expected
                   for name, expected in (
                       ('composition_source_count', 13), ('source_adjustment_count', 4),
                       ('shared_adjustment_count', 7), ('adapter_source_adjustment_count', 1),
                       ('companion_source_adjustment_count', 1),
                       ('unchanged_original_file_count', 85),
                       ('unchanged_shared_dependency_count', 15),
                       ('original_definition_count', 21)))):
        raise ValueError('Store successor provenance remains draft or changes scope')
    # A successor belongs to one complete reviewed composition. A partially
    # reverted mixture cannot borrow admission from another changed file.
    # There is no process-global cache: every admission binds all thirteen complete files.
    approved = current = value['files']
    predecessor = captured
    later_fixture = evaluate_fixture = None
    final_relations = {}
    extensions = {}
    if any((len(captured[path]), sha256(captured[path]).hexdigest()) !=
           (approved[path]['new_bytes'], approved[path]['new_sha256']) for path in PATHS):
        predecessor, current, later_fixture, extensions, evaluate_fixture, final_relations = _restore_composition_successor(
            captured, approved, inventory['shared_dependency_review'])
    restored = {path: reverse_exact(predecessor[path], approved[path], originals[path])
                for path in PATHS}
    definitions, definition_adjustments = _review_adapter(inventory, restored[ADAPTER_PATH],
        captured[ADAPTER_PATH], value.get('adapter_definition_successors'))
    if (FIXTURE.read_bytes() != frozen or ORIGINAL.read_bytes() != original_bytes
            or (later_fixture is not None and COMPOSITION_SUCCESSOR.read_bytes() != later_fixture)
            or (evaluate_fixture is not None and (ROOT / EVALUATE_FIXTURE).read_bytes() != evaluate_fixture)
            or any(COMPOSITION_EXTENSIONS[path][0].read_bytes() != raw for path, raw in extensions.items())
            or any((ROOT / path).read_bytes() != raw for path, raw in captured.items())):
        raise ValueError('successor composition changed during admission')
    composition = {path: current[path]['new_sha256'] for path in PATHS}
    fixture_sha256 = COMPOSITION_SUCCESSOR_SHA256 if later_fixture is not None else FIXTURE_SHA256
    adjustments = {path: {'path': path, 'original_sha256': sha256(restored[path]).hexdigest(),
        'current_sha256': current[path]['new_sha256'],
        'current_bytes': current[path]['new_bytes'],
        'reversible_patch_fixture_sha256': (COMPOSITION_EXTENSIONS[path][1]
            if path in extensions else fixture_sha256),
        'scope': 'exact reviewed D5, transaction owner, journal cleanup, service artifact, service read, weak SQL, context protocol, Bootstrap, Budget resource and worker unknown-terminal successor',
        'composition_sha256': composition} for path in PATHS}
    if evaluate_fixture is not None:
        service = adjustments[SERVICE_PATH]
        service['preceding_patch_fixture_sha256'] = service['reversible_patch_fixture_sha256']
        service['reversible_patch_fixture_sha256'] = EVALUATE_FIXTURE_SHA256
        service['scope'] += ', installed Evaluate planning, Artifact and Emission providers and reviewed Inspect, Cost, Read and native build dispatch'
    for name, relation in final_relations.items():
        adjustment = adjustments[name]
        adjustment['preceding_patch_fixture_sha256'] = adjustment['reversible_patch_fixture_sha256']
        adjustment['reversible_patch_fixture_sha256'] = relation['provenance_sha256']
        adjustment['scope'] += ', ' + relation['scope']
    shared = dict(inventory['shared_dependency_review'])
    for path in SHARED_PATHS:
        # Return the fixed, independently reviewed literal pins only after
        # the complete composition matched; never derive expected from disk.
        shared[path] = {'bytes': current[path]['new_bytes'], 'sha256': current[path]['new_sha256']}
    if later_fixture is not None:
        for path in LATER_SHARED_PATHS:
            shared[path] = {'bytes': current[path]['new_bytes'], 'sha256': current[path]['new_sha256']}
    if final_relations:
        from tests import hia_final_source_successor as final
        additions = {FINAL_SOURCE_HELPER: FINAL_SOURCE_HELPER_PIN,
            final.FIXTURE: {'bytes': 14940, 'sha256': final.FIXTURE_SHA256}}
        for relation in final_relations.values():
            for path, expected in relation['dependencies'].items():
                if path in additions and additions[path] != expected:
                    raise ValueError('final source dependency authorities disagree: ' + path)
                additions[path] = expected
        for path, expected in additions.items():
            if path in shared and shared[path] != expected:
                raise ValueError('final source changes an earlier shared source authority: ' + path)
            shared[path] = expected
    return {'source_adjustments': {path: adjustments[path] for path in SOURCE_PATHS},
            'shared_adjustments': {path: adjustments[path] for path in SHARED_PATHS},
            'shared_dependency_review': shared,
            'adapter_source_adjustments': {ADAPTER_PATH: adjustments[ADAPTER_PATH]},
            'companion_source_adjustments': {path: adjustments[path] for path in COMPANION_ORIGINALS},
            'adapter_definition_adjustments': definition_adjustments,
            'adapter_definition_review': definitions}
