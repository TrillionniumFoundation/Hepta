"""Exact data-only source history for complete original artifact callers."""
from hashlib import sha256
import json
from pathlib import Path

ASSEMBLY = 'tests/test_hia_agent_assembly.py'
PUBLICATION = 'tests/test_hia_artifact_publication_native.py'
NATIVE_TOOLS = 'tests/test_hia_agent_native_tools.py'
ROUTE = 'tests/test_hia_artifact_publication_route.py'
ROUTE_FIXTURE = 'tests/fixtures/hia_artifact_route_cold_selection_v1.json'
ROUTE_FIXTURE_PIN = {"bytes":1667,"sha256":"651610e574f34fbe56bc877a88f478b6c537faac5b5930275fa13a08526bdd0d"}
ASSEMBLY_FIXTURE = 'tests/fixtures/hia_artifact_assembly_source_successor_v1.json'
ASSEMBLY_FIXTURE_PIN = {'bytes': 8990, 'sha256': '703d2db853fe87d2ea10c31803a2969245d7c8714622d631cbfe130a1c614f86'}
PUBLICATION_FIXTURE = 'tests/fixtures/hia_artifact_publication_native_cold_successor_v1.json'
PUBLICATION_FIXTURE_PIN = {
    'bytes': 6050, 'sha256': 'cd4342ba51a21c812c1945ae99c9dfe7a179039e021aa4e2f65445a6ae0aaf0e'}
FROZEN_HELPER = 'tools/hia_frozen_component_sources.py'
FROZEN_HELPER_PIN = {
    'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
FROZEN_FIXTURE = 'tests/fixtures/hia_frozen_component_source_relations.json'
FROZEN_FIXTURE_PIN = {
    'bytes': 18122, 'sha256': 'acd25ffa7c6bea270fcb56cde74a60d7993899cb2e77173b97a814a3bcce14b9'}
CURRENT = {
    ROUTE: {"bytes":14742,"sha256":"32026b1a35fd73feb127c5940025bde37312948894b68615d5452317203c7d49"},
    ASSEMBLY: {'bytes': 15006, 'sha256': '367ba5cf0280d2a0cca2f42d20387d81982b5b2b45f439d3898fb51905eff339'},
    PUBLICATION: {'bytes': 19607, 'sha256': 'de92f2dc85c187fb0834de801899801c6cb1c36ab03909dab07554bcf15ee0dc'},
    NATIVE_TOOLS: {'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70'},
}
NATIVE_SIX = {'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'}
NATIVE_SIX_HELPER = 'tools/hia_native_result_caller_history.py'
NATIVE_SIX_HELPER_PIN = {
    'bytes': 2868, 'sha256': 'e1e1edfcaeaf0f80f7b2b51604afff87908d45419f1aef87fbf8408589cc4248'}
NATIVE_SIX_FIXTURE = 'tests/fixtures/hia_native_result_caller_history_v1.json'
NATIVE_SIX_FIXTURE_PIN = {
    'bytes': 1087, 'sha256': 'dccd8c04824fdaa3ac7cf638fd487622a8ecfd198236cf0108ef8dc2edb10130'}
REVIEWED = {
    ROUTE: {"bytes":14759,"sha256":"55b8c074a57a58e66ea561a89f930f0302f877182f9597f67d7db40b1425d765"},
    ASSEMBLY: {'bytes': 11095, 'sha256': '2f429e970da879bb5e4e65f414c415cfe4df6577cfb3d9618a9c8a64d992c7f7'},
    PUBLICATION: {'bytes': 19670, 'sha256': '0e0b139387f69152c54b7d5f4f4533a87bfcd539552badb613c1bef60dc3ed2a'},
    NATIVE_TOOLS: {'bytes': 46518, 'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'},
}
ASSEMBLY_ADDED_IDS = (
    'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_package_renderer_keeps_independent_roundtrip_and_profile_errors',
    'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_package_syntax_document_still_requires_whole_core_admission',
)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('artifact history requires complete bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('artifact history contains a duplicate member')
        result[key] = value
    return result


def reviewed(root, name, raw, *, take=Path.read_bytes):
    """Restore only complete recognized files; the original gate owns all others."""
    physical_pin = pin(raw)
    six_result = name == NATIVE_TOOLS and physical_pin == NATIVE_SIX
    if physical_pin != CURRENT.get(name) and not six_result:
        return raw, None
    root, captured = Path(root), {}
    physical = raw

    def capture(relative, expected):
        path = root / relative
        value = take(path)
        if pin(value) != expected or (path in captured and captured[path] != value):
            raise ValueError('artifact history fixed input differs: ' + relative)
        captured[path] = value
        return value

    if capture(name, physical_pin) != physical:
        raise ValueError('artifact history caller differs from requested root')

    def take_fixed(path):
        path = Path(path)
        name = path.relative_to(root).as_posix()
        expected = {FROZEN_FIXTURE: FROZEN_FIXTURE_PIN,
                    NATIVE_SIX_FIXTURE: NATIVE_SIX_FIXTURE_PIN,
                    NATIVE_TOOLS: physical_pin}[name]
        return capture(name, expected)

    assertion_successor = None
    if six_result:
        six_helper = capture(NATIVE_SIX_HELPER, NATIVE_SIX_HELPER_PIN)
        capture(NATIVE_SIX_FIXTURE, NATIVE_SIX_FIXTURE_PIN)
        from tools import hia_native_result_caller_history as six
        if Path(six.__file__).read_bytes() != six_helper:
            raise ValueError('artifact native-result imported helper differs')
        raw = six.unwrap(root, name, physical, take=take_fixed)
        if pin(raw) != CURRENT[NATIVE_TOOLS]:
            raise ValueError('artifact six-result whole predecessor differs')
        assertion_successor = {
            'path': name, 'physical': physical_pin, 'predecessor': pin(raw),
            'helper': {'path': NATIVE_SIX_HELPER, **NATIVE_SIX_HELPER_PIN},
            'authority': {'path': NATIVE_SIX_FIXTURE, **NATIVE_SIX_FIXTURE_PIN},
            'definition': 'ArtifactContractTests.test_discovery_is_readable_and_source_bound',
            'assertion': 'support["limits"]["function_results"]',
            'previous_expected': 3, 'current_expected': 6, 'exact_byte_splices': 1,
            'complete_original_inverse_verified': True,
            'complete_current_forward_replay_verified': True,
            'original_deadlines_changed': False, 'original_runtime_budgets_changed': False,
        }

    helper = capture(FROZEN_HELPER, FROZEN_HELPER_PIN)
    from tools import hia_frozen_component_sources as frozen
    if Path(frozen.__file__).read_bytes() != helper:
        raise ValueError('artifact history imported a different complete helper')
    added = []
    if name == NATIVE_TOOLS:
        authority_name, authority_pin = FROZEN_FIXTURE, FROZEN_FIXTURE_PIN
        authority = capture(authority_name, authority_pin)
        restored = frozen.reviewed_source(root, name, raw, take=take_fixed)
        relation = json.loads(authority, object_pairs_hook=_pairs)['files'][name]
        replay, old_end, new_end = [], 0, 0
        for at, size, original in relation['splices']:
            before = original.encode('utf-8')
            old_at = old_end + at - new_end
            if restored[old_at:old_at + len(before)] != before:
                raise ValueError('artifact native-tool forward predecessor differs')
            replay.extend((restored[old_end:old_at], raw[at:at + size]))
            old_end, new_end = old_at + len(before), at + size
        replay.append(restored[old_end:])
        if b''.join(replay) != raw:
            raise ValueError('artifact native-tool complete forward replay differs')
    elif name == ROUTE:
        authority_name, authority_pin = ROUTE_FIXTURE, ROUTE_FIXTURE_PIN
        authority = capture(authority_name, authority_pin)
        value = json.loads(authority, object_pairs_hook=_pairs)
        if (set(value) != {'schema', 'path', 'predecessor_commit', 'scope',
                          'original_method_identities_unchanged', 'original_assertions_unchanged',
                          'original_deadlines_unchanged', 'whole_native_delivery_qualified', 'record'}
                or value['schema'] != 'hepta.hia.artifact-route-cold-selection.v1'
                or value['path'] != ROUTE
                or value['predecessor_commit'] != '1213225f6a554f236dd7d6ed76607e799fd068e5'
                or value['scope'] != 'STRICT_COLD_COMPILER_SELECTION_ONLY'
                or value['original_method_identities_unchanged'] is not True
                or value['original_assertions_unchanged'] is not True
                or value['original_deadlines_unchanged'] is not True
                or value['whole_native_delivery_qualified'] is not False):
            raise ValueError('artifact route cold-selection history scope differs')
        restored = frozen.history_inverse(raw, value['record'], REVIEWED[name])
    else:
        authority_name, authority_pin = (
            (ASSEMBLY_FIXTURE, ASSEMBLY_FIXTURE_PIN) if name == ASSEMBLY
            else (PUBLICATION_FIXTURE, PUBLICATION_FIXTURE_PIN))
        authority = capture(authority_name, authority_pin)
        value = json.loads(authority, object_pairs_hook=_pairs)
        if name == ASSEMBLY:
            if (set(value) != {'schema', 'path', 'original_commit', 'physical_commit',
                              'scope', 'original_methods_unchanged', 'added_ordered_ids',
                              'whole_native_delivery_qualified', 'record'}
                    or value['schema'] != 'hepta.hia.artifact-assembly-source-successor.v1'
                    or value['path'] != ASSEMBLY
                    or value['original_commit'] != '5bf69586b890706290c5fbfe93065ec0d3af40b1'
                    or value['physical_commit'] != '241551d273c98561225263750ba98d11d93bf81c'
                    or value['scope'] != 'ORIGINAL_ASSEMBLY_18_PLUS_EXACT_TWO_SUCCESSOR_METHODS'
                    or value['original_methods_unchanged'] is not True
                    or value['whole_native_delivery_qualified'] is not False
                    or type(value['added_ordered_ids']) is not list
                    or value['added_ordered_ids'] != list(ASSEMBLY_ADDED_IDS)):
                raise ValueError('artifact assembly source history scope differs')
            record = value['record']
            added = list(ASSEMBLY_ADDED_IDS)
        else:
            if (set(value) != {'schema', 'predecessor_commit', 'scope',
                              'whole_native_delivery_qualified', 'files'}
                    or value['schema'] != 'hepta.hia.artifact-publication-native-cold-source-history.v1'
                    or value['predecessor_commit'] != 'd38ca48f4bac7a4ebba4ed9f6175d6e5f57aacb9'
                    or value['scope'] != 'HOST_BUILD_CUSTODY_AND_TEST_COMPILER_SELECTION_ONLY'
                    or value['whole_native_delivery_qualified'] is not False
                    or set(value['files']) != {'tools/build_hia_artifact_publication.py', PUBLICATION}):
                raise ValueError('artifact publication source history scope differs')
            entry = value['files'][name]
            if set(entry) != {'old', 'new', 'hunks'}:
                raise ValueError('artifact publication history record shape differs')
            record = {'old_bytes': entry['old']['bytes'], 'old_sha256': entry['old']['sha256'],
                      'new_bytes': entry['new']['bytes'], 'new_sha256': entry['new']['sha256'],
                      'hunks': entry['hunks']}
        restored = frozen.history_inverse(raw, record, REVIEWED[name])
    if pin(restored) != REVIEWED[name]:
        raise ValueError('artifact history did not restore its complete predecessor')
    if any(take(path) != value for path, value in captured.items()):
        raise ValueError('artifact source history inputs changed at terminal')
    return restored, {
        'path': name, 'physical': physical_pin, 'reviewed_predecessor': pin(restored),
        'helper': {'path': FROZEN_HELPER, **FROZEN_HELPER_PIN},
        'authority': {'path': authority_name, **authority_pin},
        'added_ordered_ids': added,
        **({'strict_cold_compiler_selection_only': True} if name == ROUTE else {}),
        **({'native_result_assertion_successor': assertion_successor}
           if assertion_successor is not None else {}),
        'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'terminal_reread_identical': True, 'source_history_only': True,
        'whole_native_delivery_qualified': False,
    }


def predecessor(root, name, raw, *, take=Path.read_bytes):
    return reviewed(root, name, raw, take=take)[0]
