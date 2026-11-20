"""Exact versioned preparation of the original Journal installed-wheel test.

The old complete test is retained as bytes. Only its package-resource staging
changes; all original test methods, assertions and deadlines remain in place.
This helper imports no product, builder, compiler, VM or retained test module.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

PATH = 'tests/test_hia_agent_journal_native.py'
HELPER = 'tests/hia_journal_installed_preparation.py'
FIXTURE = 'tests/fixtures/journal_installed_preparation_v2.json'
ARCHIVE = 'tests/fixtures/journal_installed_preparation_v1.py.txt'
PREPARATION = 'hepta.hia.journal-installed-resource-preparation.v2'
ORIGINAL = {'bytes': 48482, 'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077'}
CURRENT = {'bytes': 48798, 'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c'}
FIXTURE_PIN = {'bytes': 14729, 'sha256': '81914ecb2bef21e9c641282dc8530158146ecadd4b86e8e4e6b3f83e71b73e7b'}
SPLICE_IDS = ('complete-current-package-resources',
              'staged-byte-custody-before-original-wheel-build')
AGENT_SYMBOLS = ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES',
    'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES',
    'EMITTER_BUILD_FILES', 'BYTE_WRAPPER_BUILD_FILES', 'MACHINE_OBJECT_BUILD_FILES',
    'EXECUTION_OBSERVATION_BUILD_FILES', 'CONTINUATION_BUILD_FILES')
INTEGER_SYMBOLS = ('VM_INTEGER_DIVREM_RESOURCES', 'VM_INTEGER_ARITHMETIC_RESOURCES',
                   'VM_INTEGER_SCALAR_RESOURCES')
SOURCE_PATHS = (PATH, HELPER, FIXTURE, ARCHIVE)


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(',', ':')) + '\n').encode()


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('Journal preparation requires immutable source bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _safe(name):
    if (type(name) is not str or not name or '\x00' in name or '\\' in name
            or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
            or str(PurePosixPath(name)) != name or name == '.'):
        raise ValueError('Journal preparation resource path is not canonical')
    return name


def _read(root, name, captured):
    raw = (root / _safe(name)).read_bytes()
    if name in captured and captured[name] != raw:
        raise ValueError('Journal preparation source changed between reads: ' + name)
    captured[name] = raw
    return raw


def _unchanged(root, captured):
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('Journal preparation source changed at terminal reread: ' + name)


def _authority(root, captured):
    raw = _read(root, FIXTURE, captured)
    if pin(raw) != FIXTURE_PIN:
        raise ValueError('fixed Journal preparation authority changed')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.journal-installed-resource-preparation-authority.v2'
            or value['preparation_id'] != PREPARATION or value['path'] != PATH
            or encoded(value['original']) != encoded(ORIGINAL)
            or encoded(value['current']) != encoded(CURRENT)
            or encoded(value['original_archive']) != encoded({'path': ARCHIVE, **ORIGINAL})
            or value['original_method_count'] != 21 or len(value['original_method_ids']) != 21
            or len(set(value['original_method_ids'])) != 21
            or value['original_build_timeout_seconds'] != 120
            or value['original_install_timeout_seconds'] != 120
            or value['original_probe_timeout_seconds'] != 30
            or value['original_scope_budget_seconds'] != 1800
            or value['original_business_assertions_and_budgets_unchanged'] is not True
            or value['setup_required_resources_unchanged'] is not True
            or value['production_source_exceptions'] != []):
        raise ValueError('Journal preparation authority scope differs')
    return value


def _splices(value):
    if (type(value) is not dict or value.get('path') != PATH
            or encoded(value.get('original')) != encoded(ORIGINAL)
            or encoded(value.get('current')) != encoded(CURRENT)
            or type(value.get('splices')) is not list or len(value['splices']) != 2):
        raise ValueError('Journal preparation whole-source relation differs')
    result = []
    old_end = new_end = 0
    for index, record in enumerate(value['splices']):
        if (type(record) is not dict or set(record) != {
                'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or record['id'] != SPLICE_IDS[index]
                or type(record['old_offset']) is not int or type(record['new_offset']) is not int
                or record['old_offset'] < old_end or record['new_offset'] < new_end
                or type(record['old_hex']) is not str or type(record['new_hex']) is not str):
            raise ValueError('Journal preparation typed splice differs')
        try:
            before, after = bytes.fromhex(record['old_hex']), bytes.fromhex(record['new_hex'])
        except ValueError as error:
            raise ValueError('Journal preparation splice is not hexadecimal') from error
        if (not before or not after or before.hex() != record['old_hex']
                or after.hex() != record['new_hex']):
            raise ValueError('Journal preparation splice is not canonical')
        old_end = record['old_offset'] + len(before)
        new_end = record['new_offset'] + len(after)
        if old_end > ORIGINAL['bytes'] or new_end > CURRENT['bytes']:
            raise ValueError('Journal preparation splice exceeds complete source')
        result.append((record['old_offset'], record['new_offset'], before, after))
    return result


def restore_source(raw, value):
    """Reconstruct the complete old test, then replay the exact current test."""
    if pin(raw) != CURRENT:
        raise ValueError('Journal preparation current whole source differs')
    splices = _splices(value)
    original = raw
    for old_at, new_at, before, after in reversed(splices):
        if original[new_at:new_at + len(after)] != after:
            raise ValueError('Journal preparation inverse splice bytes differ')
        original = original[:new_at] + before + original[new_at + len(after):]
    if pin(original) != ORIGINAL:
        raise ValueError('Journal preparation inverse is not the complete original')
    replay = original
    for old_at, new_at, before, after in reversed(splices):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError('Journal preparation forward splice bytes differ')
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError('Journal preparation forward replay differs')
    return original


def admit_source(root, path, raw, original_pin):
    """Admit this exact current successor; callers retain their literal old path.

    Callers independently pin HELPER before importing it and bind every returned
    capture to their before/after source maps. Independent readers replay the
    fixed relation themselves instead of trusting this producer proof.
    """
    root = Path(root)
    if path != PATH or encoded(original_pin) != encoded(ORIGINAL) or pin(raw) != CURRENT:
        raise ValueError('Journal preparation is not an exception for this source')
    captured = {}
    if _read(root, PATH, captured) != raw:
        raise ValueError('Journal caller supplied different current source bytes')
    helper = _read(root, HELPER, captured)
    if helper != Path(__file__).read_bytes():
        raise ValueError('Journal preparation imported helper differs from captured source')
    value = _authority(root, captured)
    old = _read(root, ARCHIVE, captured)
    if pin(old) != ORIGINAL or restore_source(raw, value) != old:
        raise ValueError('Journal preparation retained original differs')
    _unchanged(root, captured)
    return {
        'schema': 'hepta.hia.journal-installed-resource-source-admission.v2',
        'preparation_id': PREPARATION, 'path': PATH,
        'original': dict(ORIGINAL), 'current': dict(CURRENT),
        'authority': {'path': FIXTURE, **FIXTURE_PIN},
        'archive': {'path': ARCHIVE, **ORIGINAL},
        'exact_splice_count': 2,
        'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'original_method_count': 21,
        'original_method_ids': value['original_method_ids'],
        'original_build_timeout_seconds': 120,
        'original_install_timeout_seconds': 120,
        'original_probe_timeout_seconds': 30,
        'original_scope_budget_seconds': 1800,
        'captured_files': {name: pin(data) for name, data in captured.items()},
        'terminal_reread_identical': True,
        'production_source_exceptions': [],
    }


def _literal(raw, name):
    tree = ast.parse(raw)
    declarations = [node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(declarations) != 1:
        raise ValueError('one literal Journal packaging declaration is required: ' + name)
    value = ast.literal_eval(declarations[0].value)
    if type(value) is not tuple or any(type(item) is not str or not item for item in value):
        raise ValueError('Journal packaging declaration is not an explicit string tuple')
    return value


def _admit_package_policy(name, raw, expected):
    """Accept the original policy or the exact extension-only v6 successor.

    The 176 Agent, 17 capture and three integer resources are unchanged.
    This is a whole-source inverse and replay, never a policy pin refresh.
    """
    if encoded(pin(raw)) == encoded(expected):
        return
    if (name != 'setup.py' or encoded(expected) != encoded({'bytes': 4839, 'sha256': 'be518d19561790ca7c07f54c70a3d98899b460ff717ca3d93c381cdbb5a2c89f'})
            or pin(raw) != {'bytes': 5398, 'sha256': 'dbd27976a0d5e411da4c3affee239f66af03fcde22651237987b7a64acf330a8'}):
        raise ValueError('Journal current package policy changed: ' + name)
    pieces = (
        (873, 873, b'ROOT=Path(__file__).resolve().parent\n', b'_image_spec = spec_from_file_location(\n    \'_hepta_native_carrier_build\', Path(__file__).resolve().parent / \'hepta/native/native_carrier_build.py\')\n_image_build = module_from_spec(_image_spec)\n_image_spec.loader.exec_module(_image_build)\n\nclass AllMechanicalBuildExt(_image_build.NativeCarrierBuildExt, MechanicalBuildExt):\n    """Independent exact receipts; each original builder handles only its ABI."""\n    pass\n\nROOT=Path(__file__).resolve().parent\n'),
        (4632, 5048, b"setup(cmdclass={'build_py':AgentResourceBuild, 'build_ext':MechanicalBuildExt},\n      ext_modules=extensions(),\n      package_data={'hepta': ['native/slot_mechanical.c', 'native/slot_mechanical_build.py']})\n", b"setup(cmdclass={'build_py':AgentResourceBuild, 'build_ext':AllMechanicalBuildExt},\n      ext_modules=extensions() + _image_build.extensions(),\n      package_data={'hepta': ['native/slot_mechanical.c', 'native/slot_mechanical_build.py',\n                              'native/native_image.c', 'native/cell_frame.c', 'native/native_carrier_build.py']})\n"),
    )
    original = raw
    for old_at, new_at, before, after in reversed(pieces):
        if original[new_at:new_at + len(after)] != after:
            raise ValueError('Journal native-carrier setup inverse differs')
        original = original[:new_at] + before + original[new_at + len(after):]
    if encoded(pin(original)) != encoded(expected):
        raise ValueError('Journal native-carrier setup whole original differs')
    replay = original
    for old_at, new_at, before, after in reversed(pieces):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError('Journal native-carrier setup replay segment differs')
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError('Journal native-carrier setup whole replay differs')



def prepare_resources(root, original_resources):
    """Read the unchanged build policy as data and capture every required input."""
    root = Path(root)
    source_proof = admit_source(root, PATH, (root / PATH).read_bytes(), ORIGINAL)
    captured = {}
    for name, expected in source_proof['captured_files'].items():
        if pin(_read(root, name, captured)) != expected:
            raise ValueError('Journal source changed after source admission: ' + name)
    value = _authority(root, captured)
    for name, expected in value['policy_sources'].items():
        _admit_package_policy(name, _read(root, name, captured), expected)
    contract = captured['hepta/hia_agent_contract.py']
    discovery = _literal(contract, AGENT_SYMBOLS[0])
    if any(PurePosixPath(name).name != name for name in discovery):
        raise ValueError('Journal discovery resource filename differs')
    agent = tuple('docs/' + name for name in discovery)
    for symbol in AGENT_SYMBOLS[1:]:
        agent += _literal(contract, symbol)
    capture = _literal(captured['hepta/hia_executable_capture.py'], 'PACKAGE_RESOURCES')
    integers = tuple(name for symbol in INTEGER_SYMBOLS
                     for name in _literal(captured['setup.py'], symbol))
    if (type(original_resources) is not tuple or original_resources != agent
            or list(agent) != value['original_agent_resources']
            or list(capture) != value['current_executable_capture_resources']
            or list(integers) != value['current_integer_resources']
            or (len(agent), len(capture), len(integers)) != (176, 17, 3)):
        raise ValueError('Journal original or additional package resource inventory differs')
    resources = agent + capture + integers
    if len(set(resources)) != 196:
        raise ValueError('Journal package resources overlap')
    for name in resources + ('setup.py', 'pyproject.toml', 'MANIFEST.in'):
        _read(root, name, captured)
    _unchanged(root, captured)
    return resources, {
        'schema': 'hepta.hia.journal-installed-resource-preparation.v2',
        'preparation_id': PREPARATION, 'source_admission': source_proof,
        'original_resource_count': 176, 'additional_resource_count': 20,
        'current_resource_count': 196, 'resources': list(resources),
        'copied_paths': list(resources + ('setup.py', 'pyproject.toml', 'MANIFEST.in')),
        'captured_files': {name: pin(data) for name, data in captured.items()},
        'original_build_timeout_seconds': 120, 'original_install_timeout_seconds': 120,
        'original_probe_timeout_seconds': 30, 'original_scope_budget_seconds': 1800,
        'setup_required_resources_unchanged': True,
        'original_business_assertions_unchanged': True,
        'whole_native': False,
    }


def verify_staged_resources(root, staged, preparation, receipt):
    """Keep staging-byte custody before the unchanged wheel and installed tests."""
    root, staged, receipt = Path(root), Path(staged), Path(receipt)
    authority_raw = (root / FIXTURE).read_bytes()
    if pin(authority_raw) != FIXTURE_PIN:
        raise ValueError('Journal staging authority changed')
    authority = json.loads(authority_raw)
    resources = (authority['original_agent_resources']
                 + authority['current_executable_capture_resources']
                 + authority['current_integer_resources'])
    copied = resources + ['setup.py', 'pyproject.toml', 'MANIFEST.in']
    expected_paths = set(SOURCE_PATHS) | set(authority['policy_sources']) | set(copied)
    fixed = {
        'schema': 'hepta.hia.journal-installed-resource-preparation.v2',
        'preparation_id': PREPARATION, 'original_resource_count': 176,
        'additional_resource_count': 20, 'current_resource_count': 196,
        'resources': resources, 'copied_paths': copied,
        'original_build_timeout_seconds': 120, 'original_install_timeout_seconds': 120,
        'original_probe_timeout_seconds': 30, 'original_scope_budget_seconds': 1800,
        'setup_required_resources_unchanged': True,
        'original_business_assertions_unchanged': True, 'whole_native': False,
    }
    if (type(preparation) is not dict
            or set(preparation) != set(fixed) | {'source_admission', 'captured_files'}
            or any(encoded(preparation.get(name)) != encoded(value) for name, value in fixed.items())
            or type(preparation.get('captured_files')) is not dict
            or set(preparation['captured_files']) != expected_paths):
        raise ValueError('Journal staged preparation inventory differs')
    source_proof = admit_source(root, PATH, (root / PATH).read_bytes(), ORIGINAL)
    if encoded(preparation.get('source_admission')) != encoded(source_proof):
        raise ValueError('Journal staged source admission differs')
    observed = {}
    for name, expected in preparation['captured_files'].items():
        raw = (root / _safe(name)).read_bytes()
        if encoded(pin(raw)) != encoded(expected):
            raise ValueError('Journal preparation source changed before wheel build: ' + name)
        observed[name] = raw
    staged_pins = {}
    for name in copied:
        raw = (staged / name).read_bytes()
        if raw != observed[name]:
            raise ValueError('Journal staged package bytes differ: ' + name)
        staged_pins[name] = pin(raw)
    # Policy modules are carried by the original hepta copytree, not by a new
    # product loader. Verify those two copies too; the build hook stays intact.
    for name in ('hepta/hia_agent_contract.py', 'hepta/hia_executable_capture.py'):
        raw = (staged / name).read_bytes()
        if raw != observed[name]:
            raise ValueError('Journal staged package policy differs: ' + name)
        staged_pins[name] = pin(raw)
    _unchanged(root, observed)
    report = dict(preparation)
    report['staged_files'] = staged_pins
    report['source_terminal_reread_identical'] = True
    report['staged_required_bytes_identical'] = True
    report['qualification'] = 'PREPARATION_ONLY_ORIGINAL_WHEEL_AND_INSTALLED_ASSERTIONS_STILL_REQUIRED'
    with receipt.open('xb') as stream:
        stream.write(encoded(report))
    return report
