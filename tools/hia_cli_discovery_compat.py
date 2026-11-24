"""Pinned historical inputs and current verified-build compatibility controls.

This is qualification support. Archived source bytes are regression inputs only;
runtime selection continues to load the single current discovery HIA owner.
"""
from __future__ import annotations

import base64
import builtins
from hashlib import sha1, sha256
import json
from pathlib import Path
import sys
from types import ModuleType
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_cli_discovery_verified_build.json'
FIXTURE_SHA256 = '21f399cdb8e6d89f4a911a3f566e2cd0caba3fa459ed7b5d2acd8da2c3ed8e76'
R5_SOURCE_NAME = 'examples/hia_bootstrap/cli_discovery_json.hepta'
R5_SOURCE_SHA256 = '8e14590337e501c2315befe8dea1df9f6e7b02dbda28ca82d54b2f20959ed543'
WORD_FIXTURE = ROOT / 'tests/fixtures/hia_cli_discovery_word_memory.json'
WORD_FIXTURE_SHA256 = '278d8b2ae36291a849f195fa6a5627a0e5482d23d91135786eb93fd930ebca3e'

DEFAULT_SUCCESSOR = ROOT / 'tests/fixtures/hia_cli_discovery_default_successor.json'
DEFAULT_SUCCESSOR_SHA256 = 'e033a6674560cbdf044082e06f1f85163f425d5afd3ad51c21fdb580015ff39f'
PROFILE_3123_SUCCESSOR = ROOT / 'tests/fixtures/hia_cli_native_3123_successor.json'
PROFILE_3123_SUCCESSOR_SHA256 = '754ee74a576b3ea7c2309ec9cf39a255bf5590373077c12606789fa09c7d4d6b'
WHEEL_TEST_SUCCESSOR = ROOT / 'tests/fixtures/hia_cli_native_wheel_test_successor.json'
WHEEL_TEST_SUCCESSOR_SHA256 = '9d191fc37aca4f661bc50814ac61248655b6914efa6693daae8e9ca8c6b8d550'


def fixture():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('verified-build compatibility fixture changed')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.cli-discovery-verified-build-compat.v1'
            or value['base_commit'] != 'f33d8da316de8fdf27b504371f1a5310997ff548'
            or value['feature_head'] != '633feee656f000e2a9b683b366e391b5eefe3ce1'):
        raise ValueError('verified-build compatibility source identity differs')
    return value


def original_source(name):
    row = fixture()['original_sources'][name]
    raw = zlib.decompress(base64.b64decode(row['data'], validate=True))
    blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if len(raw) != row['bytes'] or sha256(raw).hexdigest() != row['sha256'] or blob != row['git_blob']:
        raise ValueError('archived original source bytes differ')
    return raw


def word_fixture():
    raw = WORD_FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != WORD_FIXTURE_SHA256:
        raise ValueError('word-memory compatibility fixture changed')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.cli-discovery-word-memory-compat.v1'
            or value['base_commit'] != 'f33d8da316de8fdf27b504371f1a5310997ff548'
            or value['feature_head'] != 'd99855451c8140899c85cf264b330a81a1c00362'
            or value['verified_build_head'] != '633feee656f000e2a9b683b366e391b5eefe3ce1'):
        raise ValueError('word-memory compatibility source identity differs')
    return value


_WORD_MEMORY_DESCRIPTION = 'bounded primitive Core v9 with scalar exports'
_DUAL_VERSION_DESCRIPTION = 'bounded primitive Core v8/v9 with scalar exports'
_LOADED_SOURCE_TAIL = (
    '\n# Bind this executing module, including its top-level constants, to retained source.\n'
    'from .hia_loaded_source import register_loaded_module as _register_loaded_source\n'
    '_register_loaded_source(__name__)\n'
)
_ASSEMBLY_REGENERATION_CHECK = (
    '    def test_assembly_driver_source_regenerates(self):\n'
    '        from tools.generate_hia_assembly_driver import SOURCE, document, render_assembly, source_program\n'
    '\n'
    '        self.assertEqual(SOURCE.read_text(), render_assembly(document(source_program(), "assembly_driver")))\n'
    '\n'
)
_WORD_MEMORY_SUCCESSOR_EDITS = {
    'hepta/cli.py': (_DUAL_VERSION_DESCRIPTION, _WORD_MEMORY_DESCRIPTION),
    'hepta/hia_opcodes.py': (_LOADED_SOURCE_TAIL, ''),
    'hepta/hia_schema.py': (_LOADED_SOURCE_TAIL, ''),
    'tests/test_hia_cli_native.py': (_ASSEMBLY_REGENERATION_CHECK, ''),
}


BYTE_DISCOVERY_GENERATION = {
    'source_sha256': '8958fae49aee88ae3f4b472511e2b7d5e7753ef6ea5f8951903c2dedfe8d75e6',
    'source_bytes': 278998,
    'counts': {'functions': 40, 'blocks': 257, 'operations': 5945, 'max_ssa': 540},
    'table_sha256': 'afe3dfd94966e954f311f2a756528846e871fe4da86bd3fb29dd4558242dcdb3',
}

CURRENT_DISCOVERY_GENERATION = {
    'source_sha256': 'f8b22394340c55293304cda3678ce70c6171cad296dd99c785650ef00785741a',
    'source_bytes': 272735,
    'counts': {'functions': 40, 'blocks': 257, 'operations': 5764, 'max_ssa': 540},
    'table_sha256': BYTE_DISCOVERY_GENERATION['table_sha256'],
}


def dual_version_capabilities():
    """The reviewed v8/v9 route adds back v8 without altering other capabilities."""
    expected = word_fixture()['current_capabilities']
    selfhost = expected['build']['selfhost']
    if selfhost['input'] != _WORD_MEMORY_DESCRIPTION:
        raise ValueError('original word-memory capability source differs')
    selfhost['input'] = _DUAL_VERSION_DESCRIPTION
    return expected


def word_original_source(name):
    row = word_fixture()['pre_v9_sources'][name]
    raw = zlib.decompress(base64.b64decode(row['data'], validate=True))
    blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if len(raw) != row['bytes'] or sha256(raw).hexdigest() != row['sha256'] or blob != row['git_blob']:
        raise ValueError('archived pre-v9 source bytes differ')
    return raw


def legacy_catalog_owner():
    """Execute both complete pinned v8 sources only as an independent test oracle."""
    schema = ModuleType('hepta._cli_discovery_frozen_schema')
    schema.__package__ = 'hepta'
    schema_raw = word_original_source('hepta/hia_schema.py')
    exec(compile(schema_raw, '<pinned-v8-hia_schema>', 'exec'), schema.__dict__)
    catalog = ModuleType('hepta._cli_discovery_frozen_opcodes')
    catalog.__package__ = 'hepta'
    imports = []
    ordinary_import = builtins.__import__
    def frozen_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'hia_schema':
            imports.append((name, fromlist))
            return schema
        return ordinary_import(name, globals, locals, fromlist, level)
    catalog.__dict__['__builtins__'] = {**vars(builtins), '__import__': frozen_import}
    raw = word_original_source('hepta/hia_opcodes.py')
    missing = object()
    previous = sys.modules.get(catalog.__name__, missing)
    sys.modules[catalog.__name__] = catalog
    try:
        exec(compile(raw, '<pinned-v8-hia_opcodes>', 'exec'), catalog.__dict__)
    finally:
        if previous is missing:
            del sys.modules[catalog.__name__]
        else:
            sys.modules[catalog.__name__] = previous
    if (imports != [('hia_schema', ('LATEST_CORE_SCHEMA', 'PRIMITIVE_PROFILES'))]
            or tuple(catalog.PRIMITIVE_PROFILES) != tuple('hepta.hia.program.v'+str(i) for i in range(1,9))
            or len(catalog.OPCODES) != 50 or catalog.LATEST_CORE_SCHEMA != 'hepta.hia.program.v8'):
        raise ValueError('independent original catalog oracle domain differs')
    return catalog


def before_default_cli(name, current):
    """Undo only the pinned installed-owner and wheel fixture changes."""
    raw = DEFAULT_SUCCESSOR.read_bytes()
    if sha256(raw).hexdigest() != DEFAULT_SUCCESSOR_SHA256:
        raise ValueError('default CLI successor fixture changed')
    fixture = json.loads(raw)
    if (fixture['schema'] != 'hepta.hia.cli-default-successor.v1'
            or fixture['previous_commit'] != 'f0f37454f4dc03fdddbe8907a2499cf55cb08554'):
        raise ValueError('default CLI successor identity differs')
    row = fixture['files'].get(name)
    if row is None:
        return current
    if name == 'hepta/cli.py' and sha256(current.encode()).hexdigest() == 'e66c2cdc3a66ca1f3f09c813b5f279cfb60fad7b972e6b708179fb5c93b9bdee':
        # Undo only native nominal preverification; the original parser bytes stay pinned.
        active = "        if args.hia_action == 'build' and args.backend == 'selfhost':\n            from .hia_program_selfhost import _verify_selfhost_input\n            program, _nominal_schema = _verify_selfhost_input(read_bounded(args.input))\n        else:\n            program = verify_program(read_bounded(args.input))\n"
        original = '        program = verify_program(read_bounded(args.input))\n'
        if current.count(active) != 1:
            raise ValueError('invalid nominal preverification parser inverse')
        current = current.replace(active, original)
        if sha256(current.encode()).hexdigest() != 'fbd72fd381d7eae7ca9ddff790809815aa34f24b86a8ae7fe24a33adea24517d':
            raise ValueError('nominal preverification predecessor source differs')
    if name == 'hepta/cli.py' and sha256(current.encode()).hexdigest() == 'fbd72fd381d7eae7ca9ddff790809815aa34f24b86a8ae7fe24a33adea24517d':
        # Reconstruct the already pinned parser oracle from the package-discovery opt-in.
        for active, original in (
            ('def _reference_hia_main(argv=None, *, package_discovery=False):', 'def _reference_hia_main(argv=None):'),
            ('selected_json(1, package_default=package_discovery)', 'selected_json(1)'),
            ('selected_json(2, args.schema, package_default=package_discovery)', 'selected_json(2, args.schema)'),
            ('return _reference_hia_main(argv, package_discovery=True)', 'return _reference_hia_main(argv)'),
        ):
            if current.count(active) != 1:
                raise ValueError('invalid package discovery parser inverse')
            current = current.replace(active, original)
    additions = {
        'hepta/hia_cli_native.py': (PROFILE_3123_SUCCESSOR, PROFILE_3123_SUCCESSOR_SHA256),
        'tests/test_hia_cli_native.py': (WHEEL_TEST_SUCCESSOR, WHEEL_TEST_SUCCESSOR_SHA256),
    }
    if name in additions and sha256(current.encode()).hexdigest() != row['current_sha256']:
        path, expected = additions[name]
        record = path.read_bytes()
        if sha256(record).hexdigest() != expected:
            raise ValueError('CLI successor fixture changed: ' + name)
        successor = json.loads(record)
        if successor['name'] != name or successor['previous_sha256'] != row['current_sha256']:
            raise ValueError('CLI predecessor identity differs: ' + name)
        current = _undo_cli_delta(name, current, successor)
    return _undo_cli_delta(name, current, row)


def _undo_cli_delta(name, current, row):
    if sha256(current.encode()).hexdigest() != row['current_sha256']:
        raise ValueError('source differs from the pinned default CLI successor: ' + name)
    lines = current.splitlines(keepends=True)
    for delta in reversed(row['deltas']):
        first = delta['first']
        expected = delta['current'].splitlines(keepends=True)
        last = first + len(expected)
        if lines[first:last] != expected:
            raise ValueError('invalid default CLI inverse delta: ' + name)
        lines[first:last] = delta['previous'].splitlines(keepends=True)
    previous = ''.join(lines)
    if sha256(previous.encode()).hexdigest() != row['previous_sha256']:
        raise ValueError('default CLI predecessor source differs: ' + name)
    return previous


def original_cli_source(name, normalized_current):
    """Admit only the exact reviewed feature bytes after undoing the five hooks."""
    word = word_fixture()
    expected_word = word['current_source_sha256'].get(name)
    if expected_word is not None:
        if name in ('examples/hia_bootstrap/cli_control.hepta', 'examples/hia_bootstrap/cli_format.hepta'):
            if sha256(normalized_current.encode()).hexdigest() != expected_word:
                raw = PROFILE_3123_SUCCESSOR.read_bytes()
                if sha256(raw).hexdigest() != PROFILE_3123_SUCCESSOR_SHA256:
                    raise ValueError('CPython 3.12.3 CLI successor fixture changed')
                compressed = json.loads(raw)['generated_assets'][name]
                row = json.loads(zlib.decompress(base64.b64decode(compressed, validate=True)))
                if row['name'] != name or row['previous_sha256'] != expected_word:
                    raise ValueError('CPython 3.12.3 CLI asset predecessor identity differs')
                normalized_current = _undo_cli_delta(name, normalized_current, row)
        change = _WORD_MEMORY_SUCCESSOR_EDITS.get(name)
        if change is not None:
            new, old = change
            if normalized_current.count(new) == 1:
                # The full pinned original digest below admits exactly one splice.
                normalized_current = normalized_current.replace(new, old, 1)
        if sha256(normalized_current.encode()).hexdigest() != expected_word:
            raise ValueError('CLI changes exceed the pinned word-memory feature: ' + name)
        normalized_current = word_original_source(name).decode()
    value = fixture()
    expected = value['verified_build_source_sha256'].get(name)
    if expected is None:
        return normalized_current
    if sha256(normalized_current.encode()).hexdigest() != expected:
        raise ValueError('CLI changes exceed the pinned verified-build feature: ' + name)
    return original_source(name).decode()


def r5_regression_image(directory, compiler, *, guard):
    """Compile the pinned original source with this observation's actual compiler."""
    from tools import hia_cli_discovery_custody as custody
    from tools.qualify_hia_selfhost import compile_stage
    directory, compiler = Path(directory), Path(compiler).resolve(strict=True)
    source = original_source(R5_SOURCE_NAME)
    custody.require(sha256(source).hexdigest() == R5_SOURCE_SHA256, 'original R5 source differs')
    guard()
    directory.mkdir(mode=0o700, exist_ok=True)
    source_path = directory / 'original-r5.hepta'
    if source_path.exists():
        custody.require(source_path.read_bytes() == source, 'retained original R5 source changed')
    else:
        source_path.write_bytes(source)
    label = 'cli-discovery-r5-regression'
    image = directory / (label + '.image.bin')
    if not image.exists():
        custody.require(set(directory.iterdir()) == {source_path}, 'partial R5 observation must be reviewed')
        observed, _ = compile_stage(directory, label, compiler, source)
        custody.require(Path(observed) == image, 'unexpected original R5 image path')
    guard()
    _receipt, inputs = custody.admit_compilation(directory, label, compiler, source, image)
    return image, source_path, inputs + [custody.binding(source_path), custody.binding(compiler)]
