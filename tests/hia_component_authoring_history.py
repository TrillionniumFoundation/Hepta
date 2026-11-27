"""Exact predecessor bytes for the host component-custody migration.

This data-only reader changes no original observation or native authority.
Existing historical readers still validate the complete predecessor against
their own fixed pins after these five reviewed builder edits are reversed.
"""
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_component_authoring_successor_v1.json'
FIXTURE_SHA256 = '5aa32081d30e10ef29edec087c209031b21e617d9d00dcdb6338f404b01f2f5d'


# Newer inputs retain their separate whole-file fixtures. The existing 28-file
# authoring relation and every original expected predecessor remain unchanged.
CURRENT_INPUTS = {
    "tools/build_hia_service_bootstrap.py": {
        "current": {
            "bytes": 10309,
            "sha256": "0ac4ce2869a61fc7c4b9a86aa07bf92ea4b28cbc39651a0fa841adb1cf28469e"
        },
        "fixture": "tests/fixtures/hia_core_component_authoring_v1.json",
        "fixture_pin": {
            "bytes": 18735,
            "sha256": "9f8f0833b790d260fdfb7583758082b797009fd1f1a122854b3aa0a1fec1f39e"
        },
        "schema": "hepta.hia.core-component-authoring-history.v1"
    },
    "tools/build_hia_service_context.py": {
        "current": {
            "bytes": 5736,
            "sha256": "16f50573777652d5412fb4a381ae9a120f7e06d0e55b4ba354f1d3ad2f7245a0"
        },
        "fixture": "tests/fixtures/hia_core_component_authoring_v1.json",
        "fixture_pin": {
            "bytes": 18735,
            "sha256": "9f8f0833b790d260fdfb7583758082b797009fd1f1a122854b3aa0a1fec1f39e"
        },
        "schema": "hepta.hia.core-component-authoring-history.v1"
    },
    "tools/build_hia_store_artifact_profile.py": {
        "current": {
            "bytes": 7697,
            "sha256": "341b04b6464471367e51d2e1c201513d0ba6535f523275321b5850684c21e5f9"
        },
        "fixture": "tests/fixtures/hia_core_component_authoring_v1.json",
        "fixture_pin": {
            "bytes": 18735,
            "sha256": "9f8f0833b790d260fdfb7583758082b797009fd1f1a122854b3aa0a1fec1f39e"
        },
        "schema": "hepta.hia.core-component-authoring-history.v1"
    },
    "tools/build_hia_store_file_capture.py": {
        "current": {
            "bytes": 9143,
            "sha256": "f297be7d25d692944610306b37c4839feb9f0da64e8505071e56c80270a104b7"
        },
        "fixture": "tests/fixtures/hia_core_component_authoring_v1.json",
        "fixture_pin": {
            "bytes": 18735,
            "sha256": "9f8f0833b790d260fdfb7583758082b797009fd1f1a122854b3aa0a1fec1f39e"
        },
        "schema": "hepta.hia.core-component-authoring-history.v1"
    },
    "tools/build_hia_store_transaction.py": {
        "current": {
            "bytes": 7176,
            "sha256": "10fc790cee5445b533d869804ab21b036974164c3cc2006b15593092645beed5"
        },
        "fixture": "tests/fixtures/hia_core_component_authoring_v1.json",
        "fixture_pin": {
            "bytes": 18735,
            "sha256": "9f8f0833b790d260fdfb7583758082b797009fd1f1a122854b3aa0a1fec1f39e"
        },
        "schema": "hepta.hia.core-component-authoring-history.v1"
    },
    "tools/build_hia_evaluation.py": {
        "current": {
            "bytes": 5009,
            "sha256": "5416816ff26d34a6c1a3e9745560a7b4058a6a4f8b30b008dc40f40407d78e97"
        },
        "fixture": "tests/fixtures/hia_evaluation_component_install_inputs_v1.json",
        "fixture_pin": {
            "bytes": 1298,
            "sha256": "9576a1d5a6890e77a386223a1ceb99dcd2bcfb74facc65b69521b2346fe442c5"
        },
        "schema": "hepta.hia.evaluation-component-install-inputs-history.v1"
    }
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _current_predecessor(name, raw, *, root, take):
    spec = CURRENT_INPUTS.get(name)
    if spec is None or _pin(raw) != spec['current']:
        return raw
    if take(root / name) != raw:
        raise ValueError('current component authoring argument differs from its physical source')
    path = root / spec['fixture']
    frozen = take(path)
    if _pin(frozen) != spec['fixture_pin']:
        raise ValueError('fixed current component authoring fixture differs')
    value = json.loads(frozen)
    if (value.get('schema') != spec['schema']
            or value.get('original_fixed_fixtures_modified') is not False
            or value.get('historical_projection_is_physical_source') is not False):
        raise ValueError('current component authoring history scope differs')
    from tools import hia_frozen_component_sources as engine
    engine_raw = take(root / ENGINE)
    if _pin(engine_raw) != ENGINE_PIN or Path(engine.__file__).read_bytes() != engine_raw:
        raise ValueError('current component authoring inverse reader differs')
    row = value['files'][name]
    return engine.history_inverse(raw, row,
        {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})


def _captured_records(*, root=None, take=Path.read_bytes):
    root = ROOT if root is None else Path(root)
    path = root / FIXTURE
    raw = take(path)
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('fixed component authoring history differs')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.component-authoring-successor.v1'
            or value['predecessor_commit'] != '060ce11be28009e3769633bf43aeee16aa9a5414'
            or len(value['files']) != 28):
        raise ValueError('component authoring history scope differs')
    return value['files'], path, raw


def _records(*, root=None, take=Path.read_bytes):
    records, path, frozen = _captured_records(root=root, take=take)
    if take(path) != frozen:
        raise ValueError('component authoring fixture changed at terminal readback')
    return records


def predecessor(name, raw, *, root=None, take=Path.read_bytes):
    """Unwrap the exact new builder; leave every other input to its prior gate."""
    root = ROOT if root is None else Path(root)
    captured = {}

    def capture(path):
        data = take(path)
        if path in captured and captured[path] != data:
            raise ValueError('current component authoring input changed between captures')
        captured[path] = data
        return data

    raw = _current_predecessor(name, raw, root=root, take=capture)
    records, path, frozen = _captured_records(root=root, take=take)
    try:
        record = records.get(name)
        if record is None or sha256(raw).hexdigest() != record['new_sha256']:
            return raw
        if len(raw) != record['new_bytes']:
            raise ValueError('component authoring successor length differs')
        pieces, new_at, old_at = [], 0, 0
        for hunk in record['hunks']:
            before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
            offset = hunk['new_offset']
            gap = offset - new_at
            if (type(offset) is not int or type(hunk['old_offset']) is not int
                    or gap < 0 or hunk['old_offset'] != old_at + gap or before == after
                    or raw[offset:offset + len(after)] != after):
                raise ValueError('component authoring exact source splice differs')
            pieces.extend((raw[new_at:offset], before))
            new_at, old_at = offset + len(after), hunk['old_offset'] + len(before)
        original = b''.join((*pieces, raw[new_at:]))
        if (len(original) != record['old_bytes']
                or sha256(original).hexdigest() != record['old_sha256']):
            raise ValueError('complete component authoring predecessor differs')
        return original
    finally:
        if take(path) != frozen:
            raise ValueError('component authoring fixture changed at terminal readback')
        for current_path, current_raw in captured.items():
            if take(current_path) != current_raw:
                raise ValueError('current component authoring input changed at terminal readback')
