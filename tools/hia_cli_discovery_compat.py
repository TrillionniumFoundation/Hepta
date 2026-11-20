"""Pinned historical inputs and current verified-build compatibility controls.

This is qualification support. Archived source bytes are regression inputs only;
runtime selection continues to load the single current discovery HIA owner.
"""
from __future__ import annotations

import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_cli_discovery_verified_build.json'
FIXTURE_SHA256 = '21f399cdb8e6d89f4a911a3f566e2cd0caba3fa459ed7b5d2acd8da2c3ed8e76'
R5_SOURCE_NAME = 'examples/hia_bootstrap/cli_discovery_json.hepta'
R5_SOURCE_SHA256 = '8e14590337e501c2315befe8dea1df9f6e7b02dbda28ca82d54b2f20959ed543'


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


def original_cli_source(name, normalized_current):
    """Admit only the exact reviewed feature bytes after undoing the five hooks."""
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
    _receipt, inputs = custody.admit_compilation(directory, label, compiler, source_path, image)
    return image, source_path, inputs + [custody.binding(source_path), custody.binding(compiler)]
