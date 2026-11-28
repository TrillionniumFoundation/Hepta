"""Whole-file, data-only preparation of the explicit predecessor proof domain.

A historical execution never establishes qualification of the current graph.
Physical current bytes and the complete projected predecessor are both held.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import zlib

ROOT = Path(__file__).resolve().parents[1]
SELF = 'tools/hia_behavior_source_history.py'
FIXTURE = 'tests/fixtures/hia_behavior_input_history_v7.json'
FIXTURE_SHA256 = '6215141499231dca05b9edf889d8113ea0745dbfe081d2f6db7c1224adbc215c'
_IMPORTED_SELF = (ROOT / SELF).read_bytes()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate behavior history field')
        result[key] = value
    return result


def _path(root, path):
    root = Path(root).absolute()
    path = Path(path)
    path = path if path.is_absolute() else root / path
    try:
        name = path.relative_to(root)
    except ValueError:
        raise ValueError('behavior history input escapes its explicit root') from None
    if '..' in name.parts or not name.parts:
        raise ValueError('behavior history input is not a confined file')
    return path, name.as_posix()


def _read(root, path, take, captures):
    path, name = _path(root, path)
    current = path
    while current != Path(root).absolute():
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('behavior history input uses a symlink')
        current = current.parent
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('behavior history input is not a regular file')
    raw = take(path)
    if type(raw) is not bytes:
        raise ValueError('behavior history capture is not complete bytes')
    if raw != path.read_bytes():
        raise ValueError('behavior history capture differs from actual physical input')
    value = (raw, stat.S_IMODE(info.st_mode))
    previous = captures.setdefault(name, value)
    if previous != value:
        raise ValueError('behavior history input changed between captures')
    return raw


def _whole(row):
    if row is None:
        return None
    if type(row) is not dict or set(row) != {'bytes', 'sha256', 'zlib_base64'}:
        raise ValueError('behavior history whole-file record differs')
    if type(row['bytes']) is not int or not 0 < row['bytes'] <= 2 << 20:
        raise ValueError('behavior history source extent differs')
    encoded = base64.b64decode(row['zlib_base64'], validate=True)
    reader = zlib.decompressobj()
    raw = reader.decompress(encoded, row['bytes'] + 1)
    if (len(raw) != row['bytes'] or not reader.eof or reader.unused_data
            or reader.unconsumed_tail or sha256(raw).hexdigest() != row['sha256']):
        raise ValueError('behavior history complete source bytes differ')
    return raw


def prepare(root, supplied=None, *, take=Path.read_bytes):
    root = Path(root).absolute()
    captures = {}
    if _read(root, root / SELF, take, captures) != _IMPORTED_SELF:
        raise ValueError('behavior history loaded reader differs from physical root')
    raw = _read(root, root / FIXTURE, take, captures)
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('behavior history immutable fixture differs')
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {'schema', 'scope', 'entries', 'stage_files'}
            or value['schema'] != 'hepta.hia.behavior-input-history.v1'
            or value['scope'] != 'EXPLICIT_PREDECESSOR_446_PORT_9_METHOD_DOMAIN'):
        raise ValueError('behavior history schema or qualification scope differs')
    entries = value['entries']
    if type(entries) is not dict or not entries:
        raise ValueError('behavior history source group is empty')
    if supplied is not None and (type(supplied) is not dict or set(supplied) - set(entries)):
        raise ValueError('behavior supplied source inventory differs')
    previous = {}
    for name, row in entries.items():
        if type(row) is not dict or set(row) != {'old', 'current'}:
            raise ValueError('behavior history source relation differs')
        old, current = _whole(row['old']), _whole(row['current'])
        if current is None or old == current:
            raise ValueError('behavior history relation lacks a complete successor')
        actual = _read(root, root / name, take, captures)
        if actual != current:
            raise ValueError('behavior history source is unknown or partially reverted: ' + name)
        if supplied is not None and name in supplied and supplied[name] != actual:
            raise ValueError('behavior supplied source differs from physical input')
        previous[name] = old
    files = value['stage_files']
    if (type(files) is not list or not files or len(set(files)) != len(files)
            or any(type(name) is not str for name in files)
            or set(entries) - set(files)):
        raise ValueError('behavior history complete stage inventory differs')
    projected = {}
    for name in files:
        actual = _read(root, root / name, take, captures)
        restored = previous.get(name, actual)
        if restored is not None:
            projected[name] = restored
    def prior_take(path):
        path, name = _path(root, path)
        # A newly introduced file has an explicit absent predecessor. Still
        # re-read its captured actual bytes before confirming that absence.
        if name in captures:
            _read(root, path, take, captures)
        if name not in projected:
            raise FileNotFoundError(str(path))
        return projected[name]
    history = {'root': root, 'take': take, 'captures': captures,
               'view': projected, 'prior_take': prior_take,
               'scope': value['scope'], 'entries': tuple(entries)}
    verify_unchanged(history)
    return projected, history


def verify_unchanged(history):
    root = history['root']
    for name, (raw, mode) in tuple(history['captures'].items()):
        got = _read(root, root / name, history['take'], history['captures'])
        if got != raw or stat.S_IMODE((root / name).stat().st_mode) != mode:
            raise ValueError('behavior history captured physical source changed')


def _pins(rows):
    return {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'mode': mode}
            for name, (raw, mode) in rows.items()}


@contextmanager
def original_view(root, destination, *, take=Path.read_bytes):
    view, history = prepare(root, take=take)
    destination = Path(destination).absolute()
    destination.mkdir(mode=0o700)
    expected = {}
    for name, raw in view.items():
        p = destination / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as stream:
            stream.write(raw)
        mode = history['captures'][name][1]
        p.chmod(mode)
        expected[name] = (raw, mode)
    report = {'schema': 'hepta.hia.behavior-predecessor-preparation.v1',
              'scope': history['scope'], 'current_graph_qualified': False,
              'physical_current_before': _pins(history['captures']),
              'complete_predecessor': _pins(expected)}
    try:
        yield destination, report, history
    finally:
        verify_unchanged(history)
        for name, (raw, mode) in expected.items():
            p = destination / name
            if p.read_bytes() != raw or stat.S_IMODE(p.stat().st_mode) != mode:
                raise ValueError('behavior predecessor stage changed')
        report['physical_current_after'] = _pins(history['captures'])
        report['physical_and_projected_unchanged'] = True
