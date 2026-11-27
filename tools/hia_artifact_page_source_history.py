"""Data-only whole-file predecessor of the explicit Artifact Page integration.

Only the three exact published successors are projected. Captures always
describe the real selected files; prior_take is a named historical view for
an older complete-file gate. Unknown bytes receive no history exception.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path

SELF = 'tools/hia_artifact_page_source_history.py'
FIXTURE = 'tests/fixtures/hia_artifact_page_shared_source_history_v1.json'
FIXTURE_SHA256 = '1d93e90b03531a76caed756efe3765286a4893c97530ac1d9718de00f298548a'
CURRENT = {'hepta/hia_agent_service.py': {'bytes': 269212, 'sha256': 'dd7f26a1892e2ae502b5aa166d1722159e9ab92aa6161c9f7bce76f925a4c095'}, 'hepta/hia_native_helpers.py': {'bytes': 31306, 'sha256': 'd50438613fc3324434ae4d9a1b3cee9f89ee5ccc35ee1a823a94f375ed4e41d1'}, 'hepta/hia_worker_bundle.py': {'bytes': 9204, 'sha256': '9cd75b900a94921aab637c9e4622cd423754d510fedda719b33c51be11750aff'}}
PREDECESSORS = {'hepta/hia_agent_service.py': {'bytes': 268730, 'sha256': '353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1'}, 'hepta/hia_native_helpers.py': {'bytes': 30812, 'sha256': 'a692a261bcc86943526f93f2ff5fb76c5351ad6a0ce5683ddf46cbdc132a13a9'}, 'hepta/hia_worker_bundle.py': {'bytes': 7950, 'sha256': '58c847116bf4d747e291d199acd38f71736a3b368386a0b448581e99802c5c09'}}
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()


def _pin(raw):
    if type(raw) is not bytes:
        raise ValueError('Page source history requires exact byte inputs')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _apply(raw, record, *, inverse):
    source = 'after' if inverse else 'before'
    target = 'before' if inverse else 'after'
    if _pin(raw) != record[source]:
        raise ValueError('Page whole source is outside the fixed history')
    position = 0
    parts = []
    for edit in record['edits']:
        offset = edit[source + '_offset']
        old = base64.b64decode(edit[source], validate=True)
        new = base64.b64decode(edit[target], validate=True)
        if (type(offset) is not int or offset < position
                or raw[offset:offset + len(old)] != old):
            raise ValueError('Page fixed source splice differs')
        parts.extend((raw[position:offset], new))
        position = offset + len(old)
    parts.append(raw[position:])
    result = b''.join(parts)
    if _pin(result) != record[target]:
        raise ValueError('Page complete predecessor identity differs')
    return result


class _History:
    def __init__(self, root, take):
        self.root = Path(root).absolute()
        self.take = take
        self._actual = {}
        self._prior = {}
        self._records = None
        if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('executing Page history changed after import')
        if self._read(self.root / SELF) != _EXECUTED_SOURCE:
            raise ValueError('selected Page history is not the executing source')
        fixture = self._read(self.root / FIXTURE)
        if sha256(fixture).hexdigest() != FIXTURE_SHA256:
            raise ValueError('Page fixed source history fixture differs')
        records = json.loads(fixture)['records']
        if set(records) != set(CURRENT) or any(
                records[name]['after'] != CURRENT[name]
                or records[name]['before'] != PREDECESSORS[name]
                for name in CURRENT):
            raise ValueError('Page complete source history inventory differs')
        self._records = records

    def _name(self, path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('Page history requires an exact selected-root path')
        try:
            name = path.relative_to(self.root).as_posix()
        except ValueError as error:
            raise ValueError('Page source is outside the selected root') from error
        if name in ('', '.') or name.startswith('../'):
            raise ValueError('invalid Page source path')
        return name

    def _read(self, path):
        path = Path(path)
        name = self._name(path)
        raw = self.take(path)
        _pin(raw)
        old = self._actual.get(name)
        if old is not None and raw != old:
            raise ValueError('actual Page history input changed')
        self._actual[name] = raw
        return raw

    def bind(self, name, raw):
        actual = self._read(self.root / name)
        if actual != raw or _pin(actual) != CURRENT[name]:
            raise ValueError('supplied Page source differs from the selected physical file')
        prior = _apply(actual, self._records[name], inverse=True)
        if _apply(prior, self._records[name], inverse=False) != actual:
            raise ValueError('Page complete history forward replay differs')
        self._prior[name] = prior
        return prior

    def prior_take(self, path):
        actual = self._read(path)
        return self._prior.get(self._name(path), actual)

    @property
    def captures(self):
        return {name: _pin(raw) for name, raw in self._actual.items()}

    @property
    def review(self):
        self.verify_unchanged()
        return {
            'schema': 'hepta.hia.artifact-page-source-history-review.v1',
            'physical_inputs': self.captures,
            'historical_views': {name: _pin(raw) for name, raw in self._prior.items()},
            'complete_inverse_and_forward': True,
            'terminal_unchanged': True,
        }

    def verify_unchanged(self):
        if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('executing Page history changed after import')
        for name, before in tuple(self._actual.items()):
            if self._read(self.root / name) != before:
                raise ValueError('Page history input changed before return')

    verify = verify_unchanged


def prepare(root, physical, take=Path.read_bytes):
    if type(physical) is not dict or any(type(name) is not str for name in physical):
        raise ValueError('Page history requires an explicit source mapping')
    projected = dict(physical)
    selected = [name for name, raw in physical.items()
                if name in CURRENT and _pin(raw) == CURRENT[name]]
    if not selected:
        # Original domains do not acquire a new authority dependency.
        return projected, None
    history = _History(root, take)
    for name in selected:
        projected[name] = history.bind(name, physical[name])
    history.verify_unchanged()
    return projected, history
