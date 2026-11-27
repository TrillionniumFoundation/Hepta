"""Exact data-only predecessor view for the three Core companion integration sites.

The physical current capture and the historical source view remain distinct.
This module executes no product, builder, generator or test oracle.
"""
from __future__ import annotations

import base64
from hashlib import sha1, sha256
import json
from pathlib import Path

SELF = "tools/hia_core_three_source_history.py"
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()
FIXTURE = "tests/fixtures/hia_core_three_current_source_relation_v1.json"
FIXTURE_SHA256 = "a3a31dd441a2430f69745986712270dc2b5f1c27f9da1b6d04d3e32cab5f795f"
CURRENT = {
    "hepta/hia_core_lowering_native.py": "1d13684b7784572e6dd3ab04079dd79a698f761964f72d3d8477d6f8e9f9e0d7",
    "hepta/hia_core_lowering_selection.py": "746d4eb3270885b1fcc804034169bfd60c19e7b9a7f1ed81050c7689c50ac105",
    "hepta/hia_native_continuation_selection.py": "49992712014f95b2ada4a6c3b1e018f037bfa93802594097fb8c4e0ce50a113d",
}
PRIOR = {
    "hepta/hia_core_lowering_native.py": "1318348b9c435dd8481281f7616ca5f33b498ddcd59f864e8beea1c07d9712d6",
    "hepta/hia_core_lowering_selection.py": "8684ba2008a44efadf20ec0736b98a0f8848a509bfe5854c7a072de645834c8d",
    "hepta/hia_native_continuation_selection.py": "0b21aec25122b2b03918fc26cf0bd9dfeb2432b7d897bd4cd40cabdeb6ff379d",
}
DEPENDENCIES = (SELF, FIXTURE)


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Core source relation key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError(
                          "non-finite Core source relation value")))


def _decode(row):
    if (type(row) is not dict
            or set(row) != {"bytes", "sha256", "git_blob", "data_b64"}
            or type(row["bytes"]) is not int or row["bytes"] < 0
            or type(row["data_b64"]) is not str):
        raise ValueError("invalid exact Core source relation row")
    raw = base64.b64decode(row["data_b64"], validate=True)
    if (len(raw) != row["bytes"] or sha256(raw).hexdigest() != row["sha256"]
            or sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            != row["git_blob"]):
        raise ValueError("exact Core source relation bytes differ")
    return raw


class _History:
    def __init__(self, root, captured, take):
        self.root, self.take = root, take
        self.captures = {}
        self._saved = {}
        for name, expected in captured.items():
            if self.read(root / name) != expected:
                raise ValueError("Core source history input is not physical current bytes")
        self.module = self.read(root / SELF)
        if (self.module != _EXECUTED_SOURCE
                or Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE):
            raise ValueError("executing Core source history implementation differs")
        raw = self.read(root / FIXTURE)
        if sha256(raw).hexdigest() != FIXTURE_SHA256:
            raise ValueError("fixed Core source relation differs")
        relation = _json(raw)
        if (relation.get("schema") != "hepta.hia.core-three-current-source-relation.v1"
                or relation.get("prior_commit") != "4e5606cf5bf456e225cec3ec9a55dd7be187f69f"
                or relation.get("qualification_granted") is not False
                or type(relation.get("sources")) is not dict
                or set(relation["sources"]) != set(CURRENT)):
            raise ValueError("Core source relation provenance differs")
        self.priors = {}
        for name, pair in relation["sources"].items():
            if type(pair) is not dict or set(pair) != {"prior", "current"}:
                raise ValueError("invalid complete Core source relation")
            prior, current = _decode(pair["prior"]), _decode(pair["current"])
            if (sha256(prior).hexdigest() != PRIOR[name]
                    or sha256(current).hexdigest() != CURRENT[name]
                    or self.read(root / name) != current):
                raise ValueError("mixed or unknown current Core source integration")
            self.priors[name] = prior
        self.verify()

    def read(self, path):
        path = Path(path)
        name = path.relative_to(self.root).as_posix()
        if not name or ".." in path.relative_to(self.root).parts:
            raise ValueError("Core source capture escaped selected root")
        raw = self.take(path)
        if type(raw) is not bytes or path.read_bytes() != raw:
            raise ValueError("Core source capture is not actual physical bytes")
        if name in self._saved and self._saved[name] != raw:
            raise ValueError("Core source changed between captures")
        self.captures[name] = raw
        self._saved[name] = raw
        return raw

    def prior_take(self, path):
        self.verify()
        path = Path(path)
        physical = self.read(path)
        name = path.relative_to(self.root).as_posix()
        projected = self.priors.get(name, physical)
        self.verify()
        return projected

    def verify(self):
        if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
            raise ValueError("executing Core source history changed")
        if self.captures != self._saved:
            raise ValueError("published Core source capture changed")
        for name, raw in tuple(self._saved.items()):
            path = self.root / name
            if self.take(path) != raw or path.read_bytes() != raw:
                raise ValueError("Core source history physical input changed: " + name)


def prepare(root, captured, *, take=Path.read_bytes):
    if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
        raise ValueError("executing Core source history changed")
    if type(captured) is not dict:
        raise ValueError("Core source history requires an actual capture dictionary")
    root = Path(root).resolve(strict=True)
    active = False
    for name, raw in captured.items():
        if (type(name) is not str or type(raw) is not bytes
                or Path(name).is_absolute() or ".." in Path(name).parts):
            raise ValueError("invalid Core source history capture")
        if name in CURRENT:
            actual = take(root / name)
            if actual != raw or (root / name).read_bytes() != raw:
                raise ValueError("Core source history input is not actual physical bytes")
    # A partially reverted current composition cannot enter the legacy domain.
    # Missing members in a genuinely legacy synthetic root remain for its own gate.
    for name, expected in CURRENT.items():
        try:
            raw = take(root / name)
        except FileNotFoundError:
            continue
        if type(raw) is not bytes or (root / name).read_bytes() != raw:
            raise ValueError("Core source history probe is not physical")
        active |= sha256(raw).hexdigest() == expected
    if not active:
        return dict(captured), None
    state = _History(root, captured, take)
    projected = {name: state.priors.get(name, raw) for name, raw in captured.items()}
    history = {
        "prior_take": state.prior_take,
        "captures": state.captures,
        "review": {
            "schema": "hepta.hia.core-three-physical-source-history.v1",
            "fixture_sha256": FIXTURE_SHA256,
            "current": dict(CURRENT), "prior": dict(PRIOR),
            "qualification_granted": False,
        },
        "_state": state,
    }
    state._review_bytes = json.dumps(history["review"], sort_keys=True)
    state.verify()
    return projected, history


def verify_unchanged(history):
    if history is None:
        return
    if (type(history) is not dict or type(history.get("_state")) is not _History
            or history.get("captures") is not history["_state"].captures):
        raise ValueError("invalid Core source history terminal receipt")
    state = history["_state"]
    if (history.get("prior_take") != state.prior_take
            or json.dumps(history.get("review"), sort_keys=True) != state._review_bytes):
        raise ValueError("Core source history view or review changed")
    state.verify()
