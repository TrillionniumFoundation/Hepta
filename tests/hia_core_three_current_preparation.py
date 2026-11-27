"""Explicit current input preparation for the retained Core companion controls.

All original methods, assertions and budgets stay in the immutable ff636 corpus.
Three source-history methods examine the complete historical Core39 tree.  The
other twenty source methods execute the current physical companion code.  The
integer fixture's integration source is an exact current physical copy, never the
old embedded integration implementation.  Native methods keep their actual
manifest requirements.  This module grants no native or whole-Core qualification.
"""
from __future__ import annotations

import atexit
import base64
from contextlib import contextmanager
from functools import wraps
import gzip
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import tempfile
from types import SimpleNamespace

SELF = "tests/hia_core_three_current_preparation.py"
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()
OLD_COMMIT = "ff6360049d6b567f708532650ddbcddf4c55a63d"
CORPORA = {
    "tests/fixtures/hia_core_three_port_source_corpus_v1.json.gz":
        "92b73c76e198a89586a2051bc6696c3b171e7363a318fce2e53bcf133373b700",
    "tests/fixtures/hia_core_three_original_tests_ff636_v1.json.gz":
        "5f0bb084a8ea14b6319678b1259c5277b0a8287c8ea227b1dd4d5cf88f42e4ef",
    "tests/fixtures/hia_core_three_historical_metadata_v1.json.gz":
        "4cab26a6d749efa28bb0264957866813a8a6693992c33dd1e06585a8bfc504a6",
}
TESTS = {
    "compare": "tests/test_hia_core_compare_source.py",
    "integer": "tests/test_hia_core_integer_source.py",
    "unpack": "tests/test_hia_core_unpack_native.py",
}
CLASSES = {
    "compare": ("ExactNumericComparisonSourceTests",),
    "integer": ("ExactIntegerSourceTests",),
    "unpack": ("UnpackCompositionSourceTests", "UnpackCompositionNativeTests"),
}
HISTORICAL_METHODS = {
    "compare": "test_complete_Core39_outer_protocol_and_original116_are_unchanged",
    "integer": "test_original_population_and_unrelated_lowering_bodies_unchanged",
    "unpack": "test_original_39_units_and_Core_ABI_are_unchanged",
}
MARKER = b"\nif __name__ == '__main__':\n"
_STATES = {}


def insertion(family):
    if type(family) is not str or family not in TESTS:
        raise ValueError("unknown retained Core companion family")
    return (
        b"\n# Current physical inputs and explicitly separate historical source assertions.\n"
        b"from tests.hia_core_three_current_preparation import install as _prepare_current_core\n"
        + ("_prepare_current_core(globals(), " + repr(family) + ")\n").encode()
    )


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Core preparation data key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("non-finite Core preparation data")))


def _decode(row):
    if (type(row) is not dict or type(row.get("bytes")) is not int
            or row["bytes"] < 0 or type(row.get("data_b64")) is not str):
        raise ValueError("invalid frozen Core source row")
    raw = base64.b64decode(row["data_b64"], validate=True)
    if (len(raw) != row["bytes"] or sha256(raw).hexdigest() != row["sha256"]
            or sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            != row["git_blob"]):
        raise ValueError("frozen Core source bytes differ")
    return raw


def _name(name):
    if (type(name) is not str or not name or "\\" in name
            or PurePosixPath(name).is_absolute()
            or any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("invalid Core preparation source path")
    return name


def source_inputs(root):
    names = {
        SELF, *CORPORA, *TESTS.values(),
        "tests/hia_core_pc_expected.py",
        "hepta/hia_core_lowering_native.py",
        "hepta/hia_core_lowering_selection.py",
        "hepta/hia_native_continuation_selection.py",
        "docs/HIA_CORE_LOWERING_ABI.json",
        "hepta/hia_program.py",
        "hepta/hia_program_runtime.py",
        "hepta/hia_agent_assembly.py",
        "hepta/hia_native_helpers.py",
        "tools/generate_hia_selfhost.py",
        "tools/hia_core_companion_build.py",
        "tools/hia_core_unpack_transaction.S",
        "tools/hia_core_three_source_history.py",
        "tests/fixtures/hia_core_three_current_source_relation_v1.json",
        "tests/test_hia_core_three_current_preparation.py",
        "tests/test_hia_core_companion_continuation.py",
    }
    for family in TESTS:
        names.update({
            "examples/hia_bootstrap/core_" + family + ".hepta",
            "hepta/hia_core_" + family + "_abi.json",
            "hepta/hia_core_" + family + "_native.py",
            "hepta/hia_core_" + family + "_selection.py",
            "tools/generate_hia_core_" + family + ".py",
            "tools/build_hia_core_" + family + ".py",
        })
    abi = _json((root / "docs/HIA_CORE_LOWERING_ABI.json").read_bytes())
    if type(abi) is not dict or type(abi.get("units")) is not list:
        raise ValueError("current physical Core inventory is missing")
    for unit in ("core_lowering_pool", *abi["units"]):
        if type(unit) is not str or not unit.startswith("core_lowering_"):
            raise ValueError("current physical Core unit name differs")
        names.add(_name("examples/hia_bootstrap/" + unit + ".hepta"))
    return tuple(sorted(names))


class CapturedInputs:
    """Physical current source plus a separately labelled immutable old view."""

    def __init__(self, root, *, take=Path.read_bytes, materialize=False):
        self.root = Path(root).resolve(strict=True)
        self.take = take
        if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
            raise ValueError("executing Core preparation source changed")
        self.saved = {}
        for name in source_inputs(self.root):
            path = self.root / name
            raw = take(path)
            if type(raw) is not bytes or path.read_bytes() != raw:
                raise ValueError("Core capture must contain actual physical bytes")
            self.saved[name] = raw
        if self.saved[SELF] != _EXECUTED_SOURCE:
            raise ValueError("selected-root Core preparation implementation differs")
        self.old = {}
        self.base = {}
        for name, expected in CORPORA.items():
            raw = self.saved[name]
            if sha256(raw).hexdigest() != expected:
                raise ValueError("fixed Core source corpus differs")
            value = _json(gzip.decompress(raw))
            if (value.get("historical_commit") != OLD_COMMIT
                    or value.get("qualification_granted") is not False
                    or type(value.get("files")) is not dict):
                raise ValueError("Core source corpus provenance differs")
            for path, row in value["files"].items():
                _name(path)
                item = _decode(row)
                if path.startswith("current-base/"):
                    self.base[path[len("current-base/"):]] = item
                    continue
                if path.startswith("historical/"):
                    path = path[len("historical/"):]
                if path in self.old and self.old[path] != item:
                    raise ValueError("mixed historical Core source corpus")
                self.old[path] = item
        for family, name in TESTS.items():
            old = self.old[name]
            if old.count(MARKER) != 1:
                raise ValueError("retained Core source entry marker differs")
            expected = old.replace(MARKER, insertion(family) + MARKER, 1)
            if self.saved[name] != expected:
                raise ValueError("retained Core method source differs: " + name)
        self.temporary = None
        self.historical_root = None
        self.integer_current_root = None
        self.unchanged()
        if materialize:
            self.materialize()

    def unchanged(self):
        if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
            raise ValueError("executing Core preparation source changed")
        for name, raw in self.saved.items():
            path = self.root / name
            if self.take(path) != raw or path.read_bytes() != raw:
                raise ValueError("Core preparation physical input changed: " + name)
        if source_inputs(self.root) != tuple(sorted(self.saved)):
            raise ValueError("Core preparation physical input population changed")

    def materialize(self):
        if self.temporary is not None:
            raise ValueError("Core preparation view already materialized")
        self.unchanged()
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-core-three-frozen-source-")
        atexit.register(self.temporary.cleanup)
        base = Path(self.temporary.name)
        historical = base / "historical-data"
        current = base / "current-integer-fixtures"
        self._views = {}
        for name, raw in self.old.items():
            path = historical / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o400)
            self._views[path] = raw
            if name.startswith("tests/fixtures/hia_core_integer/"):
                target = current / name[len("tests/fixtures/hia_core_integer/"):]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o400)
                self._views[target] = raw
        integration = current / "integration/hepta/hia_core_lowering_native.py"
        integration.chmod(0o600)
        integration.write_bytes(self.saved["hepta/hia_core_lowering_native.py"])
        integration.chmod(0o400)
        self.historical_root = historical
        self.integer_current_root = current
        self._views[integration] = self.saved["hepta/hia_core_lowering_native.py"]
        self.verify_views()
        self.unchanged()

    def verify_views(self):
        for path, raw in getattr(self, "_views", {}).items():
            if path.read_bytes() != raw:
                raise ValueError("explicit Core source view changed")
        if self.historical_root is not None:
            actual = {p for base in (self.historical_root, self.integer_current_root)
                      for p in base.rglob("*") if p.is_file()}
            if actual != set(self._views):
                raise ValueError("explicit Core source view population changed")

    def historical_abi_reader(self):
        raw = self.old["hepta/hia_core_lowering_abi.json"]
        expected = _json(raw)

        def checked_abi(actual):
            if type(actual) is not bytes or actual != raw:
                raise ValueError("historical Core ABI bytes differ")
            return _json(raw)

        def source_names(abi):
            if json.dumps(abi, sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise ValueError("historical Core ABI value differs")
            return tuple("examples/hia_bootstrap/" + name + ".hiaasm"
                         for name in ("core_lowering_pool", *expected["units"]))

        return SimpleNamespace(
            ABI_SOURCE="hepta/hia_core_lowering_abi.json",
            checked_abi=checked_abi, source_names=source_names,
        )

    def proof(self):
        return {
            "schema": "hepta.hia.core-three-current-preparation.v1",
            "historical_commit": OLD_COMMIT,
            "current_root": str(self.root),
            "physical_current_inputs": {
                name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
                for name, raw in self.saved.items()
            },
            "historical_source_methods": dict(HISTORICAL_METHODS),
            "current_integer_integration_sha256":
                sha256(self.saved["hepta/hia_core_lowering_native.py"]).hexdigest(),
            "native_executed": False,
            "whole_Core_qualification_granted": False,
        }


@contextmanager
def _globals(namespace, replacements):
    previous = {name: namespace[name] for name in replacements}
    namespace.update(replacements)
    try:
        yield
    finally:
        namespace.update(previous)


def _bind_method(method, state, namespace, family):
    historical = method.__name__ == HISTORICAL_METHODS[family]

    @wraps(method)
    def checked(self, *args, **kwargs):
        state.unchanged()
        state.verify_views()
        try:
            if historical:
                values = {"ROOT": state.historical_root}
                if family == "compare":
                    values["BASE"] = state.historical_root
                elif family == "integer":
                    values["ROOT"] /= "tests/fixtures/hia_core_integer"
                elif family == "unpack":
                    values["core"] = state.historical_abi_reader()
                with _globals(namespace, values):
                    return method(self, *args, **kwargs)
            return method(self, *args, **kwargs)
        finally:
            state.verify_views()
            state.unchanged()

    checked.__qualification_domain__ = (
        "historical-source-contract" if historical else "current-physical-source"
    )
    return checked


def install(namespace, family):
    if type(namespace) is not dict or type(family) is not str or family not in TESTS:
        raise ValueError("invalid retained Core test preparation")
    if "_HIA_CURRENT_CORE_PREPARATION" in namespace:
        raise ValueError("retained Core test preparation installed twice")
    path = Path(namespace["__file__"]).resolve(strict=True)
    root = path.parents[1]
    if path != root / TESTS[family]:
        raise ValueError("retained Core test source path differs")
    state = _STATES.get(root)
    if state is None:
        state = CapturedInputs(root, materialize=True)
        _STATES[root] = state
    state.unchanged()
    if family == "integer":
        if namespace.get("ROOT") != root / "tests/fixtures/hia_core_integer":
            raise ValueError("explicit integer fixture override requires its own qualification")
        namespace["ROOT"] = state.integer_current_root
    elif family == "compare" and namespace.get("BASE") != root:
        raise ValueError("explicit comparison base override requires its own qualification")
    for name in CLASSES[family]:
        cls = namespace[name]
        for method_name, method in tuple(vars(cls).items()):
            if method_name.startswith("test_") and callable(method):
                setattr(cls, method_name, _bind_method(method, state, namespace, family))
        setup = cls.setUpClass
        teardown = cls.tearDownClass

        def wrapped_setup(inner, original=setup):
            state.unchanged()
            state.verify_views()
            original()
            state.verify_views()
            state.unchanged()

        def wrapped_teardown(inner, original=teardown):
            try:
                original()
            finally:
                state.verify_views()
                state.unchanged()

        cls.setUpClass = classmethod(wrapped_setup)
        cls.tearDownClass = classmethod(wrapped_teardown)
    namespace["_HIA_CURRENT_CORE_PREPARATION"] = state
