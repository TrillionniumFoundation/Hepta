"""Select an explicitly frozen Core39 revision for retained source controls.

The original UNPACK and comparison snapshot files stay byte-identical.  Their
provenance describes historical bytes.  This loader returns separately labelled
current expectations from the exact legacy or PC-forwarding generator identity;
it never computes expected HIA hashes from the current HIA files.  The original
callers still read and compare all 40 actual files, so mixed revisions fail.
No generator, compiler, native entry or qualification is executed here.
"""
from __future__ import annotations

from hashlib import sha1, sha256
import json
from pathlib import Path

MANIFEST = "tests/fixtures/hia_core_pc_forwarding_v93.json"
MANIFEST_SHA256 = "a3d49510a846b05c5a0985d747f2e87aaceb14ed6932bf8f1ee3ce6372c71ea4"
EXPECTED_PATHS = {
    *(f"examples/hia_bootstrap/core_lowering_{number:03d}.hiaasm" for number in range(38)),
    "examples/hia_bootstrap/core_lowering_pool.hiaasm",
    "hepta/hia_core_lowering_abi.json",
}


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate Core39 fixture field")
        result[name] = value
    return result


def _json(raw):
    def reject_constant(value):
        raise ValueError("non-finite Core39 fixture value")
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=reject_constant)


def _pin(raw):
    return {
        "size": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
    }


def _require_pin(raw, expected):
    size = expected["size"] if "size" in expected else expected["bytes"]
    if type(size) is not int or size < 0:
        raise ValueError("invalid Core39 expected size")
    wanted = {name: expected[name] for name in ("sha256", "git_blob_sha1")}
    wanted["size"] = size
    if _pin(raw) != wanted:
        raise ValueError("Core39 fixture or generator identity differs")


def current_core39_fixture(root, kind):
    """Return labelled expectations while preserving each historical file shape.

    ROOT chooses the generator revision.  A caller's separate BASE override
    continues to choose the actual source bytes checked by its original loop.
    """
    if type(kind) is not str or kind not in ("unpack", "comparison"):
        raise ValueError("unknown historical Core39 fixture")
    root = Path(root)
    manifest_raw = (root / MANIFEST).read_bytes()
    if sha256(manifest_raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("PC-forwarding expectation manifest differs")
    manifest = _json(manifest_raw)
    if manifest["schema"] != "hepta.hia.core39.explicit-pc-forwarding-v93.v1":
        raise ValueError("unknown Core39 expectation schema")

    rows = manifest["files"]
    if type(rows) is not list or len(rows) != 40:
        raise ValueError("Core39 expectation population differs")
    by_path = {}
    for row in rows:
        if set(row) != {"path", "legacy", "pc_forwarding"} or row["path"] in by_path:
            raise ValueError("duplicate or malformed Core39 expectation")
        for revision in ("legacy", "pc_forwarding"):
            pin = row[revision]
            if set(pin) != {"size", "sha256", "git_blob_sha1"} or type(pin["size"]) is not int:
                raise ValueError("malformed Core39 expected identity")
        by_path[row["path"]] = row
    if set(by_path) != EXPECTED_PATHS:
        raise ValueError("Core39 expected paths differ")
    changed = {path for path, row in by_path.items()
               if row["legacy"] != row["pc_forwarding"]}
    numbered = {f"examples/hia_bootstrap/core_lowering_{number:03d}.hiaasm"
                for number in range(38)}
    if changed != numbered:
        raise ValueError("only the 38 numbered PC units may differ")

    snapshots = {}
    for label in ("unpack", "comparison"):
        original = manifest["historical_fixtures"][label]
        raw = (root / original["path"]).read_bytes()
        _require_pin(raw, original)
        value = _json(raw)
        files = value["files"]
        if label == "unpack":
            if type(files) is not dict or set(files) != EXPECTED_PATHS:
                raise ValueError("historical unpack population differs")
            for path, pin in files.items():
                expected = by_path[path]["legacy"]
                if pin != {name: expected[name] for name in ("size", "sha256")}:
                    raise ValueError("historical unpack identity differs")
        else:
            if type(files) is not list or len(files) != 40:
                raise ValueError("historical comparison population differs")
            names = [row["path"] for row in files]
            if len(set(names)) != 40 or set(names) != EXPECTED_PATHS:
                raise ValueError("historical comparison paths differ")
            for row in files:
                if row != {"path": row["path"], **by_path[row["path"]]["legacy"]}:
                    raise ValueError("historical comparison identity differs")
        snapshots[label] = value

    generator = manifest["generator"]
    legacy_raw = generator["legacy"]["source_utf8"].encode("utf-8")
    _require_pin(legacy_raw, generator["legacy"])
    text = legacy_raw.decode("utf-8")
    replacements = generator["exact_forward_replacements"]
    if type(replacements) is not list or len(replacements) != 4:
        raise ValueError("PC derivation must have four exact substitutions")
    for replacement in replacements:
        before, after = replacement["before"], replacement["after"]
        if not before or not after or text.count(before) != 1:
            raise ValueError("ambiguous PC generator derivation")
        text = text.replace(before, after, 1)
    pc_raw = text.encode("utf-8")
    _require_pin(pc_raw, generator["pc_forwarding"])
    for replacement in reversed(replacements):
        before, after = replacement["before"], replacement["after"]
        if text.count(after) != 1:
            raise ValueError("ambiguous inverse PC generator derivation")
        text = text.replace(after, before, 1)
    if text.encode("utf-8") != legacy_raw:
        raise ValueError("PC generator inverse differs")

    actual = (root / generator["path"]).read_bytes()
    if actual == legacy_raw:
        revision = "legacy"
    elif actual == pc_raw:
        revision = "pc_forwarding"
    else:
        raise ValueError("unknown Core39 generator revision")

    baseline = snapshots[kind]
    if kind == "unpack":
        files = {path: {name: by_path[path][revision][name] for name in ("size", "sha256")}
                 for path in baseline["files"]}
    else:
        files = [{"path": row["path"], **by_path[row["path"]][revision]}
                 for row in baseline["files"]]
    result = {
        "schema": "hepta.hia.core39.selected-version-expectation.v1",
        "selected_revision": revision,
        "scope": "Explicit current expectations; historical snapshots are retained separately.",
        "legacy_fixture": {
            **manifest["historical_fixtures"][kind],
            "metadata": {name: value for name, value in baseline.items() if name != "files"},
        },
        "files": files,
    }
    if "base_commit" in baseline:
        result["base_commit"] = baseline["base_commit"]
    return result
