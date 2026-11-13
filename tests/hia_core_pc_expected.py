"""Select an explicitly frozen Core39 revision for retained source controls.

The original UNPACK and comparison snapshot files stay byte-identical.  Their
provenance describes historical bytes.  This loader returns separately labelled
current expectations from exact legacy, PC-forwarding or fixed-word-read identities.
The fixed Core39 revision also admits the exact two-loop UNPACK zero-store successor;
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
FIXED_READS_MANIFEST = "tests/fixtures/hia_core_fixed_word_reads_v94.json"
FIXED_READS_MANIFEST_SHA256 = "cb8def3b93a6ed6c285fe40dcc3f2cc5ed79af1b6f8bc182e74b5880a86ce6c9"
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


def _zero_store_unpack(fixed_raw, actual):
    """Admit only the exact two-loop UNPACK successor; Core39 pins stay v94."""
    before = (
        "    at = 0\n"
        "    while at < 256:\n"
        "        put(o, at, 0)\n"
        "        at = at + 8\n"
    )
    after = (
        "    at = 0\n"
        "    while at < 256:\n"
        "        store(o, at + 0, 0)\n"
        "        store(o, at + 1, 0)\n"
        "        store(o, at + 2, 0)\n"
        "        store(o, at + 3, 0)\n"
        "        store(o, at + 4, 0)\n"
        "        store(o, at + 5, 0)\n"
        "        store(o, at + 6, 0)\n"
        "        store(o, at + 7, 0)\n"
        "        at = at + 8\n"
    )
    text = fixed_raw.decode("utf-8")
    if text.count(before) != 2 or text.count(after) != 0:
        raise ValueError("ambiguous UNPACK zero-store predecessor")
    successor = text.replace(before, after)
    _require_pin(successor.encode("utf-8"), {
        "size": 13351,
        "sha256": "98ee56e38e2faf13a040f1749fb4152cc3080f0c930dc6378725e93b22c5bce1",
        "git_blob_sha1": "4c5c0b84b0b9ff28d6923d9b88ac11259d0cc57e",
    })
    if (successor.count(after) != 2
            or successor.replace(after, before).encode("utf-8") != fixed_raw
            or actual != successor.encode("utf-8")):
        raise ValueError("mixed fixed-word-read generator revisions")


def _fixed_word_reads(root, pc_raw, actual, by_path, numbered):
    raw = (root / FIXED_READS_MANIFEST).read_bytes()
    if sha256(raw).hexdigest() != FIXED_READS_MANIFEST_SHA256:
        raise ValueError("fixed-word-read expectation manifest differs")
    manifest = _json(raw)
    if manifest["schema"] != "hepta.hia.core39.explicit-fixed-word-reads-v94.v1":
        raise ValueError("unknown fixed-word-read expectation schema")
    if manifest["pc_forwarding_manifest"] != {"path": MANIFEST, "sha256": MANIFEST_SHA256}:
        raise ValueError("fixed-word-read predecessor differs")
    generator = manifest["generator"]
    _require_pin(pc_raw, generator["pc_forwarding"])
    text = pc_raw.decode("utf-8")
    replacements = generator["exact_forward_replacements"]
    if type(replacements) is not list or len(replacements) != 1:
        raise ValueError("fixed-word-read Core derivation must have one substitution")
    for replacement in replacements:
        before, after = replacement["before"], replacement["after"]
        if not before or not after or text.count(before) != 1:
            raise ValueError("ambiguous fixed-word-read Core derivation")
        text = text.replace(before, after, 1)
    fixed_raw = text.encode("utf-8")
    _require_pin(fixed_raw, generator["fixed_word_reads"])
    for replacement in reversed(replacements):
        before, after = replacement["before"], replacement["after"]
        if text.count(after) != 1:
            raise ValueError("ambiguous inverse fixed-word-read Core derivation")
        text = text.replace(after, before, 1)
    if text.encode("utf-8") != pc_raw or actual != fixed_raw:
        raise ValueError("unknown Core39 generator revision")

    unpack = manifest["unpack_generator"]
    baseline_raw = unpack["pc_forwarding"]["source_utf8"].encode("utf-8")
    _require_pin(baseline_raw, unpack["pc_forwarding"])
    text = baseline_raw.decode("utf-8")
    replacements = unpack["exact_forward_replacements"]
    if type(replacements) is not list or len(replacements) != 3:
        raise ValueError("fixed-word-read UNPACK derivation must have three substitutions")
    for replacement in replacements:
        before, after = replacement["before"], replacement["after"]
        if not before or not after or text.count(before) != 1:
            raise ValueError("ambiguous fixed-word-read UNPACK derivation")
        text = text.replace(before, after, 1)
    unpack_raw = text.encode("utf-8")
    _require_pin(unpack_raw, unpack["fixed_word_reads"])
    for replacement in reversed(replacements):
        before, after = replacement["before"], replacement["after"]
        if text.count(after) != 1:
            raise ValueError("ambiguous inverse fixed-word-read UNPACK derivation")
        text = text.replace(after, before, 1)
    if text.encode("utf-8") != baseline_raw:
        raise ValueError("mixed fixed-word-read generator revisions")
    current_unpack = (root / unpack["path"]).read_bytes()
    if current_unpack != unpack_raw:
        _zero_store_unpack(unpack_raw, current_unpack)

    rows = manifest["files"]
    if type(rows) is not list or len(rows) != 40:
        raise ValueError("fixed-word-read expectation population differs")
    fixed = {}
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "pc_forwarding", "fixed_word_reads"}:
            raise ValueError("malformed fixed-word-read expectation")
        path = row["path"]
        if type(path) is not str or path in fixed or path not in EXPECTED_PATHS:
            raise ValueError("duplicate or unknown fixed-word-read expectation")
        for revision in ("pc_forwarding", "fixed_word_reads"):
            pin = row[revision]
            if (type(pin) is not dict or set(pin) != {"size", "sha256", "git_blob_sha1"}
                    or type(pin["size"]) is not int or pin["size"] < 0):
                raise ValueError("malformed fixed-word-read identity")
        if row["pc_forwarding"] != by_path[path]["pc_forwarding"]:
            raise ValueError("fixed-word-read predecessor file differs")
        fixed[path] = row
    if set(fixed) != EXPECTED_PATHS:
        raise ValueError("fixed-word-read expected paths differ")
    changed = {path for path, row in fixed.items()
               if row["pc_forwarding"] != row["fixed_word_reads"]}
    if changed != numbered:
        raise ValueError("only the 38 numbered fixed-word-read Core units may differ")
    for path, row in fixed.items():
        by_path[path]["fixed_word_reads"] = row["fixed_word_reads"]
    return "fixed_word_reads"


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
        revision = _fixed_word_reads(root, pc_raw, actual, by_path, numbered)

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
