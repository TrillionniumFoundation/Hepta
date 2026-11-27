"""Exact Slot integration source history; no execution qualification is granted."""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = "tests/test_hia_slot_ledger_native_integration.py"
FIXTURE = "tests/fixtures/hia_slot_integration_component_history_v1.json"
FIXTURE_SHA256 = "ce0a0e31a881beb64d08bf85941361bfe2e10191111fe7bfcbb65b670d8a4a26"
LEGACY_FIXTURE = "tests/fixtures/hia_installed_distribution_sources.json"
LEGACY_FIXTURE_SHA256 = "6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d"
EXTERNAL_COMMIT = "4681a60bba48409749160e49cd7d3a5a6018460d"
EXTERNAL_BLOB = "8e694c560d95147817640c6b733450b18b22f328"
VERSIONS = {'current': {'bytes': 87678, 'sha256': 'f270650c8b70ef1384d0941a85c15c68b788f8198ef88de7f3fa8c96805e853f'},
 'external': {'bytes': 85231, 'sha256': '50699c2dacdf503d5d820466ab590a9786dd2023d2d4fa06bedf1c9673d9ff42'},
 'installed': {'bytes': 85213, 'sha256': 'e6aacdb28c34890f897b09d088ede33cd1360a9e8cf09ba44e48fecd1187ffd1'},
 'original': {'bytes': 85106, 'sha256': '02081467ee8eff2589f1b284f6259a349526b4a87d643072f12c9b24a725de7d'}}
COMPONENT_PINS = {'tests/hia_component_install_fixture.py': {'bytes': 31277,
                                            'sha256': '593e3b0b547a9d1e0d24a0a8c7338fb260e66e414c60f5c294d9a1d4c77f459c'},
 'tests/test_hia_component_install_fixture.py': {'bytes': 15938,
                                                 'sha256': '9cb4de7fd7f42a04c2691488bf9c0ee6cf921113eb623170cd3021c0784c330a'}}
COLD_INPUT_SOURCE = "tools/hia_cold_compiler.py"


def _require(condition, message):
    if not condition:
        raise ValueError("Slot integration component history: " + message)


def pin(raw):
    _require(type(raw) is bytes, "source must be exact bytes")
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(_same(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate fixture member")
        result[key] = value
    return result


def _read(root, name, take):
    try:
        raw = take(root / name)
    except OSError as error:
        raise ValueError("Slot integration component history: missing captured input: " + name) from error
    _require(type(raw) is bytes, "capture did not return exact bytes: " + name)
    return raw


def _inverse(raw, record, old, new):
    _require(type(record) is dict and set(record) == {"old", "new", "hunks"}
             and _same(record["old"], old) and _same(record["new"], new)
             and type(record["hunks"]) is list and len(record["hunks"]) > 0
             and pin(raw) == new, "complete fixed relation differs")
    pieces, replay, entries = [], [], []
    old_at = new_at = 0
    for hunk in record["hunks"]:
        _require(type(hunk) is dict and set(hunk) ==
                 {"old_offset", "new_offset", "old_hex", "new_hex"},
                 "fixed splice shape differs")
        a, b = hunk["old_offset"], hunk["new_offset"]
        _require(type(a) is int and type(b) is int and a >= old_at and b >= new_at
                 and a - old_at == b - new_at, "fixed splice offsets differ")
        _require(type(hunk["old_hex"]) is str and type(hunk["new_hex"]) is str,
                 "fixed splice bytes are not strings")
        try:
            before, after = bytes.fromhex(hunk["old_hex"]), bytes.fromhex(hunk["new_hex"])
        except ValueError as error:
            raise ValueError("Slot integration component history: invalid splice encoding") from error
        _require(before != after and before.hex() == hunk["old_hex"] and after.hex() == hunk["new_hex"]
                 and raw[b:b + len(after)] == after, "fixed splice bytes differ")
        pieces.extend((raw[new_at:b], before))
        entries.append((a, before, after))
        old_at, new_at = a + len(before), b + len(after)
    prior = b"".join((*pieces, raw[new_at:]))
    _require(pin(prior) == old, "complete predecessor differs")
    at = 0
    for a, before, after in entries:
        _require(prior[a:a + len(before)] == before, "forward original splice differs")
        replay.extend((prior[at:a], after))
        at = a + len(before)
    _require(b"".join((*replay, prior[at:])) == raw, "complete successor replay differs")
    return prior


def reviewed(name, raw, *, root=None, take=Path.read_bytes):
    """Restore the fixed successor to e6aa, retaining the external and original chain.

    Other complete versions are returned unchanged for their original exact
    source authorities. This adapter does not admit unknown bytes by itself.
    """
    actual = pin(raw)
    if name != PATH or actual != VERSIONS["current"]:
        return raw, None
    root = ROOT if root is None else Path(root)
    captured = {}

    def capture(path):
        data = _read(root, path, take)
        _require(path not in captured or captured[path] == data, "input changed between captures")
        captured[path] = data
        return data

    frozen = capture(FIXTURE)
    _require(sha256(frozen).hexdigest() == FIXTURE_SHA256, "immutable fixture changed")
    value = json.loads(frozen, object_pairs_hook=_pairs)
    _require(type(value) is dict and set(value) ==
             {"schema", "source_kind", "whole_native_delivery_qualified", "versions", "relations",
              "external_source_commit", "external_source_blob", "original_wheel_budget_seconds",
              "superseded_wheel_budget_seconds", "component_pins", "legacy_fixture_sha256"}
             and value["schema"] == "hepta.hia.slot-integration-component-source-history.v1"
             and value["source_kind"] == "HOST_SLOT_INTEGRATION_COMPONENT_FIXTURE_ONLY"
             and value["whole_native_delivery_qualified"] is False
             and _same(value["versions"], VERSIONS)
             and _same(value["component_pins"], COMPONENT_PINS)
             and value["external_source_commit"] == EXTERNAL_COMMIT
             and value["external_source_blob"] == EXTERNAL_BLOB
             and type(value["original_wheel_budget_seconds"]) is int
             and value["original_wheel_budget_seconds"] == 90
             and type(value["superseded_wheel_budget_seconds"]) is int
             and value["superseded_wheel_budget_seconds"] == 1800
             and value["legacy_fixture_sha256"] == LEGACY_FIXTURE_SHA256
             and type(value["relations"]) is dict
             and set(value["relations"]) ==
                 {"current_to_external", "external_to_installed", "installed_to_original"},
             "fixed source scope differs")
    _require(capture(PATH) == raw, "provided source differs from physical source")
    for path, expected in COMPONENT_PINS.items():
        _require(pin(capture(path)) == expected, "component source differs: " + path)
    # The selector has its separate current-source qualification. Capture its
    # actual bytes here for stability without treating an older helper as current.
    capture(COLD_INPUT_SOURCE)
    legacy_raw = capture(LEGACY_FIXTURE)
    _require(sha256(legacy_raw).hexdigest() == LEGACY_FIXTURE_SHA256, "original installed relation changed")
    legacy = json.loads(legacy_raw, object_pairs_hook=_pairs)["files"][PATH]
    _require(_same(legacy["current"], VERSIONS["installed"])
             and _same(legacy["original"], VERSIONS["original"]),
             "original installed complete pins differ")
    external = _inverse(raw, value["relations"]["current_to_external"],
                        VERSIONS["external"], VERSIONS["current"])
    installed = _inverse(external, value["relations"]["external_to_installed"],
                         VERSIONS["installed"], VERSIONS["external"])
    original = _inverse(installed, value["relations"]["installed_to_original"],
                        VERSIONS["original"], VERSIONS["installed"])
    _require(all(_read(root, path, take) == data for path, data in captured.items()),
             "captured source or relation changed during review")
    return installed, {
        "path": PATH, "current": dict(VERSIONS["current"]),
        "external_cold_predecessor": dict(VERSIONS["external"]),
        "installed_predecessor": dict(VERSIONS["installed"]),
        "original_predecessor": dict(VERSIONS["original"]),
        "all_three_complete_relations_reversed_and_replayed": True,
        "original_wheel_budget_seconds": 90, "superseded_wheel_budget_seconds": 1800,
        "captured_inputs": {path: pin(data) for path, data in captured.items()},
        "source_kind": "HOST_SLOT_INTEGRATION_COMPONENT_FIXTURE_ONLY",
        "native_cold_qualified": False, "whole_native_delivery_qualified": False,
    }


def predecessor(name, raw, *, root=None, take=Path.read_bytes):
    return reviewed(name, raw, root=root, take=take)[0]
