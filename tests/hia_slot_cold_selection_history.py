"""Complete fixed source history for the original Slot15 cold-selector setup.

This host-only adapter restores complete predecessor files. It grants no native
execution, original caller PASS, cold qualification, or delivery qualification.
"""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/fixtures/hia_slot_cold_selection_history_v1.json"
FIXTURE_SHA256 = "364bd147ac2747fec02d653fbca439e6079bb2477a05da692735bdbdfeb23dc2"
PREDECESSOR = "f765709ba3dc5e95878ec25ffd5e8d9c4b3675d1"
EXPECTED = {
  "tests/hia_slot_operations_component_fixture.py": {
    "hunks": 10,
    "new": {
      "bytes": 8760,
      "sha256": "44be6a9bf2798b8798e834737e34dacf869ebced7f32b6ed1b5f573e1ba3f24a"
    },
    "old": {
      "bytes": 8881,
      "sha256": "0c5bdebff660a40fbb3e965fe370a7455fb809ef6de85b9264e65640354c417c"
    }
  },
  "tests/test_hia_slot_ledger_native.py": {
    "hunks": 18,
    "new": {
      "bytes": 32270,
      "sha256": "1bdfc91035d8a31c72da7c4fb068a204602f06bb058d0e9b5c557b79cdd7319c"
    },
    "old": {
      "bytes": 32364,
      "sha256": "cfd2224fa96ef8c6a08a5aeb44f9d7576bf7fbaa611813ee0233edac7d5dcef8"
    }
  },
  "tools/qualify_hia_slot_operations_callers.py": {
    "hunks": 44,
    "new": {
      "bytes": 13275,
      "sha256": "86efd8e30f129ffe274b80cd7192de6582d596110e532e94e4c09a5457b23e64"
    },
    "old": {
      "bytes": 12742,
      "sha256": "d7195cbff9dcca5bcb937ffb11e58be23e9bfa23f6d961054ba1754666e70b26"
    }
  }
}


def _require(condition, message):
    if not condition:
        raise ValueError("Slot cold selection history: " + message)


def pin(raw):
    _require(type(raw) is bytes, "source must be exact bytes")
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate fixture member")
        result[key] = value
    return result


def _read(root, name, take):
    try:
        raw = take(root / name)
    except OSError as exc:
        raise ValueError("Slot cold selection history: missing captured input: " + name) from exc
    _require(type(raw) is bytes, "capture did not return exact bytes: " + name)
    return raw


def _inverse(name, raw, record):
    expected = EXPECTED[name]
    _require(type(record) is dict and set(record) == {"old", "new", "hunks"}
             and record["old"] == expected["old"] and record["new"] == expected["new"]
             and type(record["hunks"]) is list and len(record["hunks"]) == expected["hunks"],
             "fixed complete-file record differs: " + name)
    pieces, replay, entries = [], [], []
    old_at = new_at = 0
    for hunk in record["hunks"]:
        _require(type(hunk) is dict and set(hunk) ==
                 {"old_offset", "new_offset", "old_hex", "new_hex"},
                 "fixed splice shape differs")
        old_offset, new_offset = hunk["old_offset"], hunk["new_offset"]
        _require(type(old_offset) is int and type(new_offset) is int
                 and old_offset >= old_at and new_offset >= new_at
                 and old_offset - old_at == new_offset - new_at,
                 "fixed splice offsets differ")
        _require(type(hunk["old_hex"]) is str and type(hunk["new_hex"]) is str,
                 "fixed splice bytes are not strings")
        try:
            old, new = bytes.fromhex(hunk["old_hex"]), bytes.fromhex(hunk["new_hex"])
        except ValueError as exc:
            raise ValueError("Slot cold selection history: invalid splice encoding") from exc
        _require(old != new and old.hex() == hunk["old_hex"] and new.hex() == hunk["new_hex"]
                 and raw[new_offset:new_offset + len(new)] == new,
                 "fixed splice bytes differ")
        pieces.extend((raw[new_at:new_offset], old))
        entries.append((old_offset, new_offset, old, new))
        old_at, new_at = old_offset + len(old), new_offset + len(new)
    prior = b"".join((*pieces, raw[new_at:]))
    _require(pin(prior) == expected["old"], "complete predecessor differs: " + name)
    at = 0
    for old_offset, new_offset, old, new in entries:
        _require(prior[old_offset:old_offset + len(old)] == old,
                 "forward original splice differs")
        replay.extend((prior[at:old_offset], new))
        at = old_offset + len(old)
    _require(b"".join((*replay, prior[at:])) == raw, "complete successor replay differs")
    return prior


def reviewed(name, raw, *, root=None, take=Path.read_bytes):
    """Require a complete old or new trio, and restore only the fixed new trio."""
    _require(name in EXPECTED, "unknown source path")
    pin(raw)
    root = ROOT if root is None else Path(root)
    frozen = _read(root, FIXTURE, take)
    _require(sha256(frozen).hexdigest() == FIXTURE_SHA256, "immutable fixture changed")
    value = json.loads(frozen, object_pairs_hook=_pairs)
    _require(type(value) is dict and set(value) ==
             {"schema", "predecessor_commit", "source_kind", "whole_native_delivery_qualified", "files"}
             and value["schema"] == "hepta.hia.slot-native-cold-selection-history.v1"
             and value["predecessor_commit"] == PREDECESSOR
             and value["source_kind"] == "HOST_SLOT_COLD_SELECTION_ONLY"
             and value["whole_native_delivery_qualified"] is False
             and type(value["files"]) is dict and set(value["files"]) == set(EXPECTED),
             "fixed source scope differs")
    captured = {path: _read(root, path, take) for path in EXPECTED}
    _require(captured[name] == raw, "provided bytes differ from captured source")
    old = all(pin(captured[path]) == expected["old"] for path, expected in EXPECTED.items())
    new = all(pin(captured[path]) == expected["new"] for path, expected in EXPECTED.items())
    _require(old or new, "source trio is unknown, partially restored, or mixed")
    originals = ({path: _inverse(path, captured[path], value["files"][path]) for path in EXPECTED}
                 if new else dict(captured))
    _require(_read(root, FIXTURE, take) == frozen
             and all(_read(root, path, take) == data for path, data in captured.items()),
             "captured history or source changed during review")
    if old:
        return raw, None
    return originals[name], {
        "path": name, "old": dict(EXPECTED[name]["old"]), "new": dict(EXPECTED[name]["new"]),
        "fixture": {"path": FIXTURE, "bytes": len(frozen), "sha256": FIXTURE_SHA256},
        "complete_source_trio": {path: {"old": dict(expected["old"]), "new": dict(expected["new"])}
                                 for path, expected in EXPECTED.items()},
        "complete_predecessors_restored": True, "complete_successors_replayed": True,
        "original_test_methods_assertions_budgets_preserved": True,
        "source_kind": "HOST_SLOT_COLD_SELECTION_ONLY", "whole_native_delivery_qualified": False,
    }
