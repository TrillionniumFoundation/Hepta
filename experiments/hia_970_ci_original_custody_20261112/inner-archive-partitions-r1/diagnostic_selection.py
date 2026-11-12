"""Pure fixed-name and range selection for the original 970 inner ZIP.

STATIC DRAFT ONLY.  This module performs no downloads, archive extraction,
filesystem reads, framing, or product execution.  Its input metadata must come
from the existing reviewed outer-ZIP / exact-FINAL / captured-row validator.
The caller must still independently seal the complete original ZIP and every exact slice
after the current bound guardian has naturally exited and observed ECHILD.

This is deliberately not the former 371-target receiver.  The old HOLD and
cancelled operations remain separate historical facts.  A complete selection
ledger never changes their result.
"""
from __future__ import annotations

import re

SCHEMA = "hia.970-inner-archive-slice-selection.v1"
RAW_LIMIT = 512 * 1024
STDOUT_LIMIT = 1024 * 1024
CURRENT_READER_ALLOWANCE = 64 * 1024
HISTORICAL_ALLOWANCE = 448 * 1024
FRAME_BYTES = 24 * 1024
INDEX_MAX_BYTES = 64 * 1024

HISTORICAL_TARGETS = (
    "custody/inner-selected.zip.slice",
)

CURRENT_READER_TARGETS = (
    "reader/guard/guardian.json",
    "reader/guard/child.stdout.log",
    "reader/guard/child.stderr.log",
    "reader/recovery-terminal.json",
    "reader/setup.json",
)

# These files remain in the complete 17-member outer integrity inventory.
# Their bodies are outside this new diagnostic framing scope.
BODY_EXCLUSIONS = (
    "selected/13911977275/DIRECTORY.json",
    "selected/13911977275/OBSERVATIONS.json",
    "api/artifact-13911977275.metadata.original.json",
)


def _require(value, reason):
    if not value:
        raise ValueError("E_970_INNER_ARCHIVE_SLICE_SELECTION: " + reason)


def _metadata(value):
    """Copy only admitted byte metadata; no report-supplied path is returned."""
    _require(type(value) is dict and set(value) == {"bytes", "sha256"},
             "record must contain only complete-file bytes and sha256")
    size = value["bytes"]
    digest = value["sha256"]
    _require(type(size) is int and 0 <= size <= 32 * 1024 * 1024,
             "outer member extent is invalid")
    _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
             "complete-file sha256 is invalid")
    return {"bytes": size, "sha256": digest}


def _bucket(names, records, allowance):
    rows = []
    used = 0
    for name in names:
        if name not in records:
            rows.append({"name": name, "status": "MISSING",
                         "bytes": None, "sha256": None, "raw_bytes_selected": 0})
            continue
        original = _metadata(records[name])
        if original["bytes"] > allowance - used:
            rows.append({"name": name, "status": "OMITTED_RAW_BUDGET",
                         **original, "raw_bytes_selected": 0})
            continue
        used += original["bytes"]
        rows.append({"name": name, "status": "SELECTED_COMPLETE_ORIGINAL",
                     **original, "raw_bytes_selected": original["bytes"]})
    return rows, used


def plan_original_frames(historical_records, reader_records):
    """Plan one complete declared ZIP interval plus five complete control files.

    Missing means absent from the already-admitted captured inventory, never an
    unperformed filesystem probe.  Refused reads belong to the caller's actual
    readback ledger and must not be represented as successful selection here.
    Budget omissions do not spend a prefix of a file and cannot remove a target
    from the ledger.  The 64 KiB reader reservation is not donated to history.
    """
    _require(type(historical_records) is dict and type(reader_records) is dict,
             "record maps must be exact dictionaries")
    _require(set(historical_records) <= set(HISTORICAL_TARGETS)
             and set(reader_records) <= set(CURRENT_READER_TARGETS),
             "unplanned logical name")
    _require(len(HISTORICAL_TARGETS) == 1
             and len(CURRENT_READER_TARGETS) == 5
             and len(set(HISTORICAL_TARGETS + CURRENT_READER_TARGETS)) == 6,
             "fixed target denominator differs")
    _require(HISTORICAL_ALLOWANCE + CURRENT_READER_ALLOWANCE == RAW_LIMIT,
             "fixed budget partition differs")
    # Validate even an oversized record before omitting it.
    for original in (*historical_records.values(), *reader_records.values()):
        _metadata(original)
    current, current_bytes = _bucket(
        CURRENT_READER_TARGETS, reader_records, CURRENT_READER_ALLOWANCE)
    historical, historical_bytes = _bucket(
        HISTORICAL_TARGETS, historical_records, HISTORICAL_ALLOWANCE)
    rows = historical + current
    selected = [row["name"] for row in rows
                if row["status"] == "SELECTED_COMPLETE_ORIGINAL"]
    unavailable = [row["name"] for row in rows
                   if row["status"] != "SELECTED_COMPLETE_ORIGINAL"]
    _require(len(rows) == 6
             and len(selected) + len(unavailable) == 6
             and historical_bytes + current_bytes <= RAW_LIMIT,
             "selection accounting differs")
    return {
        "schema": SCHEMA,
        "status": "PLAN_ONLY_REQUIRES_ACTUAL_CLOSED_READBACK_AND_FINAL_FRAMES",
        "historical_targets": list(HISTORICAL_TARGETS),
        "reader_targets": list(CURRENT_READER_TARGETS),
        "rows": rows,
        "selected_names": selected,
        "unavailable_names": unavailable,
        "historical_raw_bytes_selected": historical_bytes,
        "reader_raw_bytes_selected": current_bytes,
        "total_original_raw_bytes_selected": historical_bytes + current_bytes,
        "raw_limit": RAW_LIMIT,
        "stdout_limit": STDOUT_LIMIT,
        "frame_bytes": FRAME_BYTES,
        "derived_index_maximum_bytes": INDEX_MAX_BYTES,
        "requested_ranges_truncated": False,
        "original_archive_partitioned": True,
        "whole_original_archive_in_one_partition": False,
        "all_target_metadata_accounted": True,
        "actual_original_bytes_read_by_this_module": 0,
        "actual_frame_END_emitted": False,
        "original_CUSTODY_HOLD_reclassified": False,
        "original_FRAMING_HOLD_reclassified": False,
        "cancelled_recovery_reclassified": False,
        "product_or_qualification_executed": False,
    }


INNER_ARCHIVE_BYTES = 8316154
INNER_ARCHIVE_SHA256 = "d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e"
PARTITION_COUNT = 19


def partition_for(policy, requested):
    """Validate all frozen ranges before selecting one exact binary interval."""
    _require(type(requested) is str and re.fullmatch(r"(?:0[0-9]|1[0-8])", requested) is not None,
             "fixed partition identifier required")
    expected = [
        {"id": "%02d" % number, "ordinal": number,
         "offset": number * HISTORICAL_ALLOWANCE,
         "bytes": min(HISTORICAL_ALLOWANCE,
                      INNER_ARCHIVE_BYTES - number * HISTORICAL_ALLOWANCE),
         "logical_path": HISTORICAL_TARGETS[0]}
        for number in range(PARTITION_COUNT)
    ]
    actual = policy.get("archive_partitions")
    _require(type(actual) is list and len(actual) == PARTITION_COUNT
             and all(type(row) is dict and set(row) == set(expected[0])
                     and type(row["id"]) is str and type(row["ordinal"]) is int
                     and type(row["offset"]) is int and type(row["bytes"]) is int
                     and type(row["logical_path"]) is str for row in actual)
             and actual == expected, "fixed nineteen-partition plan differs")
    pin = policy.get("inner_archive")
    _require(type(pin) is dict
             and pin.get("source_relative_path") ==
                 "selected/13911977275/selected-originals.zip"
             and pin.get("retained_file") == "014.original"
             and type(pin.get("bytes")) is int and pin["bytes"] == INNER_ARCHIVE_BYTES
             and pin.get("sha256") == INNER_ARCHIVE_SHA256,
             "external complete inner ZIP pin differs")
    _require(expected[0]["offset"] == 0
             and all(a["offset"] + a["bytes"] == b["offset"]
                     for a, b in zip(expected, expected[1:]))
             and expected[-1]["offset"] + expected[-1]["bytes"] == INNER_ARCHIVE_BYTES
             and expected[-1]["bytes"] == 58618
             and sum(row["bytes"] for row in expected) == INNER_ARCHIVE_BYTES,
             "complete original ZIP range denominator differs")
    return expected[int(requested)]
