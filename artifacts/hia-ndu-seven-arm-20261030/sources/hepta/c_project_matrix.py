"""Explicit build variants over one C/C++ compilation database.

Every listed command belongs to exactly one variant. Each variant must contain
the same complete source-unit set, but may use different macros/includes. The
variants are separate artifacts: their definitions are never merged together.
This inventories declared builds, not all possible preprocessor configurations.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex

from .c_migrate import MigrationRejected
from .c_project import (_flags, _load_compdb, _path, _reject_duplicate_keys,
                        _reject_nonfinite_constant, capture_project, digest,
                        selected_command_indices, verify_capture)
from .hia_program_tools import read_bounded


MATRIX_SCHEMA = "hepta.build-matrix.v1"
CAPTURE_SCHEMA = "hepta.build-matrix-capture.v1"
SCOPE = "all_listed_commands_exactly_one_variant_not_unlisted_builds"
_MAX_VARIANTS = 8
_NAME = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")


def _reject(message):
    raise MigrationRejected("E_C_BUILD_MATRIX", message)


def _load_matrix(path):
    path = Path(path).resolve()
    try:
        raw = read_bounded(path, limit=65536)
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys,
                              parse_constant=_reject_nonfinite_constant)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise MigrationRejected("E_C_BUILD_MATRIX", "Cannot read bounded unambiguous matrix JSON") from exc
    if (type(document) is not dict
            or set(document) != {"schema", "language", "database", "variants"}
            or document["schema"] != MATRIX_SCHEMA
            or type(document["language"]) is not str
            or document["language"] not in {"c", "c++"}
            or type(document["database"]) is not str
            or not document["database"] or "\x00" in document["database"]):
        _reject("Matrix requires schema, c/c++ language, database and explicit variants")
    database = _path(document["database"], path.parent)
    database_bytes, entries = _load_compdb(database)
    variants = document["variants"]
    if type(variants) is not list or not 1 <= len(variants) <= _MAX_VARIANTS:
        _reject("Matrix requires one to eight explicit variants")
    names, assigned, source_set, driver = set(), set(), None, None
    for variant in variants:
        if (type(variant) is not dict or set(variant) != {"name", "command_indices"}
                or type(variant["name"]) is not str or not _NAME.fullmatch(variant["name"])
                or variant["name"] in names):
            _reject("Variant names must be unique short lowercase identifiers")
        names.add(variant["name"])
        indices = selected_command_indices(entries, variant["command_indices"])
        if assigned.intersection(indices):
            _reject("Compilation command is assigned to multiple variants")
        assigned.update(indices)
        sources = set()
        for index in indices:
            entry = entries[index]
            directory = _path(entry["directory"], database.parent)
            source = _path(entry["file"], directory)
            if source in sources:
                _reject("A variant repeats a source unit with multiple configurations")
            sources.add(source)
            argv = entry.get("arguments")
            if argv is None:
                argv = shlex.split(entry["command"], posix=True)
            _flags(argv, source, directory, language=document["language"])
            current_driver = Path(argv[0]).name
            if driver is not None and driver != current_driver:
                _reject("Matrix commands must use one consistent source compiler driver")
            driver = current_driver
        if source_set is not None and source_set != sources:
            _reject("Every variant must contain the same complete source-unit set")
        source_set = sources
    if assigned != set(range(len(entries))):
        _reject("Every compilation database command must belong to exactly one variant")
    return {"path": path, "raw": raw, "document": document,
            "database": database, "database_bytes": database_bytes,
            "command_count": len(entries), "sources": sorted(map(str, source_set))}


def _identity(capture):
    return digest(json.dumps({key: value for key, value in capture.items() if key != "sha256"},
                             sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def capture_project_matrix(manifest, *, clang="clang", language=None):
    selected = _load_matrix(manifest)
    document = selected["document"]
    if language is not None and document["language"] != language:
        _reject("Matrix language differs from requested migration frontend")
    variants = []
    for variant in document["variants"]:
        captured = capture_project(selected["database"], clang=clang,
                                   language=document["language"],
                                   command_indices=variant["command_indices"])
        variants.append({"name": variant["name"],
                         "command_indices": list(variant["command_indices"]),
                         "capture": captured})
    result = {"schema": CAPTURE_SCHEMA,
              "manifest": {"path": str(selected["path"]), "sha256": digest(selected["raw"])},
              "database": {"path": str(selected["database"]),
                           "sha256": digest(selected["database_bytes"])},
              "language": document["language"], "scope": SCOPE,
              "command_count": selected["command_count"],
              "source_units_per_variant": selected["sources"], "variants": variants}
    result["sha256"] = _identity(result)
    verify_project_matrix(result)
    return result


def verify_project_matrix(capture):
    """Replay selection from source bytes; hashes alone cannot assert coverage."""
    fields = {"schema", "manifest", "database", "language", "scope", "command_count",
              "source_units_per_variant", "variants", "sha256"}
    if (type(capture) is not dict or set(capture) != fields
            or capture["schema"] != CAPTURE_SCHEMA or capture["scope"] != SCOPE
            or type(capture["manifest"]) is not dict
            or set(capture["manifest"]) != {"path", "sha256"}
            or type(capture["manifest"]["path"]) is not str
            or type(capture["command_count"]) is not int):
        _reject("Malformed matrix capture")
    try:
        if _identity(capture) != capture["sha256"]:
            _reject("Matrix capture digest differs")
    except (TypeError, ValueError, RecursionError) as exc:
        raise MigrationRejected("E_C_BUILD_MATRIX", "Invalid matrix capture identity") from exc
    actual = _load_matrix(capture["manifest"]["path"])
    document = actual["document"]
    if (capture["manifest"] != {"path": str(actual["path"]), "sha256": digest(actual["raw"])}
            or capture["database"] != {"path": str(actual["database"]),
                                       "sha256": digest(actual["database_bytes"])}
            or capture["language"] != document["language"]
            or capture["command_count"] != actual["command_count"]
            or capture["source_units_per_variant"] != actual["sources"]
            or type(capture["variants"]) is not list
            or len(capture["variants"]) != len(document["variants"])):
        _reject("Matrix scope or input identity differs from the source manifest/database")
    expected_schema = "hepta.c-build-selection.v1" if document["language"] == "c" else "hepta.cpp-build-selection.v1"
    compiler = None
    for variant, expected in zip(capture["variants"], document["variants"]):
        if (type(variant) is not dict or set(variant) != {"name", "command_indices", "capture"}
                or variant["name"] != expected["name"]
                or variant["command_indices"] != expected["command_indices"]):
            _reject("Variant partition differs from source manifest")
        selected = variant["capture"]
        verify_capture(selected)
        if (selected["schema"] != expected_schema
                or selected["database"] != capture["database"]
                or selected.get("command_indices") != expected["command_indices"]
                or sorted(row["source"] for row in selected["configurations"]) != actual["sources"]):
            _reject("Variant capture differs from declared command selection")
        if compiler is not None and selected["compiler"] != compiler:
            _reject("Variants were captured by inconsistent selected compiler identities")
        compiler = selected["compiler"]
    final = _load_matrix(capture["manifest"]["path"])
    if final["raw"] != actual["raw"] or final["database_bytes"] != actual["database_bytes"]:
        _reject("Matrix inputs changed during replay")
