"""Select actual cold-generation files without inventing a hosted report.

The native location index is only a path/byte binding. Every public selection
still passes the unchanged complete native or legacy cold admission gate.
"""
from hashlib import sha256
import os
from pathlib import Path
import re
import stat

from tools.hia_native_cold_admission import SCHEMA as NATIVE_SCHEMA, read_json


INDEX_SCHEMA = "hepta.hia.native-cold-generation-index.v1"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_COMPILER_BYTES = 1024 * 1024


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _path(value):
    _require(type(value) is str and 0 < len(value) <= 4095 and "\0" not in value,
             "cold location must be a bounded path")
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts,
             "cold generation location must be absolute without parent traversal")
    return path


def _regular(path, limit):
    path = _path(str(path))
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
                 "cold location is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        _require(len(raw) == before.st_size and (before.st_dev, before.st_ino,
                 before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 "cold location changed during readback")
        return raw
    except OSError as exc:
        raise ValueError("cold location is unreadable or redirected: " + str(path)) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def read_native_locations(cold_path, cold_raw, index_raw):
    """Read all three physical images; this function alone grants no qualification."""
    report, index = read_json(cold_raw), read_json(index_raw)
    _require(type(report) is dict and report.get("schema") == NATIVE_SCHEMA,
             "native generation locations require an original native report")
    _require(type(index) is dict and set(index) == {"schema", "source_head", "native_report",
             "generations", "location_index_only", "hosted_qualification_claimed"}
             and index["schema"] == INDEX_SCHEMA and index["location_index_only"] is True
             and index["hosted_qualification_claimed"] is False,
             "native generation index has a false authority claim or invalid shape")
    _require(type(index["source_head"]) is str
             and re.fullmatch(r"[0-9a-f]{40}", index["source_head"]) is not None,
             "native generation index has no exact original source commit")
    binding = index["native_report"]
    _require(type(binding) is dict and set(binding) == {"path", "bytes", "sha256"}
             and type(binding["bytes"]) is int and binding["bytes"] == len(cold_raw)
             and binding["sha256"] == sha256(cold_raw).hexdigest()
             and _path(binding["path"]) == _path(str(cold_path)),
             "native generation index does not bind the exact original report bytes/path")
    rows, hashes = index["generations"], report.get("generation_sha256")
    _require(type(rows) is list and len(rows) == 3 and type(hashes) is list and len(hashes) == 3,
             "native generation index must identify all three generations")
    images = []
    for number, row in enumerate(rows, 1):
        _require(type(row) is dict and set(row) == {"name", "produced_image", "produced_bytes",
                 "produced_sha256"} and row["name"] == "B" + str(number)
                 and type(row["produced_bytes"]) is int
                 and 0 < row["produced_bytes"] <= MAX_COMPILER_BYTES
                 and row["produced_sha256"] == hashes[number - 1],
                 "native generation index row differs from the original generation")
        path = _path(row["produced_image"])
        raw = _regular(path, MAX_COMPILER_BYTES)
        _require(raw.startswith(b"\x7fELF") and len(raw) == row["produced_bytes"]
                 and sha256(raw).hexdigest() == row["produced_sha256"],
                 "physical native compiler bytes differ from the generation index")
        images.append((path, raw))
    _require(len({path for path, _ in images}) == 3
             and all(raw == images[-1][1] for _, raw in images),
             "native generations must have distinct paths and identical actual compiler bytes")
    return images


def compiler_from_cold_report(cold_report, *, generation_index=None):
    """Return B3 only after complete admission and all physical inputs are reread."""
    cold_path = Path(cold_report).absolute()
    cold_raw = _regular(cold_path, MAX_REPORT_BYTES)
    report = read_json(cold_raw)
    _require(type(report) is dict, "cold report must be an object")
    if report.get("schema") == NATIVE_SCHEMA:
        index_path = (cold_path.with_suffix(".generations.json") if generation_index is None
                      else Path(generation_index).absolute())
        index_raw = _regular(index_path, MAX_REPORT_BYTES)
        images = read_native_locations(cold_path, cold_raw, index_raw)
        supporting_path, supporting_raw = index_path, index_raw
    else:
        _require(report.get("schema") == "hepta.hia.selfhost-cold-replay.v1"
                 and generation_index is None, "unrecognized cold source domain")
        nested_path = _path(report.get("nested_report"))
        nested_raw = _regular(nested_path, MAX_REPORT_BYTES)
        _require(sha256(nested_raw).hexdigest() == report.get("nested_report_sha256"),
                 "legacy nested cold report bytes differ from their original binding")
        nested = read_json(nested_raw)
        rows = nested.get("generations") if type(nested) is dict else None
        _require(type(rows) is list and len(rows) == 3,
                 "legacy cold report has no complete three-generation record")
        images = []
        for row in rows:
            _require(type(row) is dict, "invalid legacy cold generation")
            path = _path(row.get("produced_image"))
            raw = _regular(path, MAX_COMPILER_BYTES)
            _require(sha256(raw).hexdigest() == row.get("produced_sha256"),
                     "legacy physical generation bytes differ")
            images.append((path, raw))
        _require(len({path for path, _ in images}) == 3
                 and all(raw == images[-1][1] for _, raw in images),
                 "legacy cold generations are not distinct identical outputs")
        supporting_path, supporting_raw = nested_path, nested_raw
    from tools.build_hia_json_preflight import admit_cold_build
    admit_cold_build(images[-1][1], cold_raw)
    _require(_regular(cold_path, MAX_REPORT_BYTES) == cold_raw
             and _regular(supporting_path, MAX_REPORT_BYTES) == supporting_raw
             and all(_regular(path, MAX_COMPILER_BYTES) == raw for path, raw in images),
             "cold generation inputs changed after complete admission")
    return images[-1][0]
