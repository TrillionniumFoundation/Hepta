"""Pinned complete nominal admission through one syscall-only HIA executable.

The process owns constructor, type, function, helper and outer continuations,
canonicalization and primitive admission. This adapter handles immutable byte
custody, bounded process lifetime and the two public result envelopes only.
"""
from __future__ import annotations

import base64
import csv
import ctypes
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import struct
import sys
import tempfile
import time

SCHEMA = "hepta.hia.nominal-program-selection.v1"
PROFILE = "hepta.hia.nominal.complete-linux-x86_64.v1"
SELECTOR = "HEPTA_HIA_NOMINAL_PROGRAM_MANIFEST"
PIN_SELECTOR = "HEPTA_HIA_NOMINAL_PROGRAM_MANIFEST_SHA256"
MAX_EXECUTABLE_BYTES = 8 << 20
MAX_INPUT_BYTES = 8 << 20
MAX_RESULT_BYTES = 64 + 2 * MAX_INPUT_BYTES
MAX_MANIFEST_BYTES = 32768
SEMANTIC_SOURCES = {
    "owner": "composite_constructor_owner", "render": "composite_constructor_render",
    "types": "composite_types", "admit": "composite_function_admit",
    "records": "composite_function_records", "terms": "composite_function_terms",
    "advanced": "composite_function_advanced", "function-render": "composite_function_render",
    "helpers": "task_helpers", "outer-owner": "composite_outer_owner",
    "outer-render": "composite_outer_render",
}
SEMANTIC_SOURCES = {key: "examples/hia_bootstrap/" + name + ".hepta"
                    for key, name in SEMANTIC_SOURCES.items()}
LEGACY_SELECTORS = tuple("HEPTA_HIA_" + name + "_MANIFEST" for name in (
    "COMPOSITE_CONSTRUCTOR", "COMPOSITE_TYPES", "COMPOSITE_FUNCTIONS",
    "TASK_HELPERS", "COMPOSITE_OUTER"))
FRAME = struct.Struct("<8s7Q")
CONTRACT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
SOURCE_FILES = tuple("examples/hia_bootstrap/" + name + ".hepta" for name in (
    "nominal_json", "composite_constructor_owner", "composite_constructor_render",
    "composite_types", "composite_function_admit", "composite_function_records",
    "composite_function_terms", "composite_function_advanced", "composite_function_render",
    "task_helpers", "composite_outer_owner", "composite_outer_render",
    "core_admission", "json_canonical", "core_nominal_report_json",
    "core_edit/publication_frontend", "core_edit/publication_program",
    "core_edit/publication_policy", "core_edit/publication_render",
    "core_edit/publication_assembly", "elf_static_linker",
    "nominal_constructor_transport_adapters", "nominal_constructor_transport_tail",
    "nominal_constructor_publication_adapters",
)) + (CONTRACT,)


# Additional checked-in sources required by the complete installed program.
# The remaining SOURCE_FILES are already in the explicit Agent resource list.
PACKAGE_RESOURCES = (
    "examples/hia_bootstrap/core_nominal_report_json.hepta",
    "examples/hia_bootstrap/core_edit/publication_frontend.hepta",
    "examples/hia_bootstrap/core_edit/publication_program.hepta",
    "examples/hia_bootstrap/core_edit/publication_policy.hepta",
    "examples/hia_bootstrap/core_edit/publication_render.hepta",
    "examples/hia_bootstrap/core_edit/publication_assembly.hepta",
    "examples/hia_bootstrap/elf_static_linker.hepta",
    "examples/hia_bootstrap/nominal_constructor_transport_adapters.hepta",
    "examples/hia_bootstrap/nominal_constructor_transport_tail.hepta",
    "examples/hia_bootstrap/nominal_constructor_publication_adapters.hepta",
)


def _reject(message):
    from .hia_program_selfhost import _reject as reject
    reject("E_HIA_SELFHOST_NOMINAL", message)


def _inspect_executable(raw):
    """Admit a closed Linux ELF layout; exact pins select its trusted code."""
    if (not 176 < len(raw) <= MAX_EXECUTABLE_BYTES
            or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9)):
        _reject("complete nominal program is not a bounded ELF64 executable")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, version, entry, phoff, _shoff, flags, ehsize, phsize, count, *_ = header
    if (kind != 2 or machine != 62 or version != 1 or flags or ehsize != 64
            or phoff != 64 or phsize != 56 or not 1 <= count <= 4
            or phoff + phsize * count > len(raw)):
        _reject("complete nominal executable has an unsupported ELF header")
    executable_entry = False
    for index in range(count):
        typ, mode, offset, address, physical, size, memory, alignment = struct.unpack_from(
            "<IIQQQQQQ", raw, phoff + index * phsize)
        if typ == 0x6474e551:
            if (mode != 6 or offset or address or physical or size or memory or alignment != 16):
                _reject("complete nominal executable has an invalid stack segment")
        elif typ == 1:
            if (mode not in (4, 5, 6) or physical != address or size > memory
                    or offset + size > len(raw) or alignment != 4096
                    or offset % alignment != address % alignment):
                _reject("complete nominal executable has an invalid load segment")
            executable_entry |= mode == 5 and address <= entry < address + size
        else:
            _reject("complete nominal executable requires a runtime loader")
    if not executable_entry:
        _reject("complete nominal entry is outside executable bytes")


def manifest_value(executable, *, compiler_sha256, source_sha256, cold_report_sha256,
                   semantic_image_sha256=None):
    """Describe actual bytes; a null cold digest is an explicit development build."""
    raw = Path(executable).read_bytes()
    _inspect_executable(raw)
    value = {"schema": SCHEMA, "profile": PROFILE, "executable_path": Path(executable).name,
            "executable_sha256": sha256(raw).hexdigest(), "executable_bytes": len(raw),
            "compiler_sha256": compiler_sha256, "source_sha256": source_sha256,
            "cold_report_sha256": cold_report_sha256}
    if semantic_image_sha256 is not None:
        value["semantic_image_sha256"] = dict(semantic_image_sha256)
    return value


def _relative_member(value):
    if type(value) is not str or value in ("", ".", "..") or "\0" in value or "\\" in value:
        raise ValueError("invalid complete nominal member path")
    path = Path(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in ("", ".", "..") for part in path.parts)):
        raise ValueError("complete nominal member must stay inside its selected group")
    return path


class _Selection:
    def __init__(self, path, expected_sha256):
        from .hia_json_preflight_native import _source_resource_path
        from .hia_program_selfhost import _decode, _digest, _read

        if not _digest(expected_sha256):
            _reject("an exact complete nominal manifest SHA256 is required")
        manifest = _read(path, MAX_MANIFEST_BYTES)
        if sha256(manifest.raw).hexdigest() != expected_sha256:
            _reject("complete nominal manifest differs from the operator pin")
        value = _decode(manifest.raw)
        fields = {"schema", "profile", "executable_path", "executable_sha256",
                  "executable_bytes", "compiler_sha256", "source_sha256", "cold_report_sha256"}
        if (type(value) is not dict or set(value) not in (fields, fields | {"semantic_image_sha256"})
                or value["schema"] != SCHEMA or value["profile"] != PROFILE
                or type(value["executable_path"]) is not str
                or Path(value["executable_path"]).name != value["executable_path"]
                or value["executable_path"] in ("", ".", "..")
                or any(not _digest(value[key]) for key in ("executable_sha256", "compiler_sha256"))
                or type(value["executable_bytes"]) is not int
                or not 176 < value["executable_bytes"] <= MAX_EXECUTABLE_BYTES
                or type(value["source_sha256"]) is not dict
                or set(value["source_sha256"]) != set(SOURCE_FILES)
                or any(not _digest(digest) for digest in value["source_sha256"].values())
                or value["cold_report_sha256"] is not None and not _digest(value["cold_report_sha256"])):
            _reject("unsupported complete nominal selection contract")
        if "semantic_image_sha256" in value:
            images = value["semantic_image_sha256"]
            if (type(images) is not dict or set(images) != set(SEMANTIC_SOURCES)
                    or any(not _digest(digest) for digest in images.values())):
                _reject("invalid complete nominal semantic image inventory")
        self.snapshots = [(manifest, MAX_MANIFEST_BYTES, _read)]
        for name in SOURCE_FILES:
            source = _read(_source_resource_path(name), 4 << 20)
            if sha256(source.raw).hexdigest() != value["source_sha256"][name]:
                _reject("installed complete nominal source differs: " + name)
            self.snapshots.append((source, 4 << 20, _read))
        executable = _read(manifest.path.parent / value["executable_path"], MAX_EXECUTABLE_BYTES)
        if (len(executable.raw) != value["executable_bytes"]
                or sha256(executable.raw).hexdigest() != value["executable_sha256"]):
            _reject("complete nominal executable differs from its operator pin")
        _inspect_executable(executable.raw)
        self.snapshots.append((executable, MAX_EXECUTABLE_BYTES, _read))
        self.executable, self.value, self.sha256 = executable.raw, value, expected_sha256
        self.origin = "operator-pinned-complete-program"
        self.check()

    @classmethod
    def package(cls):
        from . import hia_native_helpers as helpers
        from .hia_default_native import _capture_package
        from .hia_json_preflight_native import _source_resource_path
        from .hia_program_selfhost import _digest, _read

        helpers._check_scope_owner()
        if helpers._ACTIVE is not None or helpers._SCOPE_OWNER is not None or helpers._selectors():
            _reject("an active request bundle must explicitly select its complete nominal program")
        captured = _capture_package()
        if captured is None:
            _reject("select a pinned complete nominal program or install its matching-source wheel")
        directory, pin, snapshots = captured
        if len(pin) < 9:
            _reject("installed package does not own a complete native CLI")
        records = [snapshot for snapshot, _ in snapshots if snapshot.path.name == "RECORD"]
        if len(records) != 1:
            _reject("installed complete nominal program lacks one wheel inventory")
        record = records[0]
        rows = []
        for row in csv.reader(io.StringIO(record.raw.decode("utf-8"))):
            if len(row) != 3:
                _reject("invalid installed complete nominal inventory")
            if Path(row[0]).name == "hia-nominal-constructor":
                rows.append(row)
        if len(rows) != 1:
            _reject("installed complete nominal executable inventory is ambiguous")
        member, expected, extent = rows[0]
        relative = Path(member)
        if (relative.is_absolute() or "\0" in member or "\\" in member
                or any(part not in ("..", "bin", "hia-nominal-constructor") for part in relative.parts)):
            _reject("invalid installed complete nominal script location")
        # pip --target moves scripts to target/bin but retains the installer
        # scheme's relative RECORD name. Bind either location to the same exact
        # recorded bytes; never search PATH or follow a filesystem symlink.
        candidates = [directory.parent / "bin" / "hia-nominal-constructor",
                      Path(os.path.abspath(record.path.parent.parent / relative))]
        executable = None
        for candidate in dict.fromkeys(candidates):
            try:
                found = _read(candidate, MAX_EXECUTABLE_BYTES)
            except FileNotFoundError:
                continue
            encoded = "sha256=" + base64.urlsafe_b64encode(sha256(found.raw).digest()).rstrip(b"=").decode("ascii")
            if expected != encoded or extent != str(len(found.raw)):
                _reject("installed complete nominal executable differs from wheel RECORD")
            executable = found
            break
        if executable is None:
            _reject("installed complete nominal executable is missing")
        _inspect_executable(executable.raw)
        selection = cls.__new__(cls)
        selection.snapshots = [(snapshot, limit, helpers._read) for snapshot, limit in snapshots]
        selection.snapshots.append((executable, MAX_EXECUTABLE_BYTES, _read))
        contract = _read(_source_resource_path(CONTRACT), 4 << 20)
        value = json.loads(contract.raw)
        identities = value["source_identity"]["files"]
        cold = _read(directory / "_data/native/default/full_cost/cold-report.json", 4 << 20)
        if sha256(cold.raw).hexdigest() != pin[5]:
            _reject("installed complete nominal cold report differs from its package pin")
        evidence = json.loads(cold.raw)
        generations = evidence.get("generation_sha256")
        if (evidence.get("status") != "COLD_SELFHOST_REPLAY_PASS"
                or evidence.get("profile") != value["profile"]
                or type(generations) is not list or len(generations) != 3
                or any(not _digest(digest) for digest in generations)
                or len(set(generations)) != 1):
            _reject("installed complete nominal compiler identity lacks a qualified fixed point")
        selection.snapshots.append((cold, 4 << 20, _read))
        source_hashes = {}
        for name in SOURCE_FILES:
            source = contract if name == CONTRACT else _read(_source_resource_path(name), 4 << 20)
            digest = sha256(source.raw).hexdigest()
            if name != CONTRACT and identities.get(name) != digest:
                _reject("installed complete nominal source differs: " + name)
            source_hashes[name] = digest
            selection.snapshots.append((source, 4 << 20, _read))
        selection.value = {"executable_sha256": sha256(executable.raw).hexdigest(),
                           "compiler_sha256": generations[-1], "cold_report_sha256": pin[5],
                           "source_sha256": source_hashes}
        selection.executable = executable.raw
        selection.sha256 = sha256(record.raw).hexdigest()
        selection.origin = "matching-source-wheel-record"
        selection.check()
        return selection

    @classmethod
    def legacy(cls):
        """Capture the five selected groups and their pinned complete program.

        Group selection remains authoritative: no package lookup, compilation,
        semantic Python callback or unselected image can fill a missing owner.
        """
        from . import hia_native_helpers as helpers
        from .hia_program import HIAProgramRejected
        from .hia_program_selfhost import _decode, _digest, _read, SelfhostBuildRejected

        helpers._check_scope_owner()
        selectors = helpers._selectors()
        if not any(key in selectors for key in LEGACY_SELECTORS):
            return None
        try:
            if not all(key in selectors for key in LEGACY_SELECTORS):
                raise ValueError("complete nominal selection requires all five owner groups")
            active, owner = helpers._ACTIVE, helpers._SCOPE_OWNER
            if active is not None:
                active.check()
            elif owner is not None:
                raise ValueError("nominal owners are outside the active native helper bundle")
            snapshots = []

            def capture(path, limit=65536):
                snapshot = _read(path, limit)
                snapshots.append((snapshot, limit, _read))
                return snapshot, _decode(snapshot.raw)

            groups = {key: capture(selectors[key], 16384 if index in (1, 3) else 65536)
                      for index, key in enumerate(LEGACY_SELECTORS)}
            outer_snapshot, outer = groups[LEGACY_SELECTORS[4]]
            member = outer.get("complete_program") if type(outer) is dict else None
            if (type(member) is not dict or set(member) != {"manifest_path", "manifest_sha256"}
                    or not _digest(member["manifest_sha256"])):
                raise ValueError("selected outer group has no pinned complete nominal program")
            selection = cls(outer_snapshot.path.parent / _relative_member(member["manifest_path"]),
                            member["manifest_sha256"])
            image_pins = selection.value.get("semantic_image_sha256")
            if type(image_pins) is not dict or set(image_pins) != set(SEMANTIC_SOURCES):
                raise ValueError("complete nominal program lacks its eleven selected image pins")
            source_pins = selection.value["source_sha256"]

            def image(manifest, record, label, schema):
                fields = {"schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
                if (type(record) is not dict or set(record) != fields or record["schema"] != schema
                        or record["source_sha256"] != source_pins[SEMANTIC_SOURCES[label]]
                        or record["compiler_sha256"] != selection.value["compiler_sha256"]
                        or record["image_sha256"] != image_pins[label]):
                    raise ValueError("selected nominal image identity differs: " + label)
                captured = _read(manifest.path.parent / _relative_member(record["image_path"]), 1 << 20)
                snapshots.append((captured, 1 << 20, _read))
                if sha256(captured.raw).hexdigest() != image_pins[label]:
                    raise ValueError("selected nominal executable bytes differ: " + label)

            for index, stem, labels, dependencies in (
                (0, "composite-constructor", {"owner": "owner", "render": "render"},
                 {"types_source_sha256": source_pins[SEMANTIC_SOURCES["types"]]}),
                (2, "composite-functions", {key: "function-render" if key == "render" else key
                    for key in ("admit", "records", "advanced", "terms", "render")},
                 {"types_source_sha256": source_pins[SEMANTIC_SOURCES["types"]],
                  "helpers_source_sha256": source_pins[SEMANTIC_SOURCES["helpers"]]}),
                (4, "composite-outer", {"owner": "outer-owner", "render": "outer-render"},
                 {"types_source_sha256": source_pins[SEMANTIC_SOURCES["types"]],
                  "helpers_source_sha256": source_pins[SEMANTIC_SOURCES["helpers"]],
                  "function_sources_sha256": {key: source_pins[SEMANTIC_SOURCES[
                      "function-render" if key == "render" else key]]
                      for key in ("admit", "records", "advanced", "terms", "render")},
                  "complete_program": member}),
            ):
                manifest, record = groups[LEGACY_SELECTORS[index]]
                if (type(record) is not dict or set(record) != {"schema", "kernels", *dependencies}
                        or record["schema"] != "hepta.hia." + stem + "-native.v1"
                        or type(record["kernels"]) is not dict or set(record["kernels"]) != set(labels)
                        or any(record[key] != expected for key, expected in dependencies.items())):
                    raise ValueError("selected nominal group contract differs: " + stem)
                kernel_stem = "composite-function" if index == 2 else stem
                for key, label in labels.items():
                    component, value = capture(manifest.path.parent / _relative_member(record["kernels"][key]), 16384)
                    image(component, value, label, "hepta.hia." + kernel_stem + "-" + key + "-native.v1")
            for index, label, stem in ((1, "types", "composite-types"), (3, "helpers", "task-helpers")):
                manifest, record = groups[LEGACY_SELECTORS[index]]
                image(manifest, record, label, "hepta.hia." + stem + "-native.v1")
            selection.snapshots.extend(snapshots)
            selection.legacy_scope = (active, owner, selectors)
            selection.origin = "five-selected-groups-pinned-complete-program"
            selection.check()
            return selection
        except (ValueError, OSError, UnicodeError, RuntimeError, SelfhostBuildRejected) as error:
            raise HIAProgramRejected("selected native nominal program refused: " + str(error),
                                     "E_HIA_TYPE") from error

    def check(self):
        scope = getattr(self, "legacy_scope", None)
        if scope is not None:
            from . import hia_native_helpers as helpers
            helpers._check_scope_owner()
            active, owner, selectors = scope
            if (helpers._ACTIVE is not active or helpers._SCOPE_OWNER != owner
                    or helpers._selectors() != selectors):
                _reject("selected nominal owner scope changed during admission")
            if active is not None:
                active.check()
        for snapshot, limit, reader in self.snapshots:
            if reader(snapshot.path, limit) != snapshot:
                _reject("complete nominal selection changed during admission")


def lower_nominal(raw, *, timeout_seconds=30):
    """Return native original/Core bytes and a mechanical capture; never fall back."""
    from .hia_program import HIAProgramRejected
    from .hia_program_selfhost import _run, _sealed_executable

    if (sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64")
            or sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8
            or not hasattr(os, "memfd_create")):
        _reject("complete nominal execution requires Linux x86-64 LP64")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 3600):
        _reject("complete nominal deadline must be finite and in (0,3600] seconds")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        _reject("complete nominal input must be immutable bytes within 8 MiB")
    path, expected = os.environ.get(SELECTOR), os.environ.get(PIN_SELECTOR)
    if bool(path) != bool(expected):
        _reject("complete nominal manifest and SHA256 must be supplied together")
    selection = _Selection(path, expected) if path else (_Selection.legacy() or _Selection.package())
    fd, seals = _sealed_executable(selection.executable)
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="hia-nominal-") as directory:
            result, capture = _run(fd, raw, timeout_seconds, directory,
                argv0="hia-admit-agent-json", stdout_limit=MAX_RESULT_BYTES, accepted_statuses=(0, 2, 3))
            if capture["returncode"] != 0:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    _reject("complete nominal diagnostic exceeded its deadline")
                diagnostic, diagnostic_capture = _run(fd, raw, remaining, directory,
                    argv0="hia-verify-core-json", stdout_limit=65536, accepted_statuses=(2,))
                selection.check()
                try:
                    from .hia_program_selfhost import _decode
                    value = _decode(diagnostic)
                    rows = value["diagnostics"]
                    if (set(value) != {"diagnostics", "ok", "status"} or value["ok"] is not False
                            or value["status"] != "error" or type(rows) is not list or len(rows) != 1
                            or set(rows[0]) != {"code", "phase", "message"}
                            or rows[0]["code"] != "E_DRIVER" or rows[0]["phase"] != "driver"):
                        raise ValueError("invalid diagnostic envelope")
                    message = rows[0]["message"]
                    code, separator, detail = message.partition(": ")
                    if (not separator or not code.startswith("E_HIA_") or len(message) > 4096):
                        raise ValueError("invalid semantic diagnostic")
                except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as error:
                    _reject("complete nominal program returned an unsupported refusal: " + str(error))
                rejection = HIAProgramRejected(detail, code)
                rejection.capture = {"admission": capture, "diagnostic": diagnostic_capture,
                                     "executable_sha256": selection.value["executable_sha256"]}
                raise rejection
        if len(result) < FRAME.size:
            _reject("complete nominal program omitted its result header")
        magic, action, error, profile, original_size, core_size, spare1, spare2 = FRAME.unpack_from(result)
        if (magic != b"HIAVCF01" or action or error or spare1 or spare2 or not 1 <= profile <= 4
                or not 0 < original_size <= MAX_INPUT_BYTES or not 0 < core_size <= MAX_INPUT_BYTES
                or len(result) != FRAME.size + original_size + core_size):
            _reject("complete nominal program returned an invalid result frame")
        end = FRAME.size + original_size
        receipt = {"selection_origin": selection.origin, "selection_sha256": selection.sha256,
                   "executable_sha256": selection.value["executable_sha256"],
                   "source_sha256": selection.value["source_sha256"],
                   "compiler_sha256": selection.value["compiler_sha256"],
                   "cold_report_sha256": selection.value["cold_report_sha256"],
                   "kernel_executable_seals": seals, "native_orchestration": True,
                   "host_semantic_fallback": False, "capture": capture}
        return result[FRAME.size:end], result[end:], profile, receipt
    finally:
        try:
            selection.check()
        finally:
            os.close(fd)
