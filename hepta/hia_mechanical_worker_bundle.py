"""Administrator v5 custody for the explicit Slot CPython mechanical ABI.

This capsule composes exactly one closed v1 helper bundle and one named bridge.
It never upgrades an old capsule, invents a pin, selects an arbitrary factory,
or treats a build receipt as authority without the outer expected digest.
"""
from __future__ import annotations
from hashlib import sha256
from types import MappingProxyType
from . import hia_native_helpers as authority

SCHEMA = "hepta.hia.native-helpers.v5"
ABI = "hia-worker-mechanical-bridges-v1"
BRIDGE = "slot-mechanical"
SELECTOR = "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST"


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


class _SlotBridge:
    __slots__ = ("binding", "captured", "record")

    def __init__(self, binding, captured, record):
        self.binding, self.captured, self.record = binding, captured, record

    def current(self, captured):
        binding = self.binding
        binding.check_owner()
        if (authority._ACTIVE is not binding
                and authority._MECHANICAL_BUILD is not binding):
            raise ValueError("mechanical bridge belongs to its original v5 worker scope")
        binding.check_files()
        if captured != self.captured:
            raise ValueError("mechanical bridge differs from its administrator capture")
        return self


class NativeMechanicalWorkerBinding:
    """No linker load occurs before the outer digest and entire bridge capture."""

    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        if (authority._SCOPE_OWNER != self.owner or authority._ACTIVE is not None
                or authority._MECHANICAL_BUILD is not None):
            raise ValueError("mechanical capsule requires its exclusive worker scope")
        if (not authority._digest(expected_sha256)
                or sha256(snapshot.raw).hexdigest() != expected_sha256):
            raise ValueError("native helper bundle identity mismatch")
        value = authority._decode(snapshot.raw)
        if (type(value) is not dict or set(value) != {
                "schema", "target", "abi", "helpers_bundle",
                "helpers_bundle_sha256", "bridges"}
                or value["schema"] != SCHEMA or value["target"] != authority.TARGET
                or value["abi"] != ABI
                or not authority._digest(value["helpers_bundle_sha256"])
                or type(value["bridges"]) is not list or len(value["bridges"]) != 1):
            raise ValueError("unsupported mechanical worker capsule schema, target or ABI")
        entry = value["bridges"][0]
        if (type(entry) is not dict or set(entry) != {
                "name", "abi", "package_path", "profile", "build_receipt", "binary", "sources"}
                or entry["name"] != BRIDGE):
            raise ValueError("unknown or duplicate mechanical bridge record")
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        base = self.capture(authority._path(value["helpers_bundle"], snapshot.path.parent),
                            authority.MAX_BUNDLE_BYTES, value["helpers_bundle_sha256"])
        # This version intentionally composes v1 only. Existing v2/v3/v4
        # companions retain their closed formats and are never guessed/flattened.
        entries = self.capture_base(base)
        if SELECTOR not in entries:
            raise ValueError("mechanical capsule does not select its Slot HIA owner")
        from . import hia_slot_mechanical as mechanical
        if entry["package_path"] != str(mechanical._PACKAGE):
            raise ValueError("administrator mechanical package path differs")
        captured = mechanical._bundle()  # pure reads; never loads the extension
        if entry["abi"] != mechanical.ABI or entry["profile"] != captured["profile"]:
            raise ValueError("administrator mechanical ABI/profile differs")
        wanted = {
            "name": BRIDGE, "abi": mechanical.ABI, "package_path": str(mechanical._PACKAGE),
            "profile": captured["profile"],
            "build_receipt": {"path": str(mechanical._PACKAGE / "_slot_mechanical_build.json"),
                              **_pin(captured["manifest"])},
            "binary": {"name": captured["path"].name, "path": str(captured["path"]),
                       **_pin(captured["binary"])},
            "sources": {name: {"path": str(mechanical._source_path(name)), **_pin(raw)}
                        for name, raw in sorted(captured["sources"].items())},
        }
        # Canonical bytes distinguish bool/int and reject implicit equality
        # coercion in the closed numeric pin fields.
        if authority._canonical_bridge(entry) != authority._canonical_bridge(wanted):
            raise ValueError("administrator mechanical executable/source/receipt pin differs")
        for path, raw, limit in (
                (mechanical._PACKAGE / "_slot_mechanical_build.json", captured["manifest"],
                 authority.MAX_SOURCE_BYTES),
                (captured["path"], captured["binary"], authority.MAX_IMAGE_BYTES)):
            read = self.capture(path, limit, sha256(raw).hexdigest())
            if read.raw != raw:
                raise ValueError("mechanical authority changed during capture")
        for name, raw in captured["sources"].items():
            read = self.capture(mechanical._source_path(name), authority.MAX_SOURCE_BYTES,
                                sha256(raw).hexdigest())
            if read.raw != raw:
                raise ValueError("mechanical source changed during capture")
        self.bridge_owner = _SlotBridge(self, captured, wanted)
        self.bridges = MappingProxyType({BRIDGE: self.bridge_owner})
        self.check_files()
        # Only this exact live constructor gets the pre-ACTIVE bridge token.
        # Failure removes it; no cached .so can acquire authority from v1 later.
        authority._MECHANICAL_BUILD = self
        try:
            mechanical.extension()
            self.legacy = authority.NativeHelpersBinding(
                str(base.path), value["helpers_bundle_sha256"])
            self.images = dict(self.legacy.images)
            self.selections = dict(self.legacy.selections)
            self.check_files()
        finally:
            authority._MECHANICAL_BUILD = None

    def capture(self, path, limit, digest):
        snapshot = authority._read(path, limit)
        if not authority._digest(digest) or sha256(snapshot.raw).hexdigest() != digest:
            raise ValueError("mechanical capsule input identity mismatch")
        self.snapshots.append((snapshot, limit))
        return snapshot

    def capture_base(self, base):
        value = authority._decode(base.raw)
        if (type(value) is not dict or set(value) != {"schema", "target", "abi", "helpers"}
                or value["schema"] != authority.SCHEMA
                or value["target"] != authority.TARGET or value["abi"] != authority.ABI
                or type(value["helpers"]) is not list
                or not 1 <= len(value["helpers"]) <= len(authority.HELPERS)):
            raise ValueError("mechanical capsule requires one explicit closed v1 base")
        entries = {}
        for entry in value["helpers"]:
            if (type(entry) is not dict
                    or set(entry) != {"selector", "manifest_path", "manifest_sha256"}
                    or type(entry["selector"]) is not str
                    or entry["selector"] not in authority.HELPERS
                    or entry["selector"] in entries
                    or not authority._digest(entry["manifest_sha256"])):
                raise ValueError("invalid mechanical v1 helper selection")
            entries[entry["selector"]] = (
                authority._path(entry["manifest_path"], base.path.parent),
                entry["manifest_sha256"])
        patch = entries.get("HEPTA_HIA_CORE_PATCH_MANIFEST")
        admission = entries.get("HEPTA_HIA_CORE_ADMISSION_MANIFEST")
        if patch is not None and (admission is None
                or admission[0].resolve(strict=True) !=
                   patch[0].resolve(strict=True).parent / "admission-manifest.json"):
            raise ValueError("native Core patch requires its exact adjacent admission helper")
        # Capture the entire existing helper declaration before any new C or
        # HIA executable is mapped. Original NativeHelpersBinding repeats every
        # original closed check and performs its own exact factory construction.
        for selector, (path, digest) in entries.items():
            manifest = self.capture(path, authority.MAX_MANIFEST_BYTES, digest)
            record = authority._decode(manifest.raw)
            module = authority.importlib.import_module("." + authority.HELPERS[selector][0],
                                                       authority.__package__)
            if (type(record) is not dict or set(record) != {
                    "schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
                    or record["schema"] != module.SCHEMA
                    or any(not authority._digest(record[key]) for key in
                           ("source_sha256", "image_sha256", "compiler_sha256"))):
                raise ValueError("mechanical v1 helper contract differs")
            self.capture(module.SOURCE, authority.MAX_SOURCE_BYTES, record["source_sha256"])
            self.capture(authority._path(record["image_path"], path.parent),
                         authority.MAX_IMAGE_BYTES, record["image_sha256"])
        return entries

    def check_owner(self):
        if (self.owner != (authority.os.getpid(), authority.threading.get_ident())
                or authority._SCOPE_OWNER != self.owner):
            raise ValueError("mechanical capsule belongs to its original process and thread")

    def check_files(self):
        self.check_owner()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError("mechanical capsule changed; observe the original operation")
        legacy = getattr(self, "legacy", None)
        if legacy is not None:
            legacy.check_files()

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError("native helper selection changed; observe the original operation")
        self.check_files()

    def mechanical_bridge(self, name, abi):
        self.check_owner()
        if (authority._ACTIVE is not self
                and authority._MECHANICAL_BUILD is not self):
            raise ValueError("mechanical capsule is not the current worker authority")
        if name != BRIDGE or abi != self.bridge_owner.record["abi"]:
            raise ValueError("mechanical bridge is outside the pinned capsule")
        self.check_files()
        return self.bridge_owner
