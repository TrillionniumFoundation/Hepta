"""Administrator v6 custody for fixed, explicitly selected mechanical carriers.

This version composes one unchanged closed v1 HIA helper bundle with the exact
bridges required by its Artifact, Verification and optional Slot owners. It
never upgrades v1/v5, selects arbitrary factories, or trusts an unpinned receipt.
"""
from __future__ import annotations
from hashlib import sha256
from types import MappingProxyType
from . import hia_native_helpers as authority

SCHEMA = "hepta.hia.native-helpers.v6"
ABI = "hia-worker-native-carriers-v1"
# Exact selector, loader and receipt names; no capsule-supplied import target.
BRIDGES = MappingProxyType({
    "native-image": ("HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST", "hia_native_image", "_native_image_build.json"),
    "cell-frame": ("HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST", "hia_cell_frame", "_cell_frame_build.json"),
    "slot-mechanical": ("HEPTA_HIA_SLOT_OPERATIONS_MANIFEST", "hia_slot_mechanical", "_slot_mechanical_build.json"),
})


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


class _CarrierBridge:
    __slots__ = ("binding", "captured", "record")

    def __init__(self, binding, captured, record):
        self.binding, self.captured, self.record = binding, captured, record

    def current(self, captured):
        binding = self.binding
        binding.check_owner()
        if (authority._ACTIVE is not binding
                and authority._MECHANICAL_BUILD is not binding):
            raise ValueError("mechanical bridge belongs to its original v6 worker scope")
        binding.check_files()
        if captured != self.captured:
            raise ValueError("mechanical bridge differs from its administrator capture")
        return self


class NativeCarrierWorkerBinding:
    """The entire declared HIA/C input set is captured before the first C load."""

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
                "schema", "target", "abi", "helpers_bundle", "helpers_bundle_sha256", "bridges"}
                or value["schema"] != SCHEMA or value["target"] != authority.TARGET
                or value["abi"] != ABI
                or not authority._digest(value["helpers_bundle_sha256"])
                or type(value["bridges"]) is not list or not 1 <= len(value["bridges"]) <= 3):
            raise ValueError("unsupported mechanical worker capsule schema, target or ABI")
        records = {}
        for entry in value["bridges"]:
            if (type(entry) is not dict or set(entry) != {
                    "name", "abi", "package_path", "profile", "build_receipt", "binary", "sources"}
                    or type(entry["name"]) is not str or entry["name"] not in BRIDGES
                    or entry["name"] in records):
                raise ValueError("unknown or duplicate mechanical bridge record")
            records[entry["name"]] = entry
        if (list(records) != sorted(records)
                or not ({"native-image", "cell-frame"} & records.keys())):
            raise ValueError("v6 requires ordered explicit new carrier records")
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        base = self.capture(authority._path(value["helpers_bundle"], snapshot.path.parent),
                            authority.MAX_BUNDLE_BYTES, value["helpers_bundle_sha256"])
        entries = self.capture_base(base)
        required = sorted(name for name, (selector, _module, _receipt) in BRIDGES.items()
                          if selector in entries)
        if list(records) != required:
            raise ValueError("mechanical records do not exactly cover selected v6 HIA owners")
        bridges, loaders = {}, {}
        for name, entry in records.items():
            _selector, module_name, receipt_name = BRIDGES[name]
            mechanical = authority.importlib.import_module("." + module_name, authority.__package__)
            if entry["package_path"] != str(mechanical._PACKAGE):
                raise ValueError("administrator mechanical package path differs")
            captured = mechanical._bundle()  # complete pure reads, never a linker load
            wanted = {
                "name": name, "abi": mechanical.ABI, "package_path": str(mechanical._PACKAGE),
                "profile": captured["profile"],
                "build_receipt": {"path": str(mechanical._PACKAGE / receipt_name),
                                  **_pin(captured["manifest"])},
                "binary": {"name": captured["path"].name, "path": str(captured["path"]),
                           **_pin(captured["binary"])},
                "sources": {source: {"path": str(mechanical._source_path(source)), **_pin(raw)}
                            for source, raw in sorted(captured["sources"].items())},
            }
            # Canonical JSON also rejects bool/int equality in all nested pins.
            if authority._canonical_bridge(entry) != authority._canonical_bridge(wanted):
                raise ValueError("administrator mechanical executable/source/receipt pin differs")
            for path, raw, limit in (
                    (mechanical._PACKAGE / receipt_name, captured["manifest"], authority.MAX_SOURCE_BYTES),
                    (captured["path"], captured["binary"], authority.MAX_IMAGE_BYTES)):
                read = self.capture(path, limit, sha256(raw).hexdigest())
                if read.raw != raw:
                    raise ValueError("mechanical authority changed during capture")
            for source, raw in captured["sources"].items():
                read = self.capture(mechanical._source_path(source), authority.MAX_SOURCE_BYTES,
                                    sha256(raw).hexdigest())
                if read.raw != raw:
                    raise ValueError("mechanical source changed during capture")
            bridges[name] = _CarrierBridge(self, captured, wanted)
            loaders[name] = mechanical
        self.bridges = MappingProxyType(bridges)
        self.check_files()
        # The reserved token is owned only by this constructor. Every loader
        # repeats the same complete check immediately before executing its C.
        authority._MECHANICAL_BUILD = self
        try:
            loaded = {name: module.extension() for name, module in loaders.items()}
            self.legacy = authority.NativeHelpersBinding(str(base.path), value["helpers_bundle_sha256"])
            self.images = dict(self.legacy.images)
            self.selections = dict(self.legacy.selections)
            for name in ("native-image", "cell-frame"):
                if name not in bridges:
                    continue
                selector = BRIDGES[name][0]
                required_path = str(entries[selector][0].resolve(strict=True))
                images = [image for key, image in self.images.items() if key[0] == required_path]
                if len(images) != 1:
                    raise ValueError("explicit mechanical HIA owner has no unique captured image")
                if name == "native-image" and getattr(images[0], '_native_image_carrier', None) is not loaded[name]:
                    raise ValueError("explicit native-image owner did not retain its admitted C carrier")
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
                    or entry["selector"] not in authority.HELPERS or entry["selector"] in entries
                    or not authority._digest(entry["manifest_sha256"])):
                raise ValueError("invalid mechanical v1 helper selection")
            entries[entry["selector"]] = (
                authority._path(entry["manifest_path"], base.path.parent), entry["manifest_sha256"])
        patch = entries.get("HEPTA_HIA_CORE_PATCH_MANIFEST")
        admission = entries.get("HEPTA_HIA_CORE_ADMISSION_MANIFEST")
        if patch is not None and (admission is None
                or admission[0].resolve(strict=True) !=
                   patch[0].resolve(strict=True).parent / "admission-manifest.json"):
            raise ValueError("native Core patch requires its exact adjacent admission helper")
        for selector, (path, digest) in entries.items():
            manifest = self.capture(path, authority.MAX_MANIFEST_BYTES, digest)
            record = authority._decode(manifest.raw)
            module = authority.importlib.import_module("." + authority.HELPERS[selector][0], authority.__package__)
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
        if (authority._ACTIVE is not self and authority._MECHANICAL_BUILD is not self):
            raise ValueError("mechanical capsule is not the current worker authority")
        if (type(name) is not str or name not in self.bridges or type(abi) is not str
                or abi != self.bridges[name].record["abi"]):
            raise ValueError("mechanical bridge is outside the pinned capsule")
        self.check_files()
        return self.bridges[name]
