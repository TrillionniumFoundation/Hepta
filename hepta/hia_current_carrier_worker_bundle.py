"""Explicit current Worker composition for the two native HIA carrier policies.

The old v6 envelope keeps its closed v1 domain. This distinct envelope first
admits its ordinary typed child with every existing guard, then admits the
three statically named host ABI bridges required by that child's selectors.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

from . import hia_native_helpers as authority
from .hia_native_carrier_worker_bundle import (
    NativeCarrierWorkerBinding, _CarrierBridge, BRIDGES, _pin,
)
from .hia_carrier_policy_release import capture as capture_policy_release

SCHEMA = "hepta.hia.current-carrier-worker-bundle.v1"
ABI = "hia-worker-current-native-carriers-v1"
BASE_SCHEMAS = (
    "hepta.hia.native-helpers.v24",
    "hepta.hia.core-companion-worker-bundle.v1",
    "hepta.hia.artifact-page-worker-bundle.v1",
    "hepta.hia.native-helpers.v3",
)
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()
_STORE_ATTRIBUTES = (
    "native_store", "native_store_initializer", "native_evaluate_case_executable",
    "native_evaluate_request_executable", "native_evaluate_authority_executable",
    "native_edit_query", "native_candidate_import", "native_reference_executable",
    "native_owned_reference_executable", "native_direct_call_executable",
    "native_direct_call_protocol", "native_agent_read_page_executable",
    "native_agent_journal_executable", "native_agent_store_unique_executable",
    "native_worker_journal_cost_executable", "native_worker_data_executable",
    "native_worker_terminal_executable", "native_worker_admission_executable",
)


def _ordinary_binding(base, expected, record):
    if type(record) is not dict or record.get("schema") not in BASE_SCHEMAS:
        raise ValueError("current carriers require an explicit current typed Worker child")
    if record["schema"] == BASE_SCHEMAS[0]:
        from .hia_worker_store_profile import NativeWorkerStoreBinding
        return NativeWorkerStoreBinding(base, expected, record)
    return authority._base_binding(base, expected, record)


def _ordinary_chain(binding):
    from .hia_worker_store_profile import NativeWorkerStoreBinding
    from .hia_core_companion_worker_bundle import NativeCoreCompanionWorkerBinding
    from .hia_artifact_page_worker_bundle import NativeArtifactPageWorkerBinding
    from .hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
    from .hia_worker_bundle import NativeWorkerBundleBinding
    links = {
        NativeWorkerStoreBinding: "base_binding",
        NativeCoreCompanionWorkerBinding: "base_binding",
        NativeArtifactPageWorkerBinding: "base_binding",
        NativeWorkerSchedulingBinding: "legacy",
        NativeWorkerBundleBinding: "legacy",
    }
    result = []
    while True:
        if any(binding is item for item in result) or len(result) >= 7:
            raise ValueError("current carrier Worker child contains a cycle")
        result.append(binding)
        if type(binding) is authority.NativeHelpersBinding:
            break
        field = links.get(type(binding))
        if field is None:
            raise ValueError("unknown current carrier Worker child custody type")
        binding = getattr(binding, field)
    return tuple(result)


class NativeCurrentCarrierWorkerBinding(NativeCarrierWorkerBinding):
    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        self._current_complete = False
        self._store_values = ()
        if (authority._SCOPE_OWNER != self.owner or authority._ACTIVE is not None
                or authority._MECHANICAL_BUILD is not None
                or authority._MECHANICAL_SCOPE is not None
                or authority._MECHANICAL_SELECTED is not False):
            raise ValueError("current carriers require one exclusive unselected scope")
        if (not authority._digest(expected_sha256)
                or sha256(snapshot.raw).hexdigest() != expected_sha256):
            raise ValueError("current carrier Worker capsule identity mismatch")
        record = authority._decode(snapshot.raw)
        if (type(record) is not dict or set(record) != {
                "schema", "target", "abi", "base_bundle", "base_bundle_sha256",
                "policy_release", "policy_release_sha256", "bridges"}
                or record["schema"] != SCHEMA or record["target"] != authority.TARGET
                or record["abi"] != ABI
                or not authority._digest(record["base_bundle_sha256"])
                or not authority._digest(record["policy_release_sha256"])
                or type(record["bridges"]) is not list):
            raise ValueError("unsupported current carrier Worker capsule")
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        from .hia_loaded_source import loaded_source_identity
        identities = loaded_source_identity(__name__, (
            'hia_current_carrier_worker_bundle.py', 'hia_carrier_policy_release.py',
            'hia_native_carrier_worker_bundle.py', 'hia_native_helpers.py'))
        for name, identity in identities.items():
            self.capture(Path(__file__).resolve().parent / name,
                         authority.MAX_SOURCE_BYTES, identity)
        own = self.capture(Path(__file__).resolve(), authority.MAX_SOURCE_BYTES,
                           sha256(_EXECUTED_SOURCE).hexdigest())
        if own.raw != _EXECUTED_SOURCE:
            raise ValueError("executing current carrier custody source changed")
        base = self.capture(authority._path(record["base_bundle"], snapshot.path.parent),
                            authority.MAX_BUNDLE_BYTES, record["base_bundle_sha256"])
        base_record = authority._decode(base.raw)
        # No mechanical route has been selected and no extension has been loaded.
        # The existing complete Store/Core/Page/scheduler admission runs unchanged.
        self.base_binding = _ordinary_binding(base, record["base_bundle_sha256"], base_record)
        self._ordinary = _ordinary_chain(self.base_binding)
        self.selections = dict(self.base_binding.selections)
        required = sorted(name for name, (selector, _loader, _receipt) in BRIDGES.items()
                          if selector in self.selections)
        if not {"native-image", "cell-frame"} <= set(required):
            raise ValueError("current carriers require both actual HIA service owners")
        entries = {}
        for entry in record["bridges"]:
            if (type(entry) is not dict or set(entry) != {
                    "name", "abi", "package_path", "profile", "build_receipt", "binary", "sources"}
                    or type(entry["name"]) is not str or entry["name"] not in BRIDGES
                    or entry["name"] in entries):
                raise ValueError("unknown or duplicate current mechanical bridge")
            entries[entry["name"]] = entry
        if list(entries) != required:
            raise ValueError("current carrier bridges must exactly cover the actual selectors")
        from . import hia_native_image, hia_cell_frame
        if hia_native_image._PACKAGE != hia_cell_frame._PACKAGE:
            raise ValueError("current carriers must share one actual package")
        release_path = authority._path(record["policy_release"], snapshot.path.parent)
        def release_read(path):
            captured = authority._read(path, authority.MAX_SOURCE_BYTES)
            self.snapshots.append((captured, authority.MAX_SOURCE_BYTES))
            return captured.raw
        release, _ = capture_policy_release(release_path, record["policy_release_sha256"],
                                             hia_native_image._PACKAGE, release_read)
        bridges, loaders = {}, {}
        for name, entry in entries.items():
            _selector, module_name, receipt_name = BRIDGES[name]
            loader = authority.importlib.import_module("." + module_name, authority.__package__)
            captured = loader._bundle()
            wanted = {
                "name": name, "abi": loader.ABI, "package_path": str(loader._PACKAGE),
                "profile": captured["profile"],
                "build_receipt": {"path": str(loader._PACKAGE / receipt_name), **_pin(captured["manifest"])},
                "binary": {"name": captured["path"].name, "path": str(captured["path"]), **_pin(captured["binary"])},
                "sources": {source: {"path": str(loader._source_path(source)), **_pin(raw)}
                            for source, raw in sorted(captured["sources"].items())},
            }
            if authority._canonical_bridge(entry) != authority._canonical_bridge(wanted):
                raise ValueError("current carrier actual source/receipt/executable pin differs")
            if name in ("native-image", "cell-frame"):
                kind = "image" if name == "native-image" else "cell"
                actual = authority._decode(captured["manifest"])["hia_policy"]
                policy = release["roles"][kind]
                if (authority._canonical_bridge(actual["source"]) != authority._canonical_bridge(policy["source"])
                        or authority._canonical_bridge(actual["image"]) != authority._canonical_bridge(policy["image"])
                        or authority._canonical_bridge(actual["compiler"]) != authority._canonical_bridge(release["seed"])):
                    raise ValueError("current host ABI differs from its installed native policy publication")
            for path, raw, limit in (
                    (loader._PACKAGE / receipt_name, captured["manifest"], authority.MAX_SOURCE_BYTES),
                    (captured["path"], captured["binary"], authority.MAX_IMAGE_BYTES)):
                if self.capture(path, limit, sha256(raw).hexdigest()).raw != raw:
                    raise ValueError("current carrier changed during capture")
            for name_source, raw in captured["sources"].items():
                if self.capture(loader._source_path(name_source), authority.MAX_SOURCE_BYTES,
                                sha256(raw).hexdigest()).raw != raw:
                    raise ValueError("current carrier source changed during capture")
            bridges[name] = _CarrierBridge(self, captured, wanted)
            loaders[name] = loader
        self.bridges = MappingProxyType(bridges)
        self.check_files()
        authority._MECHANICAL_SELECTED = True
        authority._MECHANICAL_BUILD = self
        try:
            loaded = {name: module.extension() for name, module in loaders.items()}
            # Replace only this newly admitted, not-yet-exposed Artifact mapping.
            # All ordinary typed child identities and selectors remain those just admitted.
            from .hia_service_artifact_native import NativeServiceArtifact, SOURCE, SCHEMA as ARTIFACT_SCHEMA
            selector = BRIDGES["native-image"][0]
            manifest_path = authority._path(self.selections[selector])
            originals = [captured for child in self._ordinary
                         for captured, _limit in child.snapshots
                         if captured.path == manifest_path]
            if not originals or any(captured != originals[0] for captured in originals):
                raise ValueError("current Artifact lacks one initial physical manifest identity")
            manifest = self.capture(manifest_path, authority.MAX_MANIFEST_BYTES,
                                    sha256(originals[0].raw).hexdigest())
            if manifest != originals[0]:
                raise ValueError("current Artifact manifest changed after typed admission")
            item = authority._decode(manifest.raw)
            key = (str(manifest_path.resolve(strict=True)), str(SOURCE.resolve(strict=True)),
                   ARTIFACT_SCHEMA, NativeServiceArtifact)
            previous = self.base_binding.images.get(key)
            if type(previous) is not NativeServiceArtifact:
                raise ValueError("current Artifact owner is not its exact admitted factory")
            raw_image = self.capture(authority._path(item["image_path"], manifest_path.parent),
                                     authority.MAX_IMAGE_BYTES, item["image_sha256"])
            current = NativeServiceArtifact(raw_image.raw, item["image_sha256"])
            current.admitted_source_sha256 = item["source_sha256"]
            if current._native_image_carrier is not loaded["native-image"]:
                raise ValueError("current Artifact did not retain its selected native carrier")
            image_tables = []
            for child in self._ordinary:
                images = child.images
                if type(images) is not dict:
                    raise ValueError("current child image custody shape differs")
                if key in images:
                    if images[key] is not previous:
                        raise ValueError("current Artifact views no longer share their original image")
                    if not any(images is table for table in image_tables):
                        image_tables.append(images)
            if not image_tables:
                raise ValueError("current Artifact mapping was not bound by its typed child")
            for images in image_tables:
                images[key] = current
            self.images = dict(self.base_binding.images)
            self.bundles = dict(getattr(self.base_binding, "bundles", {}))
            names = {name for name in vars(self.base_binding) if name.startswith("native_")}
            if not names <= set(_STORE_ATTRIBUTES):
                raise ValueError("unregistered native Store field in current carrier composition")
            self._store_values = tuple((name, getattr(self.base_binding, name)) for name in sorted(names))
            for name, value in self._store_values:
                setattr(self, name, value)
            self._current_complete = True
            self.check_files()
        finally:
            authority._MECHANICAL_BUILD = None

    def check_files(self):
        self.check_owner()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError("current carrier Worker inputs changed")
        base = getattr(self, "base_binding", None)
        if base is not None:
            base.check_files()
        for name, value in self._store_values:
            if getattr(self, name, None) is not value or getattr(base, name, None) is not value:
                raise ValueError("current carrier lost the admitted Store authority")

    def ordinary_binding(self):
        self.check_owner()
        if self._current_complete is not True:
            raise ValueError("current carrier typed child admission is incomplete")
        return self.base_binding


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
