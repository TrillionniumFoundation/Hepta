"""Exact three-companion custody for the ordinary HIA Core scheduler.

This separately named schema preserves the old five-field helper contract.
Its eight-field manifests bind the actual HIA source, ABI, bridge, selector,
image and compiler. A closed v3 scheduler, optionally wrapped by Page, owns
the same three objects throughout one Worker scope.
"""
from __future__ import annotations

from hashlib import sha256
from importlib import import_module
from pathlib import Path
from types import MappingProxyType

_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()

from . import hia_native_helpers as authority

SCHEMA = 'hepta.hia.core-companion-worker-bundle.v1'
BASE_SCHEMAS = ('hepta.hia.native-helpers.v3',
                'hepta.hia.artifact-page-worker-bundle.v1')
KINDS = ('compare', 'integer', 'unpack')
FACTORIES = ('NativeNumericCompare', 'NativeInteger', 'NativeUnpack')
SELECTORS = tuple('HEPTA_HIA_CORE_' + kind.upper() + '_MANIFEST' for kind in KINDS)


class NativeCoreCompanionWorkerBinding:
    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        self._capture_basis = None
        self._registrations = ()
        self._scheduler = None
        self._owners = None
        if (not authority._digest(expected_sha256)
                or sha256(snapshot.raw).hexdigest() != expected_sha256):
            raise ValueError('Core companion Worker capsule identity mismatch')
        record = authority._decode(snapshot.raw)
        if (type(record) is not dict or set(record) != {
                'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                'compiler_sha256', 'companions'}
                or record['schema'] != SCHEMA or record['target'] != authority.TARGET
                or record['abi'] != authority.ABI
                or not authority._digest(record['base_bundle_sha256'])
                or not authority._digest(record['compiler_sha256'])
                or type(record['companions']) is not list
                or len(record['companions']) != len(KINDS)):
            raise ValueError('unsupported Core companion Worker capsule')
        self.sha256 = expected_sha256
        self.compiler_sha256 = record['compiler_sha256']
        own = self.capture(Path(__file__).resolve(), authority.MAX_SOURCE_BYTES)
        if own.raw != _EXECUTED_SOURCE:
            raise ValueError('executing Core companion custody source changed after import')
        base = self.capture(authority._path(record['base_bundle'], snapshot.path.parent),
                            authority.MAX_BUNDLE_BYTES, record['base_bundle_sha256'])
        base_record = authority._decode(base.raw)
        if type(base_record) is not dict or base_record.get('schema') not in BASE_SCHEMAS:
            raise ValueError('Core companions require their closed v3 or Page scheduler base')
        captures = []
        selections = {}
        for kind, factory_name, entry in zip(KINDS, FACTORIES, record['companions'], strict=True):
            if (type(entry) is not dict or set(entry) != {
                    'kind', 'manifest_path', 'manifest_sha256'}
                    or type(entry['kind']) is not str or entry['kind'] != kind
                    or not authority._digest(entry['manifest_sha256'])):
                raise ValueError('Core companion kinds must be complete, unique and ordered')
            selection = import_module('.hia_core_' + kind + '_selection', __package__)
            manifest = self.capture(authority._path(entry['manifest_path'], snapshot.path.parent),
                                    4096, entry['manifest_sha256'])
            current = selection.current_inputs()
            paths = {
                selection.HIA_SOURCE: selection._source_resource_path(selection.HIA_SOURCE),
                selection.ABI_SOURCE: selection._source_resource_path(selection.ABI_SOURCE),
                selection.BRIDGE_SOURCE: Path(selection.primitive.__file__).resolve(),
                selection.SELECTION_SOURCE: Path(selection.__file__).resolve(),
            }
            source_captures = {}
            for name, path in paths.items():
                captured = self.capture(path, authority.MAX_SOURCE_BYTES)
                if captured.raw != current[name]:
                    raise ValueError('Core companion source changed during capture')
                source_captures[name] = captured
            hashes = {name: sha256(captured.raw).hexdigest()
                      for name, captured in source_captures.items()}
            selection.checked_abi(source_captures[selection.ABI_SOURCE].raw)
            value = selection._manifest(manifest.raw, hashes, self.compiler_sha256)
            image = self.capture(authority._path(value['image_path'], manifest.path.parent),
                                 authority.MAX_IMAGE_BYTES, value['image_sha256'])
            selections[selection.SELECTOR] = str(manifest.path)
            captures.append((kind, selection, factory_name, manifest, image, value))
        self._captures = tuple(captures)
        self._companion_selections = MappingProxyType(selections)
        self._capture_basis = tuple(self.snapshots)
        self.check_scheduling_companion()
        if base_record['schema'] == BASE_SCHEMAS[0]:
            from .hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
            self.base_binding = NativeWorkerSchedulingBinding(
                base, record['base_bundle_sha256'], core_companions=self)
        else:
            from .hia_artifact_page_worker_bundle import NativeArtifactPageWorkerBinding
            self.base_binding = NativeArtifactPageWorkerBinding(
                base, record['base_bundle_sha256'], core_companions=self)
        if self._owners is None or self._scheduler is None:
            raise ValueError('Core companions were not bound by the actual v3 scheduler')
        self.selections = dict(self.base_binding.selections)
        if any(self.selections.get(key) != value for key, value in selections.items()):
            raise ValueError('Core companion scheduler selection differs')
        self.images = dict(self.base_binding.images)
        self.bundles = dict(getattr(self.base_binding, 'bundles', {}))
        self.check_files()

    def capture(self, path, limit, expected=None):
        captured = authority._read(path, limit)
        if expected is not None and (
                not authority._digest(expected) or sha256(captured.raw).hexdigest() != expected):
            raise ValueError('Core companion captured input identity mismatch')
        self.snapshots.append((captured, limit))
        return captured

    def check_owner(self):
        if self.owner != (authority.os.getpid(), authority.threading.get_ident()):
            raise ValueError('Core companion binding belongs to its original process and thread')

    def check_scheduling_companion(self):
        # This method never recurses into the base which is checking this layer.
        self.check_owner()
        if self._capture_basis is None or len(self._captures) != len(KINDS):
            raise ValueError('Core companion input capture is incomplete')
        for original, limit in self._capture_basis:
            if authority._read(original.path, limit) != original:
                raise ValueError('Core companion captured inputs changed')
        if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('executing Core companion custody source changed after import')
        return dict(self._companion_selections)

    def map_scheduling_companions(self, scheduler, compiler_sha256):
        from .hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
        from .hia_json_preflight_native import NativeHiaJsonImage
        if (type(scheduler) is not NativeWorkerSchedulingBinding
                or getattr(scheduler, '_complete_input_capture', False) is not True
                or scheduler._core_companions is not self
                or self._scheduler is not None or self._owners is not None
                or type(compiler_sha256) is not str
                or compiler_sha256 != self.compiler_sha256):
            raise ValueError('Core companion construction lacks its exact captured scheduler')
        self.check_scheduling_companion()
        self._scheduler = scheduler
        owners, registrations = {}, []
        for kind, selection, factory_name, manifest, captured_image, value in self._captures:
            image = NativeHiaJsonImage(captured_image.raw, value['image_sha256'])
            image.admitted_source_sha256 = value['source_sha256']
            factory = getattr(selection.primitive, factory_name)
            owner = factory(image)
            fields = {
                'source_sha256': value['source_sha256'],
                'abi_sha256': value['abi_sha256'],
                'bridge_sha256': value['bridge_sha256'],
                'selection_sha256': value['selection_sha256'],
                'image_sha256': value['image_sha256'],
                'compiler_sha256': self.compiler_sha256,
                'manifest_sha256': sha256(manifest.raw).hexdigest(),
            }
            leaves = None
            if kind == 'unpack':
                leaves = owner.leaves
                fields.update(transaction_sha256=selection.primitive.SHIM_SHA256,
                              runtime_profile=leaves.profile)
            admitted = selection._Admitted(**fields)
            setattr(owner, '_admitted_' + kind, admitted)
            image._worker_core_companions = self
            owner._worker_core_companions = self
            owners[kind] = owner
            registrations.append((kind, owner, image, admitted, leaves))
        self._owners = MappingProxyType(owners)
        self._registrations = tuple(registrations)
        self.check_scheduling_companion()

    def scheduler_arguments(self, scheduler):
        if scheduler is not self._scheduler or self._owners is None:
            raise ValueError('Core companion scheduler construction changed')
        self.check_owner()
        return {'numeric_compare': self._owners['compare'],
                'integer': self._owners['integer'], 'unpack': self._owners['unpack']}

    def check_scheduler(self, scheduler, owner):
        if scheduler is not self._scheduler or self._owners is None:
            raise ValueError('Core companion scheduler identity changed')
        if any(getattr(owner, field, None) is not self._owners[kind]
               for kind, field in (('compare', 'numeric_compare'),
                                   ('integer', 'integer'), ('unpack', 'unpack'))):
            raise ValueError('Core scheduler lost its original three companion objects')
        for _kind, _owner, image, _admitted, _leaves in self._registrations:
            self.check_image(image)

    def check_image(self, image):
        self.check_owner()
        row = next((row for row in self._registrations if row[2] is image), None)
        if row is None or image._worker_core_companions is not self:
            raise ValueError('Core companion image is outside its original Worker capsule')
        kind, owner, original, admitted, leaves = row
        if (owner.image is not original or owner._worker_core_companions is not self
                or getattr(owner, '_admitted_' + kind, None) is not admitted
                or (leaves is not None and owner.leaves is not leaves)):
            raise ValueError('Core companion owner or image registration changed')

    def selected_owner(self, manifest_path, kind, compiler_sha256):
        self.check()
        if type(kind) is not str or kind not in KINDS or compiler_sha256 != self.compiler_sha256:
            raise ValueError('Core companion selection differs from its pinned compiler or kind')
        index = KINDS.index(kind)
        path = authority._path(str(manifest_path)).resolve(strict=True)
        if path != Path(self._companion_selections[SELECTORS[index]]).resolve(strict=True):
            raise ValueError('Core companion manifest is outside the pinned Worker capsule')
        owner = self._owners[kind]
        self.check_image(owner.image)
        return owner

    def check_files(self):
        self.check_scheduling_companion()
        base = getattr(self, 'base_binding', None)
        if base is not None:
            base.check_files()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError('Core companion Worker inputs changed')

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('Core companion Worker selection changed')
        self.check_files()


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
