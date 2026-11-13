"""Explicit v3 worker custody for five in-process HIA scheduling families.

This is a hosted executable-custody adapter, not a native object runtime or
SQLite replacement. It admits the complete fixed input closure before mapping
new scheduler code. v1/v2 capsules still cannot select any of these families.
"""
from __future__ import annotations

from hashlib import sha256
from importlib import import_module
from pathlib import Path
from types import MappingProxyType

from . import hia_native_helpers as authority

SCHEMA = 'hepta.hia.native-helpers.v3'
FAMILIES = {
    'execution-observation': ('execution_observation', 'hia_opcodes'),
    'core-lowering': ('core_lowering', 'hia_program_native'),
    'core-emitter': ('core_emitter', 'hia_program_native'),
    'byte-wrapper': ('byte_wrapper', 'hia_native_byte_abi'),
    'machine-object': ('machine_object', 'hia_machine_elf'),
}


class NativeWorkerSchedulingBinding:
    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        self.sha256 = expected_sha256
        self.snapshots = []
        self.schedulers = {}
        self._registrations = []
        if (not authority._digest(expected_sha256)
                or sha256(snapshot.raw).hexdigest() != expected_sha256):
            raise ValueError('native scheduling capsule identity mismatch')
        self.snapshots.append((snapshot, authority.MAX_BUNDLE_BYTES))
        record = authority._decode(snapshot.raw)
        if (type(record) is not dict or set(record) != {
                'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                'runtime_sha256', 'schedulers'} or record['schema'] != SCHEMA
                or record['target'] != authority.TARGET or record['abi'] != authority.ABI
                or not authority._digest(record['base_bundle_sha256'])
                or type(record['schedulers']) is not list
                or not 1 <= len(record['schedulers']) <= len(FAMILIES)):
            raise ValueError('unsupported native scheduling capsule')
        # Pin the entire production package inventory, not just the entry shim.
        package = Path(__file__).parent
        runtime = {'hepta/' + p.name: p for p in package.glob('*.py')}
        pins = record['runtime_sha256']
        if type(pins) is not dict or set(pins) != set(runtime):
            raise ValueError('native scheduling runtime inventory differs')
        for name, path in sorted(runtime.items()):
            self.capture(path, authority.MAX_SOURCE_BYTES, pins[name])
        base = self.capture(authority._path(record['base_bundle'], snapshot.path.parent),
                            authority.MAX_BUNDLE_BYTES, record['base_bundle_sha256'])
        self.capture_base(base)
        captures = []
        seen = set()
        for entry in record['schedulers']:
            if (type(entry) is not dict or set(entry) != {'kind', 'manifest_path', 'manifest_sha256'}
                    or type(entry['kind']) is not str or entry['kind'] not in FAMILIES
                    or entry['kind'] in seen or not authority._digest(entry['manifest_sha256'])):
                raise ValueError('unknown, duplicate or unpinned scheduling family')
            seen.add(entry['kind'])
            path = authority._path(entry['manifest_path'], snapshot.path.parent)
            captures.append(self.capture_scheduler(entry['kind'], path, entry['manifest_sha256']))
        # All sources, runtime, ABI, unit images and aggregate containers have
        # been captured and re-read before the first new executable mapping.
        self.check_files()
        base_record = authority._decode(base.raw)
        if base_record['schema'] == authority.SCHEMA:
            self.legacy = authority.NativeHelpersBinding(str(base.path), record['base_bundle_sha256'])
        else:
            from .hia_worker_bundle import NativeWorkerBundleBinding
            self.legacy = NativeWorkerBundleBinding(base, record['base_bundle_sha256'])
        self.selections = dict(self.legacy.selections)
        self.images = dict(self.legacy.images)
        self.bundles = dict(getattr(self.legacy, 'bundles', {}))
        from .hia_native_continuation_selection import _FAMILIES, _RUNTIME, INPROCESS_SCHEMA
        from .hia_native_continuation_inprocess import InProcessContinuation
        from .hia_json_preflight_native import NativeHiaJsonImage
        from .hia_agent_contract import CONTINUATION_BUILD_FILES
        for kind, outer, value, selection, abi, abi_raw, policy, units, aggregate in captures:
            namespace = vars(import_module('.' + FAMILIES[kind][1], __package__))
            images = tuple(NativeHiaJsonImage(image.raw, image_hash)
                           for _name, _source_hash, image, image_hash in units)
            loaded = selection._Loaded(abi, tuple(row[0] for row in units), images,
                sha256(abi_raw).hexdigest(), tuple((row[0], row[1]) for row in units),
                sha256(policy.raw).hexdigest())
            factory = _FAMILIES[kind][1]
            # Only the exact statically selected owner may initialize its pool
            # and in-process peer while the scope is still being constructed.
            owner = factory.__new__(factory)
            previous = authority._SCHEDULER_BUILD
            if previous is not None:
                raise ValueError('nested native scheduling construction')
            authority._SCHEDULER_BUILD = (self, owner)
            try:
                factory.__init__(owner, images[1:], images[0], abi, namespace)
                owner._admitted_bundle = loaded
                owner._continuation = InProcessContinuation(aggregate.raw, value['image_sha256'],
                    pool_bytes=abi['pool_bytes'], owner=owner)
            finally:
                authority._SCHEDULER_BUILD = previous
            owner._worker_scheduling_binding = self
            resources = value['resource_sha256']
            runtime_pins = value['runtime_sha256']
            owner._native_continuation_identity = ('\0'.join((INPROCESS_SCHEMA,
                sha256(outer.raw).hexdigest(), value['image_sha256'],
                *(resources[n] for n in CONTINUATION_BUILD_FILES),
                *(runtime_pins['hepta/' + n] for n in _RUNTIME)))).encode('ascii')
            key = (str(outer.path.resolve(strict=True)), kind)
            self.schedulers[key] = owner
            self._registrations.append((key, owner, owner._continuation, namespace))
            self.selections[selection.SELECTOR] = str(outer.path)
        self.schedulers = MappingProxyType(self.schedulers)
        self._registrations = tuple(self._registrations)
        self.check_files()

    def capture(self, path, limit, pin=None):
        value = authority._read(path, limit)
        if pin is not None and (not authority._digest(pin) or sha256(value.raw).hexdigest() != pin):
            raise ValueError('native scheduling captured input identity mismatch')
        self.snapshots.append((value, limit))
        return value

    def capture_image(self, manifest, source, schema):
        record = authority._decode(manifest.raw)
        if (type(record) is not dict or set(record) != {
                'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                or record['schema'] != schema
                or any(not authority._digest(record[k])
                       for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
            raise ValueError('native scheduling child image contract differs')
        self.capture(source, authority.MAX_SOURCE_BYTES, record['source_sha256'])
        image = self.capture(authority._path(record['image_path'], manifest.path.parent),
                             authority.MAX_IMAGE_BYTES, record['image_sha256'])
        return image, record

    def capture_base(self, base):
        """Pure pre-admission of every legacy input; legacy guards still run."""
        value = authority._decode(base.raw)
        if type(value) is not dict:
            raise ValueError('invalid native scheduling base capsule')
        if value.get('schema') == 'hepta.hia.native-helpers.v2':
            from . import hia_worker_report_native as worker
            from . import hia_json_wire_native as wire
            if (set(value) != {'schema', 'target', 'abi', 'helpers_bundle', 'helpers_bundle_sha256',
                              'report_bundle', 'report_bundle_sha256'}
                    or value['target'] != authority.TARGET or value['abi'] != authority.ABI):
                raise ValueError('invalid native scheduling v2 base')
            helpers = self.capture(authority._path(value['helpers_bundle'], base.path.parent),
                authority.MAX_BUNDLE_BYTES, value['helpers_bundle_sha256'])
            self.capture_base(helpers)
            hv = authority._decode(helpers.raw)
            if not any(e['selector'] == 'HEPTA_HIA_WORKER_REQUEST_MANIFEST' for e in hv['helpers']):
                raise ValueError('native scheduling v2 base requires request helper')
            report = self.capture(authority._path(value['report_bundle'], base.path.parent),
                8192, value['report_bundle_sha256'])
            rv = authority._decode(report.raw)
            if (type(rv) is not dict or set(rv) != {'schema', 'policy_manifest', 'policy_manifest_sha256',
                    'wire_manifest', 'wire_manifest_sha256'} or rv['schema'] != worker.SCHEMA):
                raise ValueError('invalid native scheduling report companion')
            for name, source, schema in [('policy', worker.SOURCE, worker.POLICY_SCHEMA),
                                         ('wire', wire.SOURCE, wire.SCHEMA)]:
                relative = rv[name + '_manifest']
                if (type(relative) is not str or not relative or Path(relative).is_absolute()
                        or '..' in Path(relative).parts):
                    raise ValueError('invalid native scheduling report companion path')
                manifest = self.capture(authority._path(relative, report.path.parent),
                    authority.MAX_MANIFEST_BYTES, rv[name + '_manifest_sha256'])
                self.capture_image(manifest, source, schema)
            return
        if (set(value) != {'schema', 'target', 'abi', 'helpers'} or value.get('schema') != authority.SCHEMA
                or value['target'] != authority.TARGET or value['abi'] != authority.ABI
                or type(value['helpers']) is not list or not 1 <= len(value['helpers']) <= len(authority.HELPERS)):
            raise ValueError('invalid native scheduling v1 base')
        entries = {}
        for entry in value['helpers']:
            if (type(entry) is not dict or set(entry) != {'selector', 'manifest_path', 'manifest_sha256'}
                    or type(entry['selector']) is not str or entry['selector'] not in authority.HELPERS
                    or entry['selector'] in entries or not authority._digest(entry['manifest_sha256'])):
                raise ValueError('invalid native scheduling legacy selection')
            selector = entry['selector']
            entries[selector] = authority._path(entry['manifest_path'], base.path.parent)
            module = import_module('.' + authority.HELPERS[selector][0], __package__)
            manifest = self.capture(entries[selector], authority.MAX_MANIFEST_BYTES, entry['manifest_sha256'])
            self.capture_image(manifest, module.SOURCE, module.SCHEMA)
        patch = entries.get('HEPTA_HIA_CORE_PATCH_MANIFEST')
        admission = entries.get('HEPTA_HIA_CORE_ADMISSION_MANIFEST')
        if patch is not None and (admission is None or admission.resolve(strict=True) !=
                                  patch.resolve(strict=True).parent / 'admission-manifest.json'):
            raise ValueError('native Core patch requires its exact adjacent admission helper')

    def capture_scheduler(self, kind, path, pin):
        from .hia_native_continuation_selection import INPROCESS_SCHEMA, _RUNTIME
        from .hia_agent_contract import CONTINUATION_BUILD_FILES
        from .hia_json_preflight_native import _source_resource_path
        from .hia_native_continuation import MAX_EXECUTABLE
        selection = import_module('.hia_' + FAMILIES[kind][0] + '_selection', __package__)
        outer = self.capture(path, authority.MAX_MANIFEST_BYTES, pin)
        value = authority._decode(outer.raw)
        if (type(value) is not dict or set(value) != {'schema', 'kind', 'policy_bundle',
                'policy_bundle_sha256', 'compiler_sha256', 'image_path', 'image_sha256',
                'resource_sha256', 'runtime_sha256'} or value['schema'] != INPROCESS_SCHEMA
                or value['kind'] != kind or value['policy_bundle'] != 'policy/manifest.json'
                or value['image_path'] != 'continuation.image.bin'
                or not authority._digest(value['compiler_sha256'])):
            raise ValueError('invalid native scheduling in-process owner')
        resources = {n: _source_resource_path(n) for n in CONTINUATION_BUILD_FILES}
        runtime = {'hepta/' + n: Path(__file__).parent / n for n in _RUNTIME}
        for field, paths in [('resource_sha256', resources), ('runtime_sha256', runtime)]:
            pins = value[field]
            if type(pins) is not dict or set(pins) != set(paths):
                raise ValueError('native scheduling owner source inventory differs')
            for name, source in paths.items():
                self.capture(source, authority.MAX_SOURCE_BYTES, pins[name])
        abi_snapshot = self.capture(_source_resource_path(selection.ABI_SOURCE), authority.MAX_SOURCE_BYTES)
        abi = selection.checked_abi(abi_snapshot.raw)
        names = tuple(Path(n).stem for n in selection.source_names(abi))
        policy = self.capture(path.parent / 'policy/manifest.json', authority.MAX_MANIFEST_BYTES,
                              value['policy_bundle_sha256'])
        base = authority._decode(policy.raw)
        if (type(base) is not dict or set(base) != {'schema', 'abi_sha256', 'compiler_sha256', 'unit_manifests'}
                or base['schema'] != selection.SCHEMA
                or base['abi_sha256'] != sha256(abi_snapshot.raw).hexdigest()
                or base['compiler_sha256'] != value['compiler_sha256']
                or base['unit_manifests'] != {n: n + '/manifest.json' for n in names}):
            raise ValueError('native scheduling complete policy or ABI differs')
        units = []
        for name in names:
            manifest = self.capture(policy.path.parent / base['unit_manifests'][name], authority.MAX_MANIFEST_BYTES)
            image, row = self.capture_image(manifest,
                _source_resource_path('examples/hia_bootstrap/' + name + '.hepta'), selection.UNIT_SCHEMA)
            if row['compiler_sha256'] != value['compiler_sha256']:
                raise ValueError('native scheduling compiler differs across units')
            units.append((name, row['source_sha256'], image, row['image_sha256']))
        aggregate = self.capture(path.parent / value['image_path'], MAX_EXECUTABLE, value['image_sha256'])
        return kind, outer, value, selection, abi, abi_snapshot.raw, policy, units, aggregate

    def check_owner(self):
        if self.owner != (authority.os.getpid(), authority.threading.get_ident()):
            raise ValueError('native helper binding belongs to its original process and thread')

    def check_files(self):
        self.check_owner()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError('native scheduling capsule inputs changed; observe the original operation')
        legacy = getattr(self, 'legacy', None)
        if legacy is not None:
            legacy.check_files()

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('native helper selection changed; observe the original operation')
        self.check_files()

    def scheduling_owner(self, manifest_path, kind, namespace):
        self.check_scheduling()
        if type(kind) is not str or kind not in FAMILIES or type(namespace) is not dict:
            raise ValueError('native scheduling owner binding differs')
        key = (str(authority._path(str(manifest_path)).resolve(strict=True)), kind)
        owner = self.schedulers.get(key)
        registration = next((r for r in self._registrations if r[0] == key), None)
        if (registration is None or owner is None or registration[3] is not namespace
                or owner.namespace is not registration[3]):
            raise ValueError('native scheduling owner is outside the pinned worker capsule')
        self.check_scheduling(owner)
        return owner

    def check_scheduling(self, owner=None, *, engine=None, host_scheduler=False, observing=False):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('native helper selection changed; observe the original operation')
        if owner is None and engine is None and not host_scheduler and not observing:
            return
        registration = next((r for r in self._registrations if r[1] is owner), None)
        if (host_scheduler or owner is None or registration is None
                or owner.namespace is not registration[3]
                or owner._continuation is not registration[2]
                or (engine is not None and engine is not registration[2])):
            raise ValueError('native scheduling owner or engine is outside the pinned worker capsule')
