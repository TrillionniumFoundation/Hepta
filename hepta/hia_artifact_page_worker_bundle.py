"""Pinned Page/wire custody composed beneath the ordinary Worker profile.

This new schema leaves every existing v1/v2/v3 helper contract unchanged.
A Store profile may select this bundle as its base; its native Store and
standalone executable guards remain with the original Store profile owner.
"""
from __future__ import annotations

from hashlib import sha256

from . import hia_native_helpers as authority

SCHEMA = 'hepta.hia.artifact-page-worker-bundle.v1'
BASE_SCHEMAS = ('hepta.hia.native-helpers.v1', 'hepta.hia.native-helpers.v2',
                'hepta.hia.native-helpers.v3')
PAGE_SELECTOR = 'HEPTA_HIA_ARTIFACT_PAGE_MANIFEST'
WIRE_SELECTOR = 'HEPTA_HIA_JSON_WIRE_MANIFEST'


class NativeArtifactPageWorkerBinding:
    def __init__(self, snapshot, expected_sha256, *, core_companions=None):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('artifact-page Worker bundle identity mismatch')
        record = authority._decode(snapshot.raw)
        if (type(record) is not dict or set(record) != {
                'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                'page_bundle', 'page_bundle_sha256'}
                or record['schema'] != SCHEMA or record['target'] != authority.TARGET
                or record['abi'] != authority.ABI
                or not authority._digest(record['base_bundle_sha256'])
                or not authority._digest(record['page_bundle_sha256'])):
            raise ValueError('unsupported artifact-page Worker bundle')
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        base = authority._read(authority._path(record['base_bundle'], snapshot.path.parent),
                               authority.MAX_BUNDLE_BYTES)
        page = authority._read(authority._path(record['page_bundle'], snapshot.path.parent), 8192)
        if (sha256(base.raw).hexdigest() != record['base_bundle_sha256']
                or sha256(page.raw).hexdigest() != record['page_bundle_sha256']):
            raise ValueError('artifact-page Worker child bundle identity mismatch')
        base_record = authority._decode(base.raw)
        if type(base_record) is not dict or base_record.get('schema') not in BASE_SCHEMAS:
            raise ValueError('artifact-page requires a closed ordinary helper base')
        if core_companions is not None and base_record['schema'] != BASE_SCHEMAS[2]:
            raise ValueError('artifact-page Core companions require the closed v3 scheduler base')
        from . import hia_artifact_page_native as page_api
        from .hia_artifact_page_policy_native import NativeArtifactPagePolicy
        from .hia_json_wire_native import NativeJsonWire, SOURCE as wire_source, SCHEMA as wire_schema
        page_record = authority._decode(page.raw)
        if (type(page_record) is not dict or set(page_record) != {
                'schema', 'policy_manifest', 'policy_manifest_sha256',
                'wire_manifest', 'wire_manifest_sha256'}
                or page_record['schema'] != page_api.SCHEMA):
            raise ValueError('invalid artifact-page policy/wire bundle')
        captures = {}
        compiler = None
        for name, source_path, schema, factory in (
            ('policy', page_api.SOURCE, page_api.POLICY_SCHEMA, NativeArtifactPagePolicy),
            ('wire', wire_source, wire_schema, NativeJsonWire),
        ):
            relative = page_record[name + '_manifest']
            pin = page_record[name + '_manifest_sha256']
            if (type(relative) is not str or not relative
                    or authority.Path(relative).is_absolute() or '\\' in relative
                    or any(p in ('', '.', '..') for p in relative.split('/'))
                    or not authority._digest(pin)):
                raise ValueError('invalid artifact-page child manifest path/pin')
            manifest = authority._read(authority._path(relative, page.path.parent),
                                       authority.MAX_MANIFEST_BYTES)
            if sha256(manifest.raw).hexdigest() != pin:
                raise ValueError('artifact-page child manifest identity mismatch')
            item = authority._decode(manifest.raw)
            if (type(item) is not dict or set(item) != {
                    'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                    or item['schema'] != schema
                    or any(not authority._digest(item[k])
                           for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
                raise ValueError('artifact-page child executable contract differs')
            image_name = item['image_path']
            if (type(image_name) is not str or not image_name or image_name in ('.', '..')
                    or authority.Path(image_name).name != image_name
                    or '/' in image_name or '\\' in image_name
                    or any(ord(c) < 32 for c in image_name)):
                raise ValueError('artifact-page image must be a sibling basename')
            source = authority._read(source_path, authority.MAX_SOURCE_BYTES)
            image = authority._read(authority._path(image_name, manifest.path.parent),
                                    authority.MAX_IMAGE_BYTES)
            if (sha256(source.raw).hexdigest() != item['source_sha256']
                    or sha256(image.raw).hexdigest() != item['image_sha256']):
                raise ValueError('artifact-page executable/source identity mismatch')
            if compiler is not None and compiler != item['compiler_sha256']:
                raise ValueError('artifact-page children use different compilers')
            compiler = item['compiler_sha256']
            captures[name] = (manifest, source, image, item, factory)
            self.snapshots.extend(((manifest, authority.MAX_MANIFEST_BYTES),
                                   (source, authority.MAX_SOURCE_BYTES),
                                   (image, authority.MAX_IMAGE_BYTES)))
        self.snapshots.extend(((base, authority.MAX_BUNDLE_BYTES), (page, 8192)))
        self._page_manifest_snapshot = page
        self._page_capture_complete = True
        self.check_files()
        if base_record['schema'] == BASE_SCHEMAS[2]:
            from .hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
            self.base_binding = NativeWorkerSchedulingBinding(
                base, record['base_bundle_sha256'], page_companion=self,
                core_companions=core_companions)
        else:
            self.base_binding = authority._base_binding(base, record['base_bundle_sha256'], base_record)
        self.selections = dict(self.base_binding.selections)
        self.images = dict(self.base_binding.images)
        self.bundles = dict(getattr(self.base_binding, 'bundles', {}))
        if ('HEPTA_HIA_SERVICE_READ_MANIFEST' in self.selections
                or (PAGE_SELECTOR in self.selections
                    and (base_record['schema'] != BASE_SCHEMAS[2]
                         or self.selections[PAGE_SELECTOR] != str(page.path)))):
            raise ValueError('artifact page and complete service read require separate explicit selections')
        if base_record['schema'] == BASE_SCHEMAS[2] and WIRE_SELECTOR not in self.selections:
            raise ValueError('artifact-page v3 companion requires the base pinned wire')
        if WIRE_SELECTOR in self.selections:
            existing = authority._read(authority._path(self.selections[WIRE_SELECTOR]),
                                       authority.MAX_MANIFEST_BYTES)
            wire_record = authority._decode(existing.raw)
            expected = captures['wire'][3]
            if (type(wire_record) is not dict
                    or any(wire_record.get(k) != expected[k]
                           for k in ('schema', 'source_sha256', 'image_sha256', 'compiler_sha256'))):
                raise ValueError('artifact-page and Worker wire identities differ')
            self.snapshots.append((existing, authority.MAX_MANIFEST_BYTES))
        else:
            self.selections[WIRE_SELECTOR] = str(captures['wire'][0].path)
        loaded = {}
        for name, (manifest, source, image, item, factory) in captures.items():
            key = (str(manifest.path.resolve(strict=True)), str(source.path.resolve(strict=True)),
                   item['schema'], factory)
            if key in self.images:
                mapped = self.images[key]
                if type(mapped) is not factory or mapped.image_sha256 != item['image_sha256']:
                    raise ValueError('artifact-page shared image binding differs')
            else:
                mapped = factory(image.raw, item['image_sha256'])
                mapped.admitted_source_sha256 = item['source_sha256']
                self.images[key] = mapped
            loaded[name] = mapped
        self.selections[PAGE_SELECTOR] = str(page.path)
        key = (str(page.path.resolve(strict=True)), page_api.SCHEMA, page_api.NativeArtifactPage)
        if key in self.bundles:
            raise ValueError('duplicate artifact-page bundle binding')
        self.bundles[key] = page_api.NativeArtifactPage(loaded['policy'], loaded['wire'])
        self.check_files()

    def check_owner(self):
        if self.owner != (authority.os.getpid(), authority.threading.get_ident()):
            raise ValueError('artifact-page Worker binding belongs to its original process and thread')

    def check_scheduling_companion(self):
        # The v3 scheduler invokes this during construction and terminal checks.
        # Read only this layer's captured files; recursing into its base would
        # re-enter the scheduler that is checking this exact Page companion.
        self.check_owner()
        if getattr(self, '_page_capture_complete', False) is not True:
            raise ValueError('artifact-page companion was not completely captured')
        page = self._page_manifest_snapshot
        if not any(original is page and limit == 8192 for original, limit in self.snapshots):
            raise ValueError('artifact-page companion lacks its actual manifest capture')
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError('artifact-page scheduling companion inputs changed')
        return {PAGE_SELECTOR: str(page.path)}

    def check_files(self):
        self.check_owner()
        base = getattr(self, 'base_binding', None)
        if base is not None:
            base.check_files()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError('artifact-page Worker inputs changed; observe the original operation')

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('artifact-page Worker selection changed; observe the original operation')
        self.check_files()


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
