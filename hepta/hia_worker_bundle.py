"""Operator-pinned v2 custody for the HIA worker policy and wire companion.

This is still a hosted custody bridge. It does not make SQLite, the runtime
process owner or the complete service native. Version 1's registered single-image
contracts and their guards remain unchanged.
"""
from __future__ import annotations

from hashlib import sha256

from . import hia_native_helpers as authority

SCHEMA = 'hepta.hia.native-helpers.v2'
REPORT_SELECTOR = 'HEPTA_HIA_WORKER_REPORT_MANIFEST'
WIRE_SELECTOR = 'HEPTA_HIA_JSON_WIRE_MANIFEST'
REQUEST_SELECTOR = 'HEPTA_HIA_WORKER_REQUEST_MANIFEST'


class NativeWorkerBundleBinding:
    """One explicit administrator pin closes all transitive executable inputs."""

    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('native helper bundle identity mismatch')
        value = authority._decode(snapshot.raw)
        if (type(value) is not dict or set(value) != {
                'schema', 'target', 'abi', 'helpers_bundle', 'helpers_bundle_sha256',
                'report_bundle', 'report_bundle_sha256'}
                or value['schema'] != SCHEMA or value['target'] != authority.TARGET
                or value['abi'] != authority.ABI
                or not authority._digest(value['helpers_bundle_sha256'])
                or not authority._digest(value['report_bundle_sha256'])):
            raise ValueError('unsupported native worker bundle schema, target or ABI')
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        base_path = authority._path(value['helpers_bundle'], snapshot.path.parent)
        report_path = authority._path(value['report_bundle'], snapshot.path.parent)
        base = authority._read(base_path, authority.MAX_BUNDLE_BYTES)
        report = authority._read(report_path, 8192)
        if sha256(base.raw).hexdigest() != value['helpers_bundle_sha256']:
            raise ValueError('native worker helper child bundle identity mismatch')
        if sha256(report.raw).hexdigest() != value['report_bundle_sha256']:
            raise ValueError('native worker report child bundle identity mismatch')
        base_value = authority._decode(base.raw)
        if (type(base_value) is not dict or base_value.get('schema') != authority.SCHEMA
                or type(base_value.get('helpers')) is not list
                or not any(type(item) is dict and item.get('selector') == REQUEST_SELECTOR
                           for item in base_value['helpers'])):
            raise ValueError('native worker v2 requires its pinned native request helper')

        from . import hia_worker_report_native as worker
        from .hia_json_preflight_native import NativeHiaJsonImage
        from .hia_json_wire_native import NativeJsonWire, SOURCE as wire_source, SCHEMA as wire_schema

        record = authority._decode(report.raw)
        if (type(record) is not dict or set(record) != {
                'schema', 'policy_manifest', 'policy_manifest_sha256',
                'wire_manifest', 'wire_manifest_sha256'} or record['schema'] != worker.SCHEMA):
            raise ValueError('invalid native worker report bundle')
        captures = {}
        for name, source_path, schema, factory in (
                ('policy', worker.SOURCE, worker.POLICY_SCHEMA, NativeHiaJsonImage),
                ('wire', wire_source, wire_schema, NativeJsonWire)):
            child_path = record[name + '_manifest']
            pin = record[name + '_manifest_sha256']
            if (type(child_path) is not str or not child_path
                    or authority.Path(child_path).is_absolute() or '..' in authority.Path(child_path).parts
                    or not authority._digest(pin)):
                raise ValueError('invalid native worker report child identity')
            manifest_path = authority._path(child_path, report.path.parent)
            manifest = authority._read(manifest_path, authority.MAX_MANIFEST_BYTES)
            if sha256(manifest.raw).hexdigest() != pin:
                raise ValueError('native worker report child manifest identity mismatch')
            image_record = authority._decode(manifest.raw)
            if (type(image_record) is not dict or set(image_record) != {
                    'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                    or image_record['schema'] != schema
                    or any(not authority._digest(image_record[key])
                           for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
                raise ValueError('native worker image does not match its selected contract')
            source = authority._read(source_path, authority.MAX_SOURCE_BYTES)
            image = authority._read(authority._path(image_record['image_path'], manifest.path.parent),
                                    authority.MAX_IMAGE_BYTES)
            if sha256(source.raw).hexdigest() != image_record['source_sha256']:
                raise ValueError('native worker source identity mismatch')
            if sha256(image.raw).hexdigest() != image_record['image_sha256']:
                raise ValueError('native worker executable identity mismatch')
            captures[name] = (manifest, source, image, image_record, factory)
            self.snapshots.extend(((manifest, authority.MAX_MANIFEST_BYTES),
                                   (source, authority.MAX_SOURCE_BYTES), (image, authority.MAX_IMAGE_BYTES)))
        self.snapshots.extend(((base, authority.MAX_BUNDLE_BYTES), (report, 8192)))
        # Both companion manifests, sources and images are checked before any
        # new report executable mapping. Do not route through a second loader.
        self.check_files()
        self.legacy = authority.NativeHelpersBinding(str(base.path), value['helpers_bundle_sha256'])
        self.selections = dict(self.legacy.selections)
        self.images = dict(self.legacy.images)
        loaded = {}
        for name, (manifest, source, image, image_record, factory) in captures.items():
            loaded[name] = factory(image.raw, image_record['image_sha256'])
            key = (str(manifest.path.resolve(strict=True)), str(source.path.resolve(strict=True)),
                   image_record['schema'], factory)
            if key in self.images:
                raise ValueError('duplicate native worker image binding')
            self.images[key] = loaded[name]
        self.selections[REPORT_SELECTOR] = str(report.path)
        self.selections[WIRE_SELECTOR] = str(captures['wire'][0].path)
        bundle_key = (str(report.path.resolve(strict=True)), worker.SCHEMA, worker.NativeWorkerReport)
        self.bundles = {bundle_key: worker.NativeWorkerReport(loaded['policy'], loaded['wire'])}
        self.check_files()

    def check_owner(self):
        if self.owner != (authority.os.getpid(), authority.threading.get_ident()):
            raise ValueError('native helper binding belongs to its original process and thread')

    def check_files(self):
        self.check_owner()
        legacy = getattr(self, 'legacy', None)
        if legacy is not None:
            legacy.check_files()
        for original, limit in self.snapshots:
            if authority._read(original.path, limit) != original:
                raise ValueError('native helper inputs changed; observe the original operation')

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('native helper selection changed; observe the original operation')
        self.check_files()
