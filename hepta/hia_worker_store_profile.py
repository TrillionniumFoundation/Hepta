"""Bind an installed HIA Store to the existing worker helper pin."""

from hashlib import sha256

from . import hia_native_helpers as authority
from .hia_agent_store_native import RELEASE_IMAGES, capture_release_image, release_identity

SCHEMA = 'hepta.hia.native-helpers.v4'
EDIT_QUERY_SCHEMA = 'hepta.hia.native-helpers.v5'
PIN_FIELDS = ('store_sha256', 'artifact_sha256', 'capture_sha256')


class NativeWorkerStoreBinding:
    def __init__(self, snapshot, expected_sha256, record):
        schema = record.get('schema')
        pin_fields = PIN_FIELDS + (('edit_query_sha256',) if schema == EDIT_QUERY_SCHEMA else ())
        if (set(record) != {'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                            'release_path', *pin_fields}
                or schema not in (SCHEMA, EDIT_QUERY_SCHEMA) or record['target'] != authority.TARGET
                or record['abi'] != authority.ABI
                or not all(authority._digest(record[key]) for key in (*pin_fields, 'base_bundle_sha256'))):
            raise ValueError('unsupported pinned native Store profile')
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('native Store profile identity mismatch')
        release = authority._path(record['release_path'], snapshot.path.parent)
        self.directory_identity = release_identity(release)
        pins = tuple(record[key] for key in PIN_FIELDS)
        self.native_store = (release, *pins)
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        self.snapshots.extend((capture_release_image(release, name, limit, pin), limit)
                              for (name, limit), pin in zip(RELEASE_IMAGES, pins, strict=True))
        self.native_edit_query = None
        if schema == EDIT_QUERY_SCHEMA:
            from .hia_agent_edit_query_native import EXECUTABLE, NativeAgentEditQuery
            name, limit = EXECUTABLE
            query = capture_release_image(release, name, limit, record['edit_query_sha256'])
            self.snapshots.append((query, limit))
            self.native_edit_query = NativeAgentEditQuery(query)
        base = authority._read(authority._path(record['base_bundle'], snapshot.path.parent),
                               authority.MAX_BUNDLE_BYTES)
        if sha256(base.raw).hexdigest() != record['base_bundle_sha256']:
            raise ValueError('native Store base helper identity mismatch')
        self.base_binding = authority._base_binding(
            base, record['base_bundle_sha256'], authority._decode(base.raw))
        self.selections = self.base_binding.selections
        self.images = self.base_binding.images
        self.bundles = getattr(self.base_binding, 'bundles', {})
        self._check_release()

    def check_owner(self):
        self.base_binding.check_owner()

    def _check_release(self):
        if (release_identity(self.native_store[0]) != self.directory_identity
                or any(authority._read(captured.path, limit) != captured
                       for captured, limit in self.snapshots)):
            raise ValueError('native Store profile inputs changed; observe the original operation')

    def check(self):
        self.base_binding.check()
        self._check_release()
