"""Bind an installed HIA Store to the existing worker helper pin."""

from hashlib import sha256
from pathlib import Path

from . import hia_native_helpers as authority
from .hia_agent_store_native import RELEASE_IMAGES, capture_release_image, release_identity

SCHEMA = 'hepta.hia.native-helpers.v4'
EDIT_QUERY_SCHEMA = 'hepta.hia.native-helpers.v5'
IMPORT_SCHEMA = 'hepta.hia.native-helpers.v6'
REFERENCE_SCHEMA = 'hepta.hia.native-helpers.v7'
SCHEMAS = (SCHEMA, EDIT_QUERY_SCHEMA, IMPORT_SCHEMA, REFERENCE_SCHEMA)
PIN_FIELDS = ('store_sha256', 'artifact_sha256', 'capture_sha256')


def profile_images(schema):
    if schema not in SCHEMAS:
        raise ValueError('unsupported pinned native Store profile')
    result = dict(zip(PIN_FIELDS, RELEASE_IMAGES, strict=True))
    if schema != SCHEMA:
        from .hia_agent_edit_query_native import EXECUTABLE
        result['edit_query_sha256'] = EXECUTABLE
    if schema in (IMPORT_SCHEMA, REFERENCE_SCHEMA):
        from .hia_agent_candidate_native import IMPORT_EXECUTABLES
        result.update(IMPORT_EXECUTABLES)
    return result


class NativeWorkerStoreBinding:
    def __init__(self, snapshot, expected_sha256, record):
        schema = record.get('schema')
        images = profile_images(schema)
        reference_fields = {'reference_path', 'reference_sha256'} if schema == REFERENCE_SCHEMA else set()
        if (set(record) != {'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                            'release_path', *images, *reference_fields}
                or record['target'] != authority.TARGET
                or record['abi'] != authority.ABI
                or not all(authority._digest(record[key]) for key in (*images, 'base_bundle_sha256'))):
            raise ValueError('unsupported pinned native Store profile')
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('native Store profile identity mismatch')
        release = authority._path(record['release_path'], snapshot.path.parent)
        self.directory_identity = release_identity(release)
        pins = tuple(record[key] for key in PIN_FIELDS)
        self.native_store = (release, *pins)
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        captures = {}
        for field, (name, limit) in images.items():
            captured = capture_release_image(release, name, limit, record[field])
            self.snapshots.append((captured, limit))
            captures[field] = captured
        self.native_edit_query = None
        if 'edit_query_sha256' in captures:
            from .hia_agent_edit_query_native import NativeAgentEditQuery
            self.native_edit_query = NativeAgentEditQuery(captures['edit_query_sha256'])
        base = authority._read(authority._path(record['base_bundle'], snapshot.path.parent),
                               authority.MAX_BUNDLE_BYTES)
        if sha256(base.raw).hexdigest() != record['base_bundle_sha256']:
            raise ValueError('native Store base helper identity mismatch')
        self.base_binding = authority._base_binding(
            base, record['base_bundle_sha256'], authority._decode(base.raw))
        self.selections = self.base_binding.selections
        self.images = self.base_binding.images
        self.bundles = getattr(self.base_binding, 'bundles', {})
        self.native_candidate_import = None
        if schema in (IMPORT_SCHEMA, REFERENCE_SCHEMA):
            from .hia_agent_candidate_native import NativeAgentCandidateImport
            from .hia_agent_inspection_native import SELECTOR
            if SELECTOR not in self.selections:
                raise ValueError('native candidate import requires pinned Agent inspection')
            self.native_candidate_import = NativeAgentCandidateImport(
                captures['assembly_import_sha256'], captures['json_admission_sha256'], self.selections[SELECTOR])
        self.native_reference_executable = None
        if schema == REFERENCE_SCHEMA:
            from .hia_scalar_reference_native import MAX_IMAGE_BYTES, SELECTOR, NativeScalarReference
            if SELECTOR not in self.selections or not authority._digest(record['reference_sha256']):
                raise ValueError('standalone reference requires its pinned scalar image and executable')
            selected = authority._path(record['reference_path'], snapshot.path.parent)
            reference = capture_release_image(
                selected.parent, selected.name, MAX_IMAGE_BYTES, record['reference_sha256'])
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items()
                      if key[0] == manifest and key[3] is NativeScalarReference]
            if len(owners) != 1 or not owners[0].matches_standalone(reference.raw):
                raise ValueError('standalone reference omits its exact pinned HIA image')
            self.snapshots.append((reference, MAX_IMAGE_BYTES))
            self.native_reference_executable = (reference.raw, record['reference_sha256'])
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
