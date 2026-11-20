"""Explicit v4 custody for one v1 helper bundle and artifact executable.

The standalone ELF has its own private delivery ABI, never the helper ABI.
Every admission and terminal check keeps the complete current source inventory.
"""
from dataclasses import dataclass
from hashlib import sha256
from . import hia_native_helpers as authority
from .hia_artifact_delivery_protocol import public_executable

SCHEMA = 'hepta.hia.native-helpers.v4'
ABI = 'hia-worker-artifact-delivery-v1'
ARTIFACT_SCHEMA = 'hepta.hia.artifact-publication-build.v1'
SELECTOR = 'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST'


@dataclass(frozen=True)
class NativeArtifactExecutable:
    binding: object
    manifest_path: object
    public: bytes
    private: bytes

    def _check_complete_current_admission(self):
        from .artifact_publication_native import _current_admitted_code
        current = _current_admitted_code(self.manifest_path)
        if current != self.private or public_executable(current) != self.public:
            raise ValueError('artifact worker executable differs from captured public/private identities')

    def current_code(self):
        authority._check_scope_owner()
        if (authority._SCOPE_OWNER is None or authority._ACTIVE is not self.binding
                or self.binding.artifact is not self):
            raise ValueError('artifact executable belongs to its original pinned worker scope')
        # Includes original full current_sources/installed module inventory,
        # current manifest and image admission, every time; never a path cache.
        self.binding.check()
        return self.private


class NativeArtifactWorkerBinding:
    def __init__(self, snapshot, expected_sha256):
        self.owner = (authority.os.getpid(), authority.threading.get_ident())
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('native helper bundle identity mismatch')
        value = authority._decode(snapshot.raw)
        if (type(value) is not dict or set(value) != {
                'schema', 'target', 'abi', 'helpers_bundle', 'helpers_bundle_sha256',
                'artifact_manifest', 'artifact_manifest_sha256'}
                or value['schema'] != SCHEMA or value['target'] != authority.TARGET
                or value['abi'] != ABI
                or not authority._digest(value['helpers_bundle_sha256'])
                or not authority._digest(value['artifact_manifest_sha256'])):
            raise ValueError('unsupported artifact worker capsule schema, target or ABI')
        self.sha256 = expected_sha256
        base = authority._read(authority._path(value['helpers_bundle'], snapshot.path.parent),
                               authority.MAX_BUNDLE_BYTES)
        artifact = authority._read(authority._path(value['artifact_manifest'], snapshot.path.parent),
                                   authority.MAX_SOURCE_BYTES)
        if sha256(base.raw).hexdigest() != value['helpers_bundle_sha256']:
            raise ValueError('artifact worker v1 helper bundle identity mismatch')
        if sha256(artifact.raw).hexdigest() != value['artifact_manifest_sha256']:
            raise ValueError('artifact worker application manifest identity mismatch')
        base_value = authority._decode(base.raw)
        if type(base_value) is not dict or base_value.get('schema') != authority.SCHEMA:
            raise ValueError('artifact worker capsule requires an explicit v1 helper bundle')
        record = authority._decode(artifact.raw)
        if (type(record) is not dict or record.get('schema') != ARTIFACT_SCHEMA
                or record.get('executable_path') != 'hia-artifact'):
            raise ValueError('artifact worker manifest is not the source-bound application')
        image = authority._read(artifact.path.parent / 'hia-artifact', authority.MAX_IMAGE_BYTES)
        from .artifact_publication_native import _current_admitted_code
        private = _current_admitted_code(str(artifact.path))
        if public_executable(private) != image.raw:
            raise ValueError('artifact worker application changed during capture')
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES),
                          (base, authority.MAX_BUNDLE_BYTES),
                          (artifact, authority.MAX_SOURCE_BYTES),
                          (image, authority.MAX_IMAGE_BYTES)]
        self.artifact = NativeArtifactExecutable(self, str(artifact.path), image.raw, private)
        self.check_files()
        self.legacy = authority.NativeHelpersBinding(str(base.path), value['helpers_bundle_sha256'])
        self.images = dict(self.legacy.images)
        self.selections = dict(self.legacy.selections)
        self.selections[SELECTOR] = str(artifact.path)
        key = (str(artifact.path.resolve(strict=True)), ARTIFACT_SCHEMA, NativeArtifactExecutable)
        self.bundles = {key: self.artifact}
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
                raise ValueError('artifact worker inputs changed; observe the original operation')
        self.artifact._check_complete_current_admission()

    def check(self):
        self.check_owner()
        if authority._selectors() != self.selections:
            raise ValueError('native helper selection changed; observe the original operation')
        self.check_files()
