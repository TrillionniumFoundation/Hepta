"""Pin a sealed HIA Store release in the existing worker helper configuration."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta import hia_native_helpers as authority
from hepta.hia_agent_store_native import capture_release_image, release_identity
from hepta.hia_worker_store_profile import (
    EDIT_QUERY_SCHEMA, IMPORT_SCHEMA, REFERENCE_SCHEMA, SCHEMA, profile_images,
)
from tools.build_hia_worker_report import custody_path


def bind_worker_store(output, base_bundle, release, *, edit_query=False, candidate_import=False,
                      portable=False, reference_executable=None):
    base = authority._read(authority._path(str(Path(base_bundle).absolute())), authority.MAX_BUNDLE_BYTES)
    record = authority._decode(base.raw)
    if type(record) is not dict or record.get('schema') not in (
            authority.SCHEMA, 'hepta.hia.native-helpers.v2', 'hepta.hia.native-helpers.v3'):
        raise ValueError('native Store needs a v1, v2 or v3 base helper bundle')
    release = authority._path(str(Path(release).absolute()))
    directory = release_identity(release)
    pins = {}
    schema = IMPORT_SCHEMA if candidate_import else EDIT_QUERY_SCHEMA if edit_query else SCHEMA
    reference_fields = {}
    if reference_executable is not None:
        if not candidate_import:
            raise ValueError('standalone reference requires the full native Store profile')
        from hepta.hia_scalar_reference_native import MAX_IMAGE_BYTES
        path = authority._path(str(Path(reference_executable).absolute()))
        digest = sha256(authority._read(path, MAX_IMAGE_BYTES).raw).hexdigest()
        captured = capture_release_image(path.parent, path.name, MAX_IMAGE_BYTES, digest)
        reference_fields = {
            'reference_path': custody_path(output, captured.path, portable=portable),
            'reference_sha256': digest,
        }
        schema = REFERENCE_SCHEMA
    for field, (name, limit) in profile_images(schema).items():
        digest = sha256(authority._read(release / name, limit).raw).hexdigest()
        capture_release_image(release, name, limit, digest)
        pins[field] = digest
    if release_identity(release) != directory:
        raise ValueError('native Store release changed while binding')
    record = {'schema': schema, 'target': authority.TARGET, 'abi': authority.ABI,
              'base_bundle': custody_path(output, base.path.resolve(strict=True) if portable else base.path,
                                          portable=portable),
              'base_bundle_sha256': sha256(base.raw).hexdigest(),
              'release_path': custody_path(output, release.resolve(strict=True) if portable else release,
                                           portable=portable), **pins, **reference_fields}
    raw = (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()
    with Path(output).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-bundle', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--edit-query', action='store_true',
                        help='select the sealed native Agent dependency query')
    parser.add_argument('--candidate-import', action='store_true',
                        help='select native Agent candidate admission and dependency query')
    parser.add_argument('--reference-executable', type=Path)
    parser.add_argument('--portable', action='store_true',
                        help='require relative base/installation paths within the output directory')
    args = parser.parse_args()
    pin = bind_worker_store(args.output, args.base_bundle, args.release,
                            edit_query=args.edit_query, candidate_import=args.candidate_import,
                            portable=args.portable, reference_executable=args.reference_executable)
    print(json.dumps({'manifest': str(args.output.absolute()), 'sha256': pin}))


if __name__ == '__main__':
    main()
