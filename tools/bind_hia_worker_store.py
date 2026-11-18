"""Pin a sealed HIA Store release in the existing worker helper configuration."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta import hia_native_helpers as authority
from hepta.hia_agent_store_native import capture_release_image, release_identity
from hepta.hia_worker_store_profile import (
    DIRECT_CALL_SCHEMA, DIRECT_REPEAT_SCHEMA, EDIT_QUERY_SCHEMA, IMPORT_SCHEMA,
    OWNED_REFERENCE_SCHEMA, REFERENCE_SCHEMA, SCHEMA, profile_images,
)
from tools.build_hia_worker_report import custody_path


def bind_worker_store(output, base_bundle, release, *, edit_query=False, candidate_import=False,
                      portable=False, reference_executable=None, owned_reference_executable=None,
                      direct_call_executable=None, direct_call_protocol=1):
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
    if owned_reference_executable is not None and reference_executable is None:
        raise ValueError('standalone owned reference requires the standalone scalar reference')
    if direct_call_protocol not in (1, 2) or direct_call_protocol == 2 and direct_call_executable is None:
        raise ValueError('direct call protocol requires its executable')
    direct_schema = DIRECT_REPEAT_SCHEMA if direct_call_protocol == 2 else DIRECT_CALL_SCHEMA
    if direct_call_executable is not None and owned_reference_executable is None:
        raise ValueError('standalone direct calls require both reference executables')
    for name, executable, profile in (('reference', reference_executable, REFERENCE_SCHEMA),
                                      ('owned_reference', owned_reference_executable, OWNED_REFERENCE_SCHEMA),
                                      ('direct_call', direct_call_executable, direct_schema)):
        if executable is None:
            continue
        if not candidate_import:
            raise ValueError('standalone reference requires the full native Store profile')
        from hepta.hia_scalar_reference_native import MAX_IMAGE_BYTES
        path = authority._path(str(Path(executable).absolute()))
        digest = sha256(authority._read(path, MAX_IMAGE_BYTES).raw).hexdigest()
        captured = capture_release_image(path.parent, path.name, MAX_IMAGE_BYTES, digest)
        reference_fields[name + '_path'] = custody_path(output, captured.path, portable=portable)
        reference_fields[name + '_sha256'] = digest
        schema = profile
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
    parser.add_argument('--owned-reference-executable', type=Path)
    parser.add_argument('--direct-call-executable', type=Path)
    parser.add_argument('--direct-call-protocol', type=int, choices=(1, 2), default=1)
    parser.add_argument('--portable', action='store_true',
                        help='require relative base/installation paths within the output directory')
    args = parser.parse_args()
    pin = bind_worker_store(args.output, args.base_bundle, args.release,
                            edit_query=args.edit_query, candidate_import=args.candidate_import,
                            portable=args.portable, reference_executable=args.reference_executable,
                            owned_reference_executable=args.owned_reference_executable,
                            direct_call_executable=args.direct_call_executable,
                            direct_call_protocol=args.direct_call_protocol)
    print(json.dumps({'manifest': str(args.output.absolute()), 'sha256': pin}))


if __name__ == '__main__':
    main()
