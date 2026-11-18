"""Pin a sealed HIA Store release in the existing worker helper configuration."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta import hia_native_helpers as authority
from hepta.hia_agent_store_native import RELEASE_IMAGES, capture_release_image, release_identity
from hepta.hia_worker_store_profile import PIN_FIELDS, SCHEMA


def bind_worker_store(output, base_bundle, release):
    base = authority._read(authority._path(str(Path(base_bundle).absolute())), authority.MAX_BUNDLE_BYTES)
    record = authority._decode(base.raw)
    if type(record) is not dict or record.get('schema') not in (
            authority.SCHEMA, 'hepta.hia.native-helpers.v2', 'hepta.hia.native-helpers.v3'):
        raise ValueError('native Store needs a v1, v2 or v3 base helper bundle')
    release = authority._path(str(Path(release).absolute()))
    directory = release_identity(release)
    pins = {}
    for field, (name, limit) in zip(PIN_FIELDS, RELEASE_IMAGES, strict=True):
        digest = sha256(authority._read(release / name, limit).raw).hexdigest()
        capture_release_image(release, name, limit, digest)
        pins[field] = digest
    if release_identity(release) != directory:
        raise ValueError('native Store release changed while binding')
    record = {'schema': SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
              'base_bundle': str(base.path), 'base_bundle_sha256': sha256(base.raw).hexdigest(),
              'release_path': str(release), **pins}
    raw = (json.dumps(record, indent=2, sort_keys=True) + '\n').encode()
    with Path(output).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-bundle', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    pin = bind_worker_store(args.output, args.base_bundle, args.release)
    print(json.dumps({'manifest': str(args.output.absolute()), 'sha256': pin}))


if __name__ == '__main__':
    main()
