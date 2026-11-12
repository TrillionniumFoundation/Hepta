"""Create an explicit v3 custody pin; does not compile or activate a service."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path


def bind_scheduling_bundle(output, base_bundle, schedulers):
    from hepta import hia_native_helpers as authority
    from hepta.hia_worker_scheduling_bundle import SCHEMA, FAMILIES, NativeWorkerSchedulingBinding
    if (type(schedulers) is not dict or not 1 <= len(schedulers) <= len(FAMILIES)
            or any(type(k) is not str or k not in FAMILIES for k in schedulers)):
        raise ValueError('one to five fixed scheduling families required')
    base = authority._read(authority._path(str(Path(base_bundle).resolve(strict=True))), authority.MAX_BUNDLE_BYTES)
    entries = []
    for kind, path in schedulers.items():
        captured = authority._read(authority._path(str(Path(path).resolve(strict=True))), authority.MAX_MANIFEST_BYTES)
        entries.append({'kind': kind, 'manifest_path': str(captured.path),
                        'manifest_sha256': sha256(captured.raw).hexdigest()})
    package = Path(authority.__file__).parent
    runtime = {'hepta/' + p.name: sha256(authority._read(p, authority.MAX_SOURCE_BYTES).raw).hexdigest()
               for p in package.glob('*.py')}
    value = {'schema': SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
             'base_bundle': str(base.path), 'base_bundle_sha256': sha256(base.raw).hexdigest(),
             'runtime_sha256': runtime, 'schedulers': entries}
    target = Path(output)
    with target.open('xb') as stream:
        stream.write((json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
    target.chmod(0o600)
    captured = authority._read(authority._path(str(target.resolve(strict=True))), authority.MAX_BUNDLE_BYTES)
    pin = sha256(captured.raw).hexdigest()
    binding = NativeWorkerSchedulingBinding(captured, pin)
    binding.check_files()
    return target, pin


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-bundle', type=Path, required=True)
    parser.add_argument('--schedulers-json', type=Path, required=True,
                        help='object mapping fixed family names to explicit manifests')
    args = parser.parse_args()
    target, pin = bind_scheduling_bundle(args.output, args.base_bundle,
                                        json.loads(args.schedulers_json.read_bytes()))
    print(json.dumps({'manifest': str(target), 'sha256': pin, 'production_activated': False,
                      'matching_source_cold_qualification_claimed': False}))
