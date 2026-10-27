#!/usr/bin/env python3
"""Export the isolated local-model client and its exact service/model binding."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

try:
    from .local_model_common import (canonical, digest, file_digest, model_identity,
                                    validate_config, validate_lock, validate_service_locks)
    from .local_model_service import service_identity
except ImportError:
    from local_model_common import (canonical, digest, file_digest, model_identity,
                                   validate_config, validate_lock, validate_service_locks)
    from local_model_service import service_identity

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
CLIENT_FILES = ('local_model_adapter.py', 'local_model_common.py', 'openai_chat.py')


def export_bundle(service, output, metadata_out, *, port, python='/usr/bin/python3'):
    if not isinstance(service, dict) or service.get('schema') != 'hepta.local_service.v1':
        raise ValueError('E_LOCAL_EXPORT: actual service identity record required')
    locks = service.get('locks')
    if not isinstance(locks, list) or not 1 <= len(locks) <= 16:
        raise ValueError('E_LOCAL_EXPORT: complete model locks required')
    validate_service_locks(locks)
    models = [model_identity(lock) for lock in locks]
    upstream = [(v['repository'], v['repository_revision']) for v in locks]
    weights = [tuple(sorted((f['sha256'], f['bytes']) for f in v['files'] if f['path'].endswith('.safetensors')))
               for v in locks]
    if len(set(upstream)) != len(upstream) or len(set(weights)) != len(weights):
        raise ValueError('E_LOCAL_EXPORT: generation settings do not turn identical weights into distinct models')
    if (service.get('models') != models or service_identity(locks, service.get('runtime')) != service.get('service_sha256')):
        raise ValueError('E_LOCAL_EXPORT: service identity differs from its locks/runtime')
    config = validate_config({'schema': 'hepta.local_model_adapter.v1', 'host': '127.0.0.1',
                              'port': port, 'service_sha256': service['service_sha256'], 'models': models})
    output, metadata_out = Path(output).absolute(), Path(metadata_out).absolute()
    executable = Path(python)
    if (not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK)
            or not any(executable.resolve().is_relative_to(Path(base).resolve()) for base in ('/usr', '/bin'))):
        raise ValueError('E_LOCAL_EXPORT: select Python in the existing /usr or /bin namespace mounts')
    if output.exists() or output.is_symlink() or metadata_out.exists() or metadata_out.is_symlink():
        raise ValueError('E_LOCAL_EXPORT: output paths must be new')
    resolved = output.resolve()
    if resolved.is_relative_to(REPOSITORY) or REPOSITORY.is_relative_to(resolved):
        raise ValueError('E_LOCAL_EXPORT: bundle must be outside the source repository')
    if metadata_out.resolve().is_relative_to(resolved) or resolved.is_relative_to(metadata_out.resolve()):
        raise ValueError('E_LOCAL_EXPORT: configuration must be outside the bundle')
    command = [str(executable), '{adapter}/local_model_adapter.py']
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hepta-local-export-', dir=output.parent) as temp:
        stage = Path(temp) / 'bundle'
        stage.mkdir()
        for name in CLIENT_FILES:
            shutil.copyfile(HERE / name, stage / name)
        (stage / 'local-config.json').write_bytes(canonical(config) + b'\n')
        (stage / 'command.json').write_bytes(canonical(command) + b'\n')
        manifest = {'schema': 'hepta.local_adapter_bundle.v1', 'models': models,
                    'service_sha256': service['service_sha256'],
                    'files': {p.name: file_digest(p) for p in sorted(stage.iterdir())},
                    'actual_ai_model_runs': 0, 'qualification': 'not_performed',
                    'client_standard_library_only': True, 'model_assets_in_capsule': False,
                    'receipt_authenticity': 'local_inference_service_attested_not_billing',
                    'requires_strict_namespace': True, 'requires_coordinator_capability': 'abort_frame'}
        (stage / 'manifest.json').write_bytes(canonical(manifest) + b'\n')
        bundle_sha = digest(canonical([(p.relative_to(stage).as_posix(), file_digest(p))
                                      for p in sorted(stage.iterdir())]))
        metadata = [{'model': model, 'bundle_sha256': bundle_sha, 'command': command,
                     'executable_sha256': file_digest(executable.resolve()),
                     'passed_environment_names': [], 'network_requested': True}
                    for model in models]
        os.rename(stage, output)
        try:
            with metadata_out.open('xb') as stream:
                stream.write(canonical(metadata) + b'\n')
        except OSError:
            shutil.rmtree(output)
            raise
    return {'schema': 'hepta.local_adapter_export.v1', 'bundle': str(output),
            'adapter_configs': str(metadata_out), 'bundle_sha256': bundle_sha,
            'models': models, 'command': command, 'actual_ai_model_runs': 0,
            'complete_study_model_requirement_met': len(models) >= 2}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', required=True, help='Service evidence directory/service.json')
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--output', required=True)
    parser.add_argument('--metadata-out', required=True)
    parser.add_argument('--python', default='/usr/bin/python3')
    args = parser.parse_args(argv)
    path = Path(args.service)
    if path.is_symlink() or path.stat().st_size > 1024**2:
        raise ValueError('E_LOCAL_EXPORT: bounded regular service record required')
    result = export_bundle(json.loads(path.read_bytes()), args.output, args.metadata_out,
                            port=args.port, python=args.python)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
