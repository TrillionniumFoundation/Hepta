#!/usr/bin/env python3
"""Export a standalone reviewed adapter plus frozen, credential-free metadata."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

try:
    from .openai_chat import ENDPOINT, AdapterError, canonical, parse_json, validate_models
except ImportError:  # Direct invocation from the checkout, without installation.
    from openai_chat import ENDPOINT, AdapterError, canonical, parse_json, validate_models


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bundle_digest(root):
    root = Path(root)
    entries = sorted(root.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in entries):
        raise ValueError('E_EXPORT_INPUT: symlinks and special files are not bundle inputs')
    files = [(p.relative_to(root).as_posix(), digest(p.read_bytes())) for p in entries if p.is_file()]
    return digest(canonical(files))


def export_bundle(models, output, metadata_out, *, python='/usr/bin/python3'):
    models = validate_models(models)
    output, metadata_out = Path(output).absolute(), Path(metadata_out).absolute()
    executable = Path(python)
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('E_EXPORT_PYTHON: select an installed absolute Python executable')
    # The shared namespace mounts /usr and /bin. Do not export a command that
    # relies on the evaluator privately mounting an ambient /opt interpreter.
    if not any(executable.resolve().is_relative_to(Path(base).resolve()) for base in ('/usr', '/bin')):
        raise ValueError('E_EXPORT_PYTHON: select Python beneath the namespace /usr or /bin mounts')
    if output.exists() or output.is_symlink() or metadata_out.exists() or metadata_out.is_symlink():
        raise ValueError('E_EXPORT_EXISTS: output paths must be new')
    resolved = output.resolve()
    if resolved.is_relative_to(REPOSITORY) or REPOSITORY.is_relative_to(resolved):
        raise ValueError('E_EXPORT_SCOPE: export the bundle outside the source repository')
    if metadata_out.resolve().is_relative_to(resolved) or resolved.is_relative_to(metadata_out.resolve()):
        raise ValueError('E_EXPORT_METADATA: frozen configuration belongs outside the bundle')
    command = [str(executable), '{adapter}/openai_chat.py']
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.hepta-adapter-export-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'bundle'
        stage.mkdir()
        shutil.copyfile(HERE / 'openai_chat.py', stage / 'openai_chat.py')
        shutil.copyfile(HERE / 'README.md', stage / 'README.md')
        (stage / 'models.json').write_bytes(canonical(models) + b'\n')
        (stage / 'command.json').write_bytes(canonical(command) + b'\n')
        manifest = {'schema': 'hepta.openai_adapter_bundle.v1', 'endpoint': ENDPOINT,
                    'files': {p.name: digest(p.read_bytes()) for p in sorted(stage.iterdir())},
                    'actual_ai_model_runs': 0, 'provider_qualification': 'not_performed',
                    'receipt_authenticity': 'adapter_attested_not_independently_verified',
                    'requires_coordinator_capability': 'abort_frame', 'standard_library_only': True}
        (stage / 'manifest.json').write_bytes(canonical(manifest) + b'\n')
        bundle_sha = bundle_digest(stage)
        metadata = [{'model': model, 'bundle_sha256': bundle_sha, 'command': command,
                     'executable_sha256': digest(executable.resolve().read_bytes()),
                     'passed_environment_names': ['OPENAI_API_KEY'], 'network_requested': True}
                    for model in models]
        # The digest includes every final bundle file. The per-model metadata
        # lives outside it, avoiding a self-referential bundle hash.
        os.rename(stage, output)
        try:
            with metadata_out.open('xb') as stream:
                stream.write(canonical(metadata) + b'\n')
        except OSError:
            shutil.rmtree(output)
            raise
    return {'schema': 'hepta.openai_adapter_export.v1', 'bundle': str(output),
            'adapter_configs': str(metadata_out), 'bundle_sha256': bundle_sha,
            'command': command, 'actual_ai_model_runs': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models', required=True, help='Operator-supplied array of at least two exact dated OpenAI revisions')
    parser.add_argument('--output', required=True, help='New standalone bundle directory outside the source repository')
    parser.add_argument('--metadata-out', required=True, help='New adapter-configs JSON file outside the bundle')
    parser.add_argument('--python', default='/usr/bin/python3', help='Installed interpreter inside the /usr or /bin namespace mounts')
    args = parser.parse_args(argv)
    try:
        path = Path(args.models)
        if path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError('E_EXPORT_MODELS: require a small regular JSON configuration file')
        result = export_bundle(parse_json(path.read_bytes()), args.output, args.metadata_out, python=args.python)
    except (AdapterError, ValueError, OSError):
        print(json.dumps({'status': 'rejected', 'error': 'E_EXPORT: invalid models, executable, or new output paths'}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
