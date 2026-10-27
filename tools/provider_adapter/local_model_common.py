"""Strict identities for an optional local, open-weight inference provider.

This module does not import a model runtime, contact a network, or infer a model
identity from a moving alias. Its hashes bind supplied files, not their origin.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SCHEMA = 'hepta.local_model_lock.v1'
CONFIG_SCHEMA = 'hepta.local_model_adapter.v1'
PROVIDER = 'local-transformers'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('E_LOCAL_INPUT: a regular non-symlink file is required')
    return path


def validate_lock(lock):
    fields = {'schema', 'repository', 'repository_revision', 'files', 'generation', 'lock_sha256'}
    if not isinstance(lock, dict) or set(lock) != fields or lock['schema'] != SCHEMA:
        raise ValueError('E_LOCAL_LOCK: unknown or incomplete lock schema')
    if (not isinstance(lock['repository'], str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', lock['repository'])
            or not isinstance(lock['repository_revision'], str)
            or not re.fullmatch('[0-9a-f]{40}', lock['repository_revision'])):
        raise ValueError('E_LOCAL_REVISION: exact repository and immutable commit required')
    files = lock['files']
    if not isinstance(files, list) or not 3 <= len(files) <= 128:
        raise ValueError('E_LOCAL_FILES: bounded complete model/tokenizer inventory required')
    paths = []
    for item in files:
        if (not isinstance(item, dict) or set(item) != {'path', 'bytes', 'sha256'}
                or not isinstance(item['path'], str) or not item['path']
                or type(item['bytes']) is not int or not 0 <= item['bytes'] <= 16 * 1024**3
                or not sha(item['sha256'])):
            raise ValueError('E_LOCAL_FILES: invalid asset identity')
        path = PurePosixPath(item['path'])
        if (path.is_absolute() or '..' in path.parts or '\\' in item['path']
                or path.as_posix() != item['path']
                or path.suffix not in {'.json', '.safetensors', '.model', '.txt', '.md'}):
            raise ValueError('E_LOCAL_FILES: model assets must be safe relative data paths')
        paths.append(item['path'])
    if paths != sorted(set(paths)) or not {'config.json', 'tokenizer_config.json'} <= set(paths):
        raise ValueError('E_LOCAL_FILES: sorted unique assets and configuration required')
    if not any(p.endswith('.safetensors') for p in paths):
        raise ValueError('E_LOCAL_FILES: only safetensors weights are admitted')
    if not any(p in paths for p in ('tokenizer.json', 'tokenizer.model', 'vocab.json')):
        raise ValueError('E_LOCAL_FILES: tokenizer asset required')
    generation = lock['generation']
    generation_fields = {'device', 'dtype', 'do_sample', 'max_new_tokens', 'max_input_tokens', 'threads'}
    if (not isinstance(generation, dict)
            or set(generation) not in (generation_fields, generation_fields | {'prompt_format'})
            or generation['device'] != 'cpu' or generation['dtype'] not in {'float32', 'bfloat16'}
            or generation['do_sample'] is not False
            or generation.get('prompt_format', 'tokenizer_chat_template') not in {'tokenizer_chat_template', 'chatml_v1'}
            or any(type(generation[k]) is not int for k in ('max_new_tokens', 'max_input_tokens', 'threads'))
            or not 1 <= generation['max_new_tokens'] <= 8192
            or not 1 <= generation['max_input_tokens'] <= 65536
            or not 1 <= generation['threads'] <= 16):
        raise ValueError('E_LOCAL_GENERATION: explicit bounded CPU greedy generation required')
    if (not sha(lock['lock_sha256'])
            or digest(canonical({k: v for k, v in lock.items() if k != 'lock_sha256'})) != lock['lock_sha256']):
        raise ValueError('E_LOCAL_LOCK: content identity mismatch')
    return lock


def model_identity(lock):
    validate_lock(lock)
    return {'provider': PROVIDER, 'name': lock['repository'], 'revision': lock['lock_sha256']}


def validate_service_locks(locks):
    """Torch intraop threads are process-global, so one service needs one value."""
    if not isinstance(locks, list) or not 1 <= len(locks) <= 16:
        raise ValueError('E_LOCAL_CONFIG: bounded model locks required')
    for lock in locks:
        validate_lock(lock)
    if len({lock['lock_sha256'] for lock in locks}) != len(locks):
        raise ValueError('E_LOCAL_CONFIG: duplicate model lock')
    if len({lock['generation']['threads'] for lock in locks}) != 1:
        raise ValueError('E_LOCAL_THREADS: one process cannot promise different per-model intraop thread counts')
    return locks


def verify_assets(lock, directory):
    validate_lock(lock)
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('E_LOCAL_FILES: regular model directory required')
    expected = {item['path']: item for item in lock['files']}
    actual = {}
    for path in directory.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('E_LOCAL_FILES: symlink or special model input refused')
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            actual[relative] = {'path': relative, 'bytes': path.stat().st_size, 'sha256': file_digest(path)}
    if actual != expected:
        raise ValueError('E_LOCAL_FILES: model files differ from the frozen complete inventory')
    return True


def freeze_model(directory, repository, revision, *, max_new_tokens=1024,
                 max_input_tokens=16384, threads=2, dtype='float32', prompt_format='tokenizer_chat_template'):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('E_LOCAL_FILES: regular model directory required')
    entries = sorted(directory.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in entries):
        raise ValueError('E_LOCAL_FILES: symlink or special model input refused')
    value = {'schema': SCHEMA, 'repository': repository, 'repository_revision': revision,
             'files': [{'path': p.relative_to(directory).as_posix(), 'bytes': p.stat().st_size,
                        'sha256': file_digest(p)} for p in entries if p.is_file()],
             'generation': {'device': 'cpu', 'dtype': dtype, 'do_sample': False,
                            'max_new_tokens': max_new_tokens, 'max_input_tokens': max_input_tokens,
                            'threads': threads, 'prompt_format': prompt_format}}
    value['lock_sha256'] = digest(canonical(value))
    return validate_lock(value)


def validate_config(config):
    if (not isinstance(config, dict)
            or set(config) != {'schema', 'host', 'port', 'service_sha256', 'models'}
            or config['schema'] != CONFIG_SCHEMA or config['host'] != '127.0.0.1'
            or type(config['port']) is not int or not 1024 <= config['port'] <= 65535
            or not sha(config['service_sha256'])
            or not isinstance(config['models'], list) or not 1 <= len(config['models']) <= 16):
        raise ValueError('E_LOCAL_CONFIG: exact loopback service and model identities required')
    seen = set()
    for model in config['models']:
        if (not isinstance(model, dict) or set(model) != {'provider', 'name', 'revision'}
                or model['provider'] != PROVIDER or not sha(model['revision'])
                or not isinstance(model['name'], str)
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', model['name'])
                or model['revision'] in seen):
            raise ValueError('E_LOCAL_CONFIG: unique exact local model identity required')
        seen.add(model['revision'])
    return config
