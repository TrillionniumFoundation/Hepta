"""Frozen public bundles; private references are only loaded by qualification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
TASK_IDS = ('api_migration', 'owned_result', 'native_bridge', 'resource_cancel', 'defect_repair')
LANGUAGES = ('rust', 'hepta')
ARMS = {
    'rust_plain': {'language': 'rust', 'semantic_tools': False},
    'rust_semantic': {'language': 'rust', 'semantic_tools': True},
    'hepta_plain': {'language': 'hepta', 'semantic_tools': False},
    'hepta_protocol': {'language': 'hepta', 'semantic_tools': True},
}
MAX_SOURCE_BYTES = 256 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def relative(name):
    if (not isinstance(name, str) or not name or '\\' in name or '\0' in name
            or PurePosixPath(name).is_absolute() or any(p in {'', '.', '..'} for p in name.split('/'))):
        raise ValueError('E_PATH: require a normalized relative POSIX path')
    return name


def snapshot_id(files):
    return digest(canonical({name: digest(source.encode()) for name, source in sorted(files.items())}))


def verify_manifest(root=ROOT):
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('schema') != 'hepta.crossfile_tasks.v1':
        raise ValueError('E_TASK_MANIFEST: unknown schema')
    if manifest.get('tasks') != list(TASK_IDS) or manifest.get('languages') != list(LANGUAGES):
        raise ValueError('E_TASK_MANIFEST: paired task matrix changed')
    for name, expected in manifest['files'].items():
        path = root / relative(name)
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError('E_TASK_STALE: frozen input changed: ' + name)
    identity = digest(canonical({k: v for k, v in manifest.items() if k != 'taskset_sha256'}))
    if identity != manifest.get('taskset_sha256'):
        raise ValueError('E_TASK_STALE: manifest identity changed')
    return manifest


def _bundle(manifest, prefix):
    # Read only files explicitly committed to the taskset, never a recursive
    # candidate-controlled directory or ambient checkout inputs.
    files = {name[len(prefix):]: (ROOT / name).read_text()
             for name in manifest['files'] if name.startswith(prefix)}
    if not files:
        raise ValueError('E_TASK_MANIFEST: missing source bundle')
    return files


def task_request(task, language):
    if task not in TASK_IDS or language not in LANGUAGES:
        raise ValueError('E_TASK: unknown task or language')
    manifest = verify_manifest()
    directory = ROOT / 'tasks' / task
    files = _bundle(manifest, f'tasks/{task}/{language}/')
    extension = '.rs' if language == 'rust' else '.hepta'
    editable = sorted(name for name in files if name.endswith(extension) and name != 'main' + extension)
    base = snapshot_id(files)
    return {'task_id': task, 'language': language, 'files': files, 'editable': editable,
            'entry': 'main' + extension, 'base_sha256': base,
            'taskset_sha256': manifest['taskset_sha256'],
            'task_sha256': digest(canonical({'taskset': manifest['taskset_sha256'], 'task': task,
                                           'language': language, 'base': base})),
            'instructions': (directory / 'instructions.md').read_text(),
            'public_tests': json.loads((directory / 'public.json').read_text()),
            'language_reference': (ROOT / (language + '_reference.md')).read_text()}


def trusted_reference(task, language):
    manifest = verify_manifest()
    return _bundle(manifest, f'_private/references/{task}/{language}/')


def validate_files(request, files):
    if not isinstance(files, dict) or set(files) != set(request['files']):
        raise ValueError('E_EDIT_SCOPE: preserve the exact frozen file set')
    if any(not isinstance(v, str) for v in files.values()):
        raise ValueError('E_EDIT_SCOPE: file contents must be UTF-8 source strings')
    if sum(len(s.encode()) for s in files.values()) > MAX_SOURCE_BYTES:
        raise ValueError('E_EDIT_SCOPE: candidate exceeds 256 KiB')
    for name in files:
        relative(name)
        if name not in request['editable'] and files[name] != request['files'][name]:
            raise ValueError('E_EDIT_SCOPE: frozen input changed: ' + name)
    return dict(files)


def apply_files(request, current, replacements):
    if (not isinstance(replacements, dict) or not replacements
            or any(name not in request['editable'] for name in replacements)):
        raise ValueError('E_EDIT_SCOPE: replace one or more editable source files')
    return validate_files(request, {**current, **replacements})
