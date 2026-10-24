"""Public immutable task metadata and source reconstruction."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TASK_IDS = ('compact_runs', 'rolling_sum', 'lower_bound', 'parse_decimal')
LANGUAGES = ('hepta', 'rust')
START = '/* AGENT_BODY_BEGIN */'
END = '/* AGENT_BODY_END */'


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def verify_manifest(root: Path = ROOT) -> dict:
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest.get('schema') != 'hepta.agent_tasks.v1':
        raise ValueError('E_TASK_MANIFEST: unknown schema')
    for name, expected in manifest['files'].items():
        path = root / name
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError('E_TASK_STALE: frozen content changed: ' + name)
    expected_id = digest(canonical({key: value for key, value in manifest.items() if key != 'taskset_sha256'}))
    if manifest['taskset_sha256'] != expected_id:
        raise ValueError('E_TASK_STALE: manifest identity mismatch')
    return manifest


def task_request(task: str, language: str) -> dict:
    if task not in TASK_IDS or language not in LANGUAGES:
        raise ValueError('E_TASK: unknown task or language')
    manifest = verify_manifest()
    directory = ROOT / 'tasks' / task
    source = (directory / ('starter.' + ('hepta' if language == 'hepta' else 'rs'))).read_text()
    return {
        'task_id': task, 'language': language, 'taskset_sha256': manifest['taskset_sha256'],
        'base_sha256': digest(source.encode()),
        'task_sha256': digest(canonical({'taskset': manifest['taskset_sha256'], 'task': task, 'language': language, 'source': digest(source.encode())})),
        'instructions': (directory / 'instructions.md').read_text(),
        'starter_source': source, 'public_tests': json.loads((directory / 'public.json').read_text()),
        'language_reference': (ROOT / (language + '_reference.md')).read_text(),
    }


def balanced_body(body: str) -> bool:
    """Require one outer block; understand comments and common Rust literals.

    Full syntax/type correctness remains the compiler's responsibility. This
    scanner prevents closing the edit region and appending declarations.
    """
    text = body.strip()
    if not text.startswith('{') or not text.endswith('}'):
        return False
    i, depth, n = 0, 0, len(text)
    while i < n:
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            i = n if end < 0 else end + 1
            continue
        if text.startswith('/*', i):
            level, i = 1, i + 2
            while i < n and level:
                if text.startswith('/*', i): level, i = level + 1, i + 2
                elif text.startswith('*/', i): level, i = level - 1, i + 2
                else: i += 1
            if level: return False
            continue
        # Raw Rust strings r"...", r#"..."#, including b/c prefixes.
        raw_start = i + 1 if text[i:i + 1] in ('b', 'c') and text[i + 1:i + 2] == 'r' else i
        if text[raw_start:raw_start + 1] == 'r':
            j = raw_start + 1
            while j < n and text[j] == '#': j += 1
            if j < n and text[j] == '"':
                endmark = '"' + '#' * (j - raw_start - 1)
                end = text.find(endmark, j + 1)
                if end < 0: return False
                i = end + len(endmark)
                continue
        if text[i] == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            if i >= n: return False
            i += 1
            continue
        if text[i] == "'":
            # Character literals; lifetimes such as 'a are not quoted strings.
            j = i + 1
            if j < n and text[j] == '\\':
                j += 2
                if text[i + 2:i + 3] == 'u' and text[j:j + 1] == '{':
                    end = text.find('}', j + 1)
                    if end < 0: return False
                    j = end + 1
            else: j += 1
            if j < n and text[j] == "'":
                i = j + 1
                continue
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth < 0 or depth == 0 and i != n - 1: return False
        i += 1
    return depth == 0


def materialize(request: dict, body: str) -> str:
    if not isinstance(body, str) or len(body.encode()) > 65536 or not balanced_body(body):
        raise ValueError('E_EDIT_SCOPE: response must contain exactly one bounded function body')
    source = request['starter_source']
    if source.count(START) != 1 or source.count(END) != 1:
        raise ValueError('E_TASK_MANIFEST: invalid edit markers')
    prefix, tail = source.split(START)
    _, suffix = tail.split(END)
    return prefix + START + '\n' + body.strip() + '\n' + END + suffix
