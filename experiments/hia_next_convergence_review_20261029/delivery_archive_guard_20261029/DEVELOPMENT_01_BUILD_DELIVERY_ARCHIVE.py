"""Retained-evidence packer; no network or upload capability.

All candidate files pass guards before ZIP creation. Opaque nested archives and
source bundles still require their separate content review. No evidence is
deleted, rewritten, redacted, or silently excluded after a guard rejection.
"""
from pathlib import Path, PurePosixPath
from hashlib import sha256
from datetime import datetime, timezone
import html
import json
import os
import re
import stat
import sys
from urllib.parse import parse_qsl, unquote, urlsplit
import zipfile

BEFORE_V8 = 'completed-work-checkpoint-before-v8'
LATER_AGENT_PREFIXES = tuple('hepta-next-agent-' + v + '-' for v in ('v7', 'v8', 'v9', 'v10'))
PROTECTED_MODEL_ROOT = Path('/tmp/hepta-next-model-qwen3-4b-20261029')
MAX_MEMBER_BYTES = 128 * 1024 * 1024
KNOWN_BINARY_SUFFIXES = {'.zip', '.gz', '.bundle', '.o', '.bc', '.profraw', '.profdata'}
KNOWN_TEXT_SUFFIXES = {'.json', '.log', '.md', '.txt', '.py', '.sh', '.stdout', '.stderr', '.sse',
                       '.hepta', '.ll', '.smt2', '.c', '.cc', '.cpp', '.h', '.hpp', '.rs', '.ts',
                       '.go', '.patch', '.yaml', '.yml'}
SIGNED_QUERY_KEYS = {'signature', 'sig', 'token', 'access_token', 'authorization', 'policy', 'key-pair-id'}
URL = re.compile(r'https?://[^\s<>"\x27`]+', re.IGNORECASE)
REQUEST_NAME = re.compile(r'(?:^|[_.-])requests?(?:[_.-]|$)', re.IGNORECASE)
DOWNLOAD_NAME = re.compile(r'download|acqui(?:re|sition)|fetch|gguf|qwen|model', re.IGNORECASE)
MODEL_WEIGHT_NAME = re.compile(r'\.(?:gguf|ggml|safetensors)(?:[._-].*)?$', re.IGNORECASE)


def refuse(path, category):
    # Only the evidence path and category are ever disclosed, never a value.
    raise ValueError('Evidence guard rejected [' + category + ']: ' + str(path))


def no_symlink_components(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            refuse(path, 'missing-retained-path')
        if stat.S_ISLNK(mode):
            refuse(path, 'symlink-path-component')
    if '.git' in path.parts:
        refuse(path, 'git-metadata-path')
    if path == PROTECTED_MODEL_ROOT or PROTECTED_MODEL_ROOT in path.parents:
        refuse(path, 'protected-model-directory')
    return path


def directory_guard(path):
    path = no_symlink_components(path)
    if not stat.S_ISDIR(path.lstat().st_mode):
        refuse(path, 'not-a-directory')
    if os.path.lexists(path / '.git'):
        refuse(path, 'live-checkout-root')
    return path


def evidence_files(directory):
    """Common route for fixed, globbed, and extra evidence directory entries."""
    directory = directory_guard(directory)
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        current = directory_guard(current)
        for name in sorted(dirnames):
            directory_guard(current / name)
        for name in sorted(filenames):
            path = no_symlink_components(current / name)
            if not stat.S_ISREG(path.lstat().st_mode):
                refuse(path, 'non-regular-file')
            yield path


def phase_allows_name(name, phase):
    return phase != BEFORE_V8 or not name.startswith(LATER_AGENT_PREFIXES)


def add_candidate(sources, path, archive_name):
    path = no_symlink_components(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        refuse(path, 'non-regular-file')
    if MODEL_WEIGHT_NAME.search(path.name):
        refuse(path, 'model-weight-filename')
    download_parent = any('download' in part.lower() or 'acquisition' in part.lower() for part in path.parts[:-1])
    if path.suffix.lower() == '.json' and REQUEST_NAME.search(path.name) and (DOWNLOAD_NAME.search(path.name) or download_parent):
        refuse(path, 'downloader-request-json-filename')
    member = PurePosixPath(archive_name)
    if not archive_name or member.is_absolute() or '..' in member.parts or '\\' in archive_name:
        refuse(path, 'unsafe-archive-member-name')
    if archive_name in sources and sources[archive_name] != path:
        refuse(path, 'duplicate-archive-member')
    sources[archive_name] = path


def dict_is_download_request(value, path):
    if not isinstance(value, dict):
        return False
    values = {str(key).lower(): item for key, item in value.items()}
    direct_url = any(isinstance(values.get(key), str) and URL.match(values[key])
                     for key in ('url', 'download_url', 'source_url', 'signed_url', 'presigned_url'))
    if not direct_url:
        return False
    # Public acquisition outcome receipts are retained; active download request
    # specifications have request names or transport/destination fields.
    return bool(REQUEST_NAME.search(path.name) or
                set(values) & {'headers', 'method', 'destination', 'output_file', 'save_as', 'request_headers', 'signed_url', 'presigned_url'})


def candidate_text_guard(path, data):
    path = Path(path)
    if path.suffix.lower() in KNOWN_BINARY_SUFFIXES or data.startswith(b'\x7fELF'):
        return False
    if b'\x00' in data and path.suffix.lower() not in KNOWN_TEXT_SUFFIXES:
        return False
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        if path.suffix.lower() in KNOWN_TEXT_SUFFIXES:
            refuse(path, 'unclassifiable-expected-text')
        return False
    strings = [text]
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        # Malformed failure evidence stays intact. Decode complete JSON string
        # literals so a normally escaped URL still receives the same guard.
        for match in re.finditer(r'"(?:[^"\\]|\\.)*"', text):
            try:
                strings.append(json.loads(match.group(0)))
            except (json.JSONDecodeError, RecursionError):
                continue
    else:
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if path.suffix.lower() == '.json' and dict_is_download_request(item, path):
                    refuse(path, 'downloader-request-json-structure')
                pending.extend(item.values())
                pending.extend(str(key) for key in item)
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, str):
                strings.append(item)
    for value in strings:
        if not isinstance(value, str):
            continue
        decoded = html.unescape(unquote(unquote(value)))
        for match in URL.finditer(decoded):
            try:
                parsed = urlsplit(match.group(0))
                keys = [key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
                credentials = parsed.username is not None or parsed.password is not None
            except ValueError:
                refuse(path, 'unclassifiable-url')
            if credentials:
                refuse(path, 'url-userinfo-credential')
            if any(key in SIGNED_QUERY_KEYS or key.startswith(('x-amz-', 'x-goog-')) for key in keys):
                refuse(path, 'signed-or-bearer-download-url')
    return True


def read_candidate(path):
    path = no_symlink_components(path)
    if MODEL_WEIGHT_NAME.search(path.name):
        refuse(path, 'model-weight-filename')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            refuse(path, 'non-regular-file')
        if before.st_size > MAX_MEMBER_BYTES:
            refuse(path, 'member-exceeds-preflight-budget')
        head = stream.read(4)
        if head == b'GGUF':
            refuse(path, 'GGUF-payload-magic')
        data = head + stream.read(MAX_MEMBER_BYTES + 1 - len(head))
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields) or len(data) != before.st_size:
        refuse(path, 'file-changed-during-read')
    identity = {key: getattr(before, key) for key in fields}
    identity.update(bytes=len(data), sha256=sha256(data).hexdigest(), mode=stat.S_IMODE(before.st_mode))
    return data, before, identity


def preflight(sources):
    reviewed = {}
    for name, path in sorted(sources.items()):
        data, _, identity = read_candidate(path)
        candidate_text_guard(path, data)
        reviewed[name] = identity
    return reviewed


def require_preflight_identity(path, identity, expected):
    if identity != expected:
        refuse(path, 'candidate-changed-after-preflight')


def main():
    root = Path('/workspace/scratch/220b9d034358/Hepta')
    tmp = Path('/tmp')
    output = Path(sys.argv[1])
    phase = sys.argv[2] if len(sys.argv) > 2 else 'completed-work-checkpoint-before-v8'
    assert not output.exists(), 'Refuse overwriting an earlier delivery archive'
    sources = {}

    def add(path, archive_name):
        add_candidate(sources, path, archive_name)

    directories = [
        'hepta-next-legacy-development', 'hepta-next-legacy-formal-01',
        'hepta-next-legacy-irpgo-probe-01', 'hepta-next-legacy-irpgo-development-01',
        'hepta-next-legacy-irpgo-formal-01', 'hepta-next-legacy-rust-shadow-formal-01',
        'hepta-next-safety-development-evidence', 'hepta-next-safety-scalar-formal-01',
        'hepta-next-safety-scalar-formal-02', 'hepta-next-ndu-activation-formal-01',
        'hepta-next-ndu-formal-build-01',
        'hepta-next-agent-v5-controls-01', 'hepta-next-agent-v5-controls-02',
        'hepta-next-agent-v5-qwen1_5b-01', 'hepta-next-agent-v5-qwen1_5b-03',
        'hepta-next-agent-v5-qwen1_5b-04', 'hepta-next-agent-v5-qwen7b-01',
        'hepta-next-agent-v5-into-typecheck-01',
        'hepta-next-agent-v6-profile-controls-01', 'hepta-next-agent-v6-qwen7b-01',
    ]
    patterns = ['hepta-next-agent-structured-controls-*']
    if phase != 'completed-work-checkpoint-before-v8':
        patterns += ['hepta-next-agent-v7-*', 'hepta-next-agent-v8-*',
                     'hepta-next-agent-v9-*', 'hepta-next-agent-v10-*']
    for pattern in patterns:
        for p in tmp.glob(pattern):
            if p.is_dir():
                if (p / '.git').exists():
                    raise ValueError('Use a source bundle instead of archiving a live checkout: ' + str(p))
                directories.append(p.name)
    extra = tmp / 'hepta-next-delivery-extra-paths.json'
    if extra.exists():
        for p in json.loads(extra.read_text()):
            path = Path(p)
            if path.is_dir():
                for child in evidence_files(path):
                    add(child, 'extra/' + path.name + '/' + str(child.relative_to(path)))
            else:
                add(path, 'extra/' + path.name)
    for name in sorted(set(directories)):
        path = tmp / name
        assert path.is_dir(), name
        for child in evidence_files(path):
            add(child, 'raw/' + name + '/' + str(child.relative_to(path)))
    for path in sorted(tmp.glob('hepta-next-*')):
        if not phase_allows_name(path.name, phase):
            continue
        if path.is_file() and (path.suffix in {'.log', '.json', '.bundle', '.hepta'}
                               or path.name.startswith('hepta-next-measured-sources-20261029.')
                               or path.name == 'hepta-next-ndu-prepared-evidence-20261029.tar.gz'):
            add(path, 'receipts/' + path.name)
    for name in ('env.sh', 'execution-prerequisites-before.json', 'llvm-restoration.json',
                 'rust-bootstrap.stdout', 'rust-bootstrap.stderr', 'llvm-bootstrap.stdout',
                 'llvm-bootstrap.stderr', 'cargo-build.stdout', 'cargo-build.stderr',
                 'cargo-fetch.stdout', 'cargo-fetch.stderr'):
        path = tmp / 'hepta-next-closure-20261028' / name
        if path.is_file():
            add(path, 'environment/' + name)
    for name in ('docs/HIA_NEXT_SIX_OUTCOMES_20261029.md',
                 'experiments/hia_next_closure/BLOCKERS_20261029.json',
                 'experiments/hia_next_closure/CI_OBSERVATIONS_20261029.json',
                 'experiments/hia_next_closure/SOURCE_PUBLICATIONS_20261029.json'):
        add(root / name, 'report/' + Path(name).name)
    add(Path(__file__), 'reproduction/' + Path(__file__).name)

    reviewed = preflight(sources)  # No ZIP exists until every candidate passes.

    manifest = {'schema': 'hepta.hia.next-closure-delivery.v1',
                'snapshot_phase': phase,
                'created_utc': datetime.now(timezone.utc).isoformat(),
                'preserve_original_experiment_source_identities': True,
                'all_blockers_closed': False,
                'no_model_weights_toolchains_or_cargo_cache_included': True,
                'candidate_preflight': {'all_candidates_before_zip_creation': True,
                    'known_weight_names_and_GGUF_magic_rejected': True,
                    'downloader_request_json_rejected': True,
                    'candidate_text_signed_bearer_URLs_rejected': True,
                    'all_directory_routes_reject_git_markers_and_symlinks': True,
                    'max_member_bytes': MAX_MEMBER_BYTES,
                    'opaque_nested_archives_and_bundles_require_separate_review': True},
                'files': []}
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, path in sorted(sources.items()):
            data, before, identity = read_candidate(path)
            require_preflight_identity(path, identity, reviewed[name])
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = before.st_mode << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            manifest['files'].append({'archive_path': name, 'original_path': str(path),
                                      'bytes': len(data), 'mode': stat.S_IMODE(before.st_mode),
                                      'sha256': sha256(data).hexdigest()})
        archive.writestr('MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
        archive.writestr('README.txt',
            'HIA next closure evidence, 2026-10-29\n\n'
            'Read report/HIA_NEXT_SIX_OUTCOMES_20261029.md first.\n'
            'Each experiment retains its own source identity, environment and denominator.\n'
            'Negative and failed attempts are retained. These results do not establish every\n'
            'language, migration, performance, Agent or NDU claim.\n'
            'MANIFEST.json binds every included file. The nested NDU archive includes its\n'
            'own raw member inventory. Source bundles require the recorded public prerequisite.\n')
    with zipfile.ZipFile(output) as archive:
        for row in manifest['files']:
            data = archive.read(row['archive_path'])
            assert len(data) == row['bytes'] and sha256(data).hexdigest() == row['sha256'], row['archive_path']
            assert stat.S_IMODE(archive.getinfo(row['archive_path']).external_attr >> 16) == row['mode'], row['archive_path']
    receipt = {'path': str(output), 'bytes': output.stat().st_size,
               'sha256': sha256(output.read_bytes()).hexdigest(),
               'verified_member_files': len(manifest['files']),
               'uncompressed_member_bytes': sum(x['bytes'] for x in manifest['files']),
               'created_utc': manifest['created_utc']}
    (tmp / 'hepta-next-final-delivery-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
