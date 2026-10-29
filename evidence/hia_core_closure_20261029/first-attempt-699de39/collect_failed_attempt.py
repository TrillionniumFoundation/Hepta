#!/usr/bin/env python3
"""Preserve only the requested first failed full8 run and its original review.

No source mutation, testing, native execution, or private transport reads occur.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

OUT = Path(__file__).resolve().parent
BASE = OUT.parent
SOURCE = '699de39a8e92e0f083df316ecc5333fb3ecf8571'
ROOTS = ('final-qualification-699de39', 'final-run-independent-review-699de39')
SINGLES = ('run_final_integrated_699de39.py', 'source-publication-699de39.json')
ARCHIVE = 'hepta_699de39_first_failed_full8_20261029.tar.gz'
LIMIT, PART = 12_000_000, 4 * 1024 * 1024
PATTERNS = {
    'github_fine_grained_token': rb'github_pat_[A-Za-z0-9_]{50,}',
    'github_classic_or_app_token': rb'gh[pousr]_[A-Za-z0-9]{30,}',
    'openai_secret_key': rb'sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{30,}',
    'aws_access_key': rb'(?:AKIA|ASIA)[A-Z0-9]{16}',
    'private_key_header': rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----',
    'slack_token': rb'xox[baprs]-[A-Za-z0-9-]{20,}',
    'google_api_key': rb'AIza[0-9A-Za-z_-]{35}',
    'gitlab_access_token': rb'glpat-[A-Za-z0-9_-]{20,}',
    'sendgrid_api_key': rb'SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',
    'signed_download_url': rb'https?://[^\s"<>]+(?:[?&](?:sig|X-Amz-Signature|Signature)=)[^\s"<>]+',
}


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity_bytes(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                git_blob_sha1=hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest())


def identity_stream(stream, size):
    sha = hashlib.sha256()
    blob = hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
    count = 0
    while block := stream.read(1024 * 1024):
        count += len(block); sha.update(block); blob.update(block)
    assert count == size, 'stream size changed'
    return dict(bytes=count, sha256=sha.hexdigest(), git_blob_sha1=blob.hexdigest())


def stable_file(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), 'only original regular files admitted'
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        assert (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
        result = identity_stream(stream, opened.st_size)
        after_open = os.fstat(stream.fileno())
    after = path.lstat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert key(before) == key(opened) == key(after_open) == key(after), 'original file changed while reading'
    return result


def input_paths():
    paths = []
    for name in ROOTS:
        root = BASE / name
        assert root.is_dir() and not root.is_symlink()
        paths.append(root)
        paths.extend(root.rglob('*'))
    paths.extend(BASE / name for name in SINGLES)
    names = [str(p.relative_to(BASE)) for p in paths]
    assert len(names) == len(set(names))
    return sorted(paths, key=lambda p: str(p.relative_to(BASE)))


def scan(data, label, findings):
    for name, pattern in PATTERNS.items():
        for match in re.finditer(pattern, data):
            findings.append(dict(path=label, pattern=name, offset=match.start(), length=len(match.group())))


def main():
    assert not (OUT / ARCHIVE).exists(), 'checkpoint already exists'
    run = json.loads((BASE / ROOTS[0] / 'process.json').read_text())
    qualification = json.loads((BASE / ROOTS[0] / 'run/qualification.json').read_text())
    review = json.loads((BASE / ROOTS[1] / 'summary.json').read_text())
    assert run['source_commit'] == SOURCE and type(run['returncode']) is int and run['returncode'] == 1
    assert run['source_unchanged'] is True and run['finished_utc']
    assert qualification['ok'] is False and qualification['status'] == 'integration_qualification_failed'
    assert qualification['source_unchanged'] is True and qualification['external_inputs_unchanged'] is True
    assert len(qualification['gates']) == 8 and sum(g['passed'] is True for g in qualification['gates']) == 6
    assert review['qualification_passed'] is False and review['audit_integrity_ok'] is True and review['audit_findings'] == []
    assert review['integrity_check_count'] == 75 and review['python_status_counts'] == {'ERROR': 1, 'ok': 3627}
    assert review['source_files_raw_git_checked'] == 4385 and review['external_files_rehashed'] == 440
    assert hashlib.sha256((BASE / ROOTS[1] / 'audit.json').read_bytes()).hexdigest() == review['audit_sha256']
    assert hashlib.sha256((BASE / ROOTS[0] / 'stdout.log').read_bytes()).hexdigest() == run['stdout_sha256']
    assert hashlib.sha256((BASE / ROOTS[0] / 'stderr.log').read_bytes()).hexdigest() == run['stderr_sha256']
    rows, findings = [], []
    for path in input_paths():
        name = str(path.relative_to(BASE)); info = path.lstat()
        posix = PurePosixPath(name)
        assert not posix.is_absolute() and '..' not in posix.parts and not path.is_symlink()
        row = dict(path=name, mode=stat.S_IMODE(info.st_mode))
        if stat.S_ISDIR(info.st_mode):
            row.update(kind='directory', bytes=0)
        else:
            row.update(kind='file', **stable_file(path))
            scan(path.read_bytes(), name, findings)
        rows.append(row)
    file_rows = [r for r in rows if r['kind'] == 'file']
    assert len(file_rows) == 68
    assert any(r['path'].startswith(ROOTS[1] + '/parser-attempt01/') for r in file_rows)
    scan_report = dict(schema='hepta.failed-full8-checkpoint-credential-scan.v1', pattern_count=len(PATTERNS),
                       patterns=list(PATTERNS), original_files_scanned=len(file_rows),
                       original_bytes_scanned=sum(r['bytes'] for r in file_rows), findings=findings,
                       private_transport_references_read=False, secret_values_printed=False)
    (OUT / 'credential-scan.json').write_bytes(wire(scan_report))
    assert not findings, 'credential pattern findings; locations only retained'
    manifest = dict(schema='hepta.failed-full8-checkpoint-manifest.v1', source=SOURCE,
                    tree=review['source_tree'], input_directories=list(ROOTS), input_files=list(SINGLES),
                    scope='Exactly the complete original directories and two original files requested; no retry or toolchain inputs added.',
                    original_files=len(file_rows), original_directories=len(rows)-len(file_rows),
                    original_bytes=sum(r['bytes'] for r in file_rows), entries=rows,
                    tar_timestamp_policy='Deterministic zero timestamps; original file bytes and permission modes preserved.')
    (OUT / 'MANIFEST.json').write_bytes(wire(manifest))
    with (OUT / ARCHIVE).open('xb') as sink:
        with gzip.GzipFile(fileobj=sink, filename='', mode='wb', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for row in rows:
                    info = tarfile.TarInfo(row['path']); info.mode = row['mode']; info.mtime = 0
                    if row['kind'] == 'directory':
                        info.type = tarfile.DIRTYPE; archive.addfile(info)
                    else:
                        info.size = row['bytes']
                        with (BASE / row['path']).open('rb') as source:
                            archive.addfile(info, source)
    # Read the compressed tar as a stream. Every raw original file is rehashed.
    readback = []
    with tarfile.open(OUT / ARCHIVE, mode='r|gz') as archive:
        for expected, member in zip(rows, archive, strict=True):
            assert member.name == expected['path'] and member.mode == expected['mode']
            if expected['kind'] == 'directory':
                assert member.isdir()
            else:
                assert member.isfile() and member.size == expected['bytes']
                observed = identity_stream(archive.extractfile(member), member.size)
                assert observed == {k: expected[k] for k in ('bytes', 'sha256', 'git_blob_sha1')}
            readback.append(member.name)
    assert readback == [r['path'] for r in rows]
    assert [str(p.relative_to(BASE)) for p in input_paths()] == readback, 'original input membership changed'
    for row in rows:
        path = BASE / row['path']; assert stat.S_IMODE(path.lstat().st_mode) == row['mode']
        if row['kind'] == 'file':
            assert stable_file(path) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob_sha1')}
    archive_identity = stable_file(OUT / ARCHIVE)
    payloads = []
    if archive_identity['bytes'] <= LIMIT:
        payloads.append(dict(path=ARCHIVE, index=0, **archive_identity))
    else:
        target = OUT / 'parts'; target.mkdir(exist_ok=False)
        count = (archive_identity['bytes'] + PART - 1) // PART
        with (OUT / ARCHIVE).open('rb') as stream:
            for index in range(count):
                data = stream.read(PART)
                name = f'parts/{ARCHIVE}.part-{index + 1:03d}-of-{count:03d}'
                (OUT / name).write_bytes(data)
                payloads.append(dict(path=name, index=index, **identity_bytes(data)))
        class Parts:
            def __init__(self): self.index = 0; self.stream = None
            def read(self, size):
                while self.index < len(payloads):
                    if self.stream is None: self.stream = (OUT / payloads[self.index]['path']).open('rb')
                    data = self.stream.read(size)
                    if data: return data
                    self.stream.close(); self.stream = None; self.index += 1
                return b''
        assert identity_stream(Parts(), archive_identity['bytes']) == archive_identity
    for p in payloads:
        assert stable_file(OUT / p['path']) == {k: p[k] for k in ('bytes', 'sha256', 'git_blob_sha1')}
    summary = dict(schema='hepta.failed-full8-checkpoint-summary.v1', source=SOURCE, attempt='first full8 attempt',
                   qualification_passed=False, passed_gates=6, total_gates=8, process_returncode=1,
                   started_utc=run['started_utc'], finished_utc=run['finished_utc'], wall_seconds=run['wall_seconds'],
                   python_methods=3628, python_ok=3627, python_errors=1, python_failures=0, python_skips=0,
                   rust_tests=88, source_files_stable=4385, external_files_stable=440,
                   integrity_checks_passed=75, nonpassing_methods=review['nonpassing_methods'],
                   observed_error=review['observed_error'], failed_gates=review['failed_gates'],
                   initial_audit_parser_failure_preserved=True, native_or_test_reruns_by_collector=0,
                   source_or_original_files_modified=False, later_retry_evidence_included=False)
    (OUT / 'summary.json').write_bytes(wire(summary))
    allowed = [p['path'] for p in payloads] + ['README.md', 'collect_failed_attempt.py', 'MANIFEST.json', 'credential-scan.json',
               'summary.json', 'PUBLIC_FILES.json', 'freeze-receipt.json', 'publication-payloads.json']
    allow = dict(schema='hepta.failed-full8-checkpoint-public-allowlist.v1', source=SOURCE, files=sorted(allowed),
                 original_archive_members=readback, private_transport_references_included=False)
    (OUT / 'PUBLIC_FILES.json').write_bytes(wire(allow))
    receipt = dict(schema='hepta.failed-full8-checkpoint-freeze.v1', source=SOURCE, qualification_passed=False,
                   archive=dict(path=ARCHIVE, **archive_identity), file_members=len(file_rows), directory_members=len(rows)-len(file_rows),
                   original_bytes=sum(r['bytes'] for r in file_rows), streaming_readback=True,
                   all_member_sha256_git_blob_bytes_and_modes_match=True, original_inputs_rechecked_unchanged=True,
                   complete_requested_input_set_preserved=True, original_parser_failure_preserved=True,
                   native_or_test_reruns=0, source_files_modified=0,
                   manifest=stable_file(OUT / 'MANIFEST.json'), allowlist=stable_file(OUT / 'PUBLIC_FILES.json'),
                   credential_scan=dict(pattern_count=10, original_files=len(file_rows), findings=[], private_transport_references_read=False))
    (OUT / 'freeze-receipt.json').write_bytes(wire(receipt))
    publish = dict(schema='hepta.failed-full8-checkpoint-publication.v1', source=SOURCE,
                   repository_prefix='evidence/hia_core_closure_20261029/first-attempt-699de39/',
                   outcome='actual_failed_attempt_not_qualification_pass', archive=dict(path=ARCHIVE, **archive_identity),
                   ordered_archive_payloads=payloads,
                   payloads=[dict(path=name, **stable_file(OUT / name)) for name in sorted(allowed) if name != 'publication-payloads.json'],
                   this_map_policy='Publish this final map beside its payloads; the publication commit binds its identity.')
    (OUT / 'publication-payloads.json').write_bytes(wire(publish))
    for name in allowed:
        generated_findings = []; scan((OUT / name).read_bytes(), name, generated_findings)
        assert not generated_findings, 'generated public payload contains credential pattern'
    print(json.dumps(dict(archive=dict(path=ARCHIVE, **archive_identity), files=len(file_rows), directories=len(rows)-len(file_rows),
                          publication_files=len(allowed), publication_map=stable_file(OUT / 'publication-payloads.json'),
                          freeze_receipt=stable_file(OUT / 'freeze-receipt.json')), indent=2))


if __name__ == '__main__':
    main()
