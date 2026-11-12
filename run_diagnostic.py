"""Read-only exact-4b source I/O diagnostic with complete raw evidence."""
from __future__ import annotations
import argparse
import ast
import base64
from collections import Counter, defaultdict
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import time
import traceback
import zlib

COMMIT = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE = '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
TRACKED_FILES = 3153
CLOSURE_FILES = 963
CLOSURE_BYTES = 28526830
CONTRACT_SHA = '233796caa92557d5dcbf4de125a867a70bc2859564f0dbe31fbc4196de6781f5'
BRANCH = 'codex/hia-source-syscall-diagnostic-v77-20261112-dda7'


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def source_snapshot(root):
    if git(root, 'rev-parse', 'HEAD').decode().strip() != COMMIT:
        raise AssertionError('checkout HEAD differs')
    if git(root, 'rev-parse', 'HEAD^{tree}').decode().strip() != TREE:
        raise AssertionError('checkout tree differs')
    if git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all'):
        raise AssertionError('source checkout is not clean')
    rows = {}
    for record in git(root, 'ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
        if not record:
            continue
        meta, name_raw = record.split(b'\t', 1)
        mode, kind, expected_blob = meta.decode('ascii').split()
        name = os.fsdecode(name_raw)
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise AssertionError('unexpected original tracked entry: ' + name)
        path = root / name
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or bool(st.st_mode & 0o111) != (mode == '100755'):
            raise AssertionError('tracked mode/type differs: ' + name)
        raw = path.read_bytes()
        blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if blob != expected_blob:
            raise AssertionError('tracked bytes differ: ' + name)
        rows[name] = {'git_mode': mode, 'posix_mode': format(stat.S_IMODE(st.st_mode), '04o'),
                      'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'git_blob': blob}
    if len(rows) != TRACKED_FILES:
        raise AssertionError('tracked file count differs')
    return rows


def run(command, folder, env):
    folder.mkdir()
    started = time.perf_counter()
    record = {'command': command, 'diagnostic_outer_timeout_seconds': 120,
              'product_limit_changed': False, 'timed_out': False, 'owned_cleanup_confirmed': False}
    with (folder / 'stdout.log').open('wb') as out, (folder / 'stderr.log').open('wb') as err:
        process = subprocess.Popen(command, stdout=out, stderr=err, env=env, start_new_session=True)
        record['pid'] = process.pid
        try:
            record['returncode'] = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            os.killpg(process.pid, signal.SIGKILL)
            record['returncode'] = process.wait(timeout=10)
            record['owned_cleanup_confirmed'] = True
    record['outer_wall_seconds'] = time.perf_counter() - started
    record['stdout'] = identity(folder / 'stdout.log')
    record['stderr'] = identity(folder / 'stderr.log')
    save(folder / 'PROCESS.json', record)
    return record


def parse_trace(path, scan, root, names):
    raw = path.read_bytes()
    lines = raw.decode('utf-8', 'surrogateescape').splitlines()
    def marker(which):
        text = scan['markers'][which]
        pattern = re.compile(r'\bwrite\(2(?:<[^>]*>)?, "' + re.escape(text) + r'\\n",')
        found = [i for i, line in enumerate(lines) if pattern.search(line)]
        if len(found) != 1:
            raise AssertionError('trace marker is missing or ambiguous: ' + which)
        return found[0]
    first, last = marker('begin'), marker('end')
    if first >= last:
        raise AssertionError('trace markers reversed')
    counts, intervals, errors = Counter(), defaultdict(float), Counter()
    opens, file_reads, source_bytes = [], Counter(), 0
    source_dir = str(root) + '/'
    unparsed = []
    syscall = re.compile(r'^(?:(\d+)\s+)?(\d+\.\d+)\s+(\w+)\((.*)$')
    for index in range(first + 1, last):
        line = lines[index]
        match = syscall.match(line)
        if not match:
            if '--- ' in line or '+++ ' in line:
                continue
            unparsed.append({'line': index + 1, 'text': line})
            continue
        name = match.group(3)
        counts[name] += 1
        elapsed = re.search(r'<(\d+\.\d+)>$', line)
        if elapsed:
            intervals[name] += float(elapsed.group(1))
        else:
            unparsed.append({'line': index + 1, 'text': line})
        return_text = line.rsplit(' = ', 1)[-1]
        if return_text.startswith('-1 '):
            errors[name] += 1
        if name in ('openat', 'open'):
            path_match = re.search(r'\bopenat\([^,]+, ("(?:\\.|[^"\\])*"),', line) if name == 'openat' else re.search(r'\bopen\(("(?:\\.|[^"\\])*"),', line)
            if path_match:
                opened = ast.literal_eval(path_match.group(1))
                if opened.startswith(source_dir) and opened[len(source_dir):] in names:
                    opens.append(opened[len(source_dir):])
        if name == 'read':
            fd_path = re.search(r'\bread\(\d+<([^>]*)>,', line)
            returned = re.match(r'(-?\d+)(?:\s|$)', return_text)
            if fd_path and returned and fd_path.group(1).startswith(source_dir):
                relative = fd_path.group(1)[len(source_dir):]
                if relative in names:
                    file_reads[relative] += 1
                    source_bytes += max(0, int(returned.group(1)))
    families = {'openat': ('openat', 'open'), 'fstat': ('newfstatat', 'fstat', 'fstat64', 'statx'),
                'read': ('read',), 'close': ('close',), 'lseek': ('lseek',),
                'getdents64': ('getdents64', 'getdents')}
    result = {'schema': 'hia.fresh-source.strace-window.v1', 'trace': identity(path),
              'begin_line': first + 1, 'end_line': last + 1,
              'window_lines': last - first - 1, 'counts': dict(counts),
              'observed_syscall_elapsed_seconds': dict(intervals), 'syscall_errors': dict(errors),
              'families': {label: {'count': sum(counts[n] for n in group),
                                  'observed_elapsed_seconds': sum(intervals[n] for n in group)}
                           for label, group in families.items()},
              'source_open_order': opens, 'source_file_read_calls': dict(file_reads),
              'source_read_bytes': source_bytes, 'unparsed_window_lines': unparsed,
              'syscall_elapsed_is_not_uninstrumented_kernel_cpu': True,
              'path_object_construction_is_not_classified_as_kernel_time': True}
    result['complete_expected_source_reads'] = (opens == sorted(names) and set(file_reads) == set(names)
                                                and source_bytes == CLOSURE_BYTES)
    result['parse_complete'] = not unparsed
    return result


def emit_capsule(report, out):
    files = {}
    for relative in ('REPORT.json', 'SOURCE-BEFORE.json', 'SOURCE-AFTER.json', 'TRACE-SUMMARY.json',
                     'before/RESULT.json', 'before/PROCESS.json', 'before/stdout.log', 'before/stderr.log',
                     'observed/RESULT.json', 'observed/PROCESS.json', 'observed/stdout.log', 'observed/stderr.log',
                     'after/RESULT.json', 'after/PROCESS.json', 'after/stdout.log', 'after/stderr.log'):
        path = out / relative
        if path.is_file():
            raw = path.read_bytes()
            files[relative] = {**identity(path), 'base64': base64.b64encode(raw).decode('ascii')}
    raw = json.dumps({'schema': 'hia.fresh-source.diagnostic-text-capsule.v1', 'files': files,
                      'full_strace_in_artifact_only': report.get('trace_identity')},
                     separators=(',', ':'), sort_keys=True).encode()
    packed = zlib.compress(raw, 9)
    (out / 'TEXT-CAPSULE.json.zlib').write_bytes(packed)
    encoded = base64.b64encode(packed).decode('ascii')
    total = (len(encoded) + 11999) // 12000
    print('HIA_SOURCE_IO_CAPSULE_MANIFEST ' + json.dumps({'raw_bytes': len(raw),
        'raw_sha256': sha256(raw).hexdigest(), 'compressed_bytes': len(packed),
        'compressed_sha256': sha256(packed).hexdigest(), 'chunks': total}, sort_keys=True), flush=True)
    for index in range(total):
        print('HIA_SOURCE_IO_CAPSULE ' + json.dumps({'index': index, 'total': total,
            'base64': encoded[index*12000:(index+1)*12000]}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root, out = Path(args.source).resolve(), Path(args.output).resolve()
    if root == out or root in out.parents:
        raise RuntimeError('evidence must be outside the read-only source checkout')
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'hia.fresh-source.syscall-diagnostic.v1', 'status': 'STARTED',
              'scope': 'EXACT_4B_CPYTHON_3_14_4_DIAGNOSTIC_NOT_QUALIFICATION',
              'source_commit': COMMIT, 'source_tree': TREE, 'source': str(root),
              'python': sys.version, 'platform': platform.platform(), 'processes': {}, 'scans': {},
              'source_identity_checks_precede_scans_and_warm_os_page_cache': True,
              'each_scan_uses_a_separate_fresh_python_process': True,
              'strace_only_observes_middle_process': True,
              'business_cases_executed': False, 'product_changed': False,
              'source_read_caching_added': False, 'parallel_io_added': False,
              'current_source_cold': False, 'full': False, 'default': False,
              'live': False, 'deletion': False, 'original_limits_changed': False}
    try:
        if sys.version_info[:3] != (3, 14, 4) or sys.implementation.name != 'cpython':
            raise RuntimeError('actual CPython 3.14.4 required')
        report['source_before'] = source_snapshot(root)
        save(out / 'SOURCE-BEFORE.json', report.pop('source_before'))
        raw_contract = (root / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes()
        if sha256(raw_contract).hexdigest() != CONTRACT_SHA:
            raise AssertionError('exact source contract bytes differ')
        expected = json.loads(raw_contract)['source_identity']['files']
        if len(expected) != CLOSURE_FILES:
            raise AssertionError('source closure differs')
        report['closure_count'] = len(expected)
        report['closure_bytes'] = CLOSURE_BYTES
        tracer = shutil.which('strace')
        if tracer is None:
            raise RuntimeError('strace prerequisite is unavailable')
        report['strace'] = {'path': tracer, **identity(Path(tracer)),
                           'version': subprocess.run([tracer, '--version'], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10).stdout.decode()}
        env = dict(os.environ)
        report['removed_inherited_native_selector_names'] = sorted(k for k in env if k.startswith('HEPTA_HIA'))
        for key in report['removed_inherited_native_selector_names']:
            del env[key]
        worker = Path(__file__).resolve().with_name('scan_worker.py')
        report['harness_sources'] = {path.name: identity(path) for path in (Path(__file__).resolve(), worker)}
        for label in ('before', 'observed', 'after'):
            folder = out / label
            command = [sys.executable, '-I', '-B', str(worker), '--source', str(root),
                       '--report', str(folder / 'RESULT.json'), '--label', label]
            if label == 'observed':
                command = [tracer, '-f', '-ttt', '-T', '-s', '256', '-y',
                           '-o', str(out / 'strace-full.log'), '--', *command]
            report['processes'][label] = run(command, folder, env)
            if (folder / 'RESULT.json').is_file():
                report['scans'][label] = json.loads((folder / 'RESULT.json').read_bytes())
            save(out / 'REPORT.json', report)
        trace = out / 'strace-full.log'
        if trace.is_file():
            report['trace_identity'] = {'path': 'strace-full.log', **identity(trace)}
        if 'observed' in report['scans'] and trace.is_file():
            parsed = parse_trace(trace, report['scans']['observed'], root, expected)
            save(out / 'TRACE-SUMMARY.json', parsed)
            report['trace_summary'] = {k: v for k, v in parsed.items()
                if k not in ('source_open_order', 'source_file_read_calls', 'unparsed_window_lines')}
        before = json.loads((out / 'SOURCE-BEFORE.json').read_bytes())
        report['source_after_attempted'] = True
        after = source_snapshot(root)
        save(out / 'SOURCE-AFTER.json', after)
        report['all_tracked_source_bytes_modes_unchanged'] = before == after
        scans = report['scans']
        checks = {
            'all_three_workers_returned_zero': all(report['processes'][k]['returncode'] == 0 and
                not report['processes'][k]['timed_out'] for k in ('before', 'observed', 'after')),
            'all_three_scans_passed': all(scans.get(k, {}).get('status') == 'PASS' for k in ('before', 'observed', 'after')),
            'all_ordered_maps_equal': len(scans) == 3 and scans['before'].get('ordered_items') ==
                scans['observed'].get('ordered_items') == scans['after'].get('ordered_items'),
            'all_3153_source_bytes_modes_unchanged': before == after,
            'trace_complete': report.get('trace_summary', {}).get('parse_complete') is True,
            'all_963_files_read_in_order': report.get('trace_summary', {}).get('complete_expected_source_reads') is True,
        }
        report['checks'] = checks
        if all(checks.values()):
            unobserved = statistics.median([scans['before']['scan_wall_ns'], scans['after']['scan_wall_ns']])
            report['observed_to_uninstrumented_median_wall_ratio'] = scans['observed']['scan_wall_ns'] / unobserved
            report['status'] = 'DIAGNOSTIC_COMPLETE'
        else:
            report['status'] = 'DIAGNOSTIC_FAILED'
    except BaseException as exc:
        report['status'] = 'DIAGNOSTIC_FAILED'
        report['error'] = {'type': type(exc).__qualname__, 'args': repr(exc.args), 'traceback': traceback.format_exc()}
    finally:
        if not report.get('source_after_attempted') and (out / 'SOURCE-BEFORE.json').is_file():
            report['source_after_attempted'] = True
            try:
                after = source_snapshot(root)
                save(out / 'SOURCE-AFTER.json', after)
                report['all_tracked_source_bytes_modes_unchanged'] = after == json.loads(
                    (out / 'SOURCE-BEFORE.json').read_bytes())
            except BaseException as exc:
                report['source_after_error'] = {'type': type(exc).__qualname__,
                    'args': repr(exc.args), 'traceback': traceback.format_exc()}
        save(out / 'REPORT.json', report)
        summary = {k: v for k, v in report.items() if k != 'scans'}
        summary['scans'] = {k: {key: value for key, value in row.items() if key != 'ordered_items'}
                            for k, row in report.get('scans', {}).items()}
        save(out / 'SUMMARY.json', summary)
        print('HIA_SOURCE_IO_DIAGNOSTIC_SUMMARY ' + json.dumps(summary, sort_keys=True), flush=True)
        emit_capsule(report, out)
    return 0 if report['status'] == 'DIAGNOSTIC_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
