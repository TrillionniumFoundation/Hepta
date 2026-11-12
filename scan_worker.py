"""One unchanged checkout source scan; no business operations or native selection."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import sys
import time
import traceback


def usage():
    row = resource.getrusage(resource.RUSAGE_SELF)
    return {name: getattr(row, name) for name in (
        'ru_utime', 'ru_stime', 'ru_maxrss', 'ru_minflt', 'ru_majflt',
        'ru_inblock', 'ru_oublock', 'ru_nvcsw', 'ru_nivcsw')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--label', required=True, choices=('before', 'observed', 'after'))
    args = parser.parse_args()
    root, output = Path(args.source).resolve(), Path(args.report).resolve()
    report = {'schema': 'hia.fresh-source.single-scan.v1', 'status': 'STARTED',
              'scope': 'DIAGNOSTIC_ONLY_NO_QUALIFICATION', 'label': args.label,
              'python': sys.version, 'executable': sys.executable, 'pid': os.getpid(),
              'source': str(root), 'original_limits_changed': False,
              'product_changed': False, 'business_cases_executed': False}
    started = False
    begin = 'HIA_FRESH_SOURCE_SCAN_BEGIN|' + args.label + '|' + str(os.getpid())
    end = 'HIA_FRESH_SOURCE_SCAN_END|' + args.label + '|' + str(os.getpid())
    report['markers'] = {'begin': begin, 'end': end}
    try:
        if sys.version_info[:3] != (3, 14, 4):
            raise RuntimeError('this diagnostic requires actual CPython 3.14.4')
        if sys.implementation.name != 'cpython':
            raise RuntimeError('CPython implementation required')
        if not sys.dont_write_bytecode or not sys.flags.isolated:
            raise RuntimeError('isolated mode and disabled bytecode writes required')
        sys.path.insert(0, str(root))
        from tools import hia_selfhost_contract as contract
        if Path(contract.__file__).resolve() != root / 'tools/hia_selfhost_contract.py':
            raise RuntimeError('source contract imported from a different checkout')
        declared = json.loads((root / contract.CONTRACT_PATH).read_bytes())
        expected = declared['source_identity']['files']
        if type(expected) is not dict or len(expected) != 963:
            raise RuntimeError('expected exact 963-file source closure')
        report['contract_module_sha256'] = sha256(Path(contract.__file__).read_bytes()).hexdigest()
        os.write(2, (begin + '\n').encode('ascii'))
        started = True
        before = usage()
        cpu = time.process_time_ns()
        wall = time.perf_counter_ns()
        try:
            actual = contract.file_digests(root)
        finally:
            wall = time.perf_counter_ns() - wall
            cpu = time.process_time_ns() - cpu
            after = usage()
            report['scan_wall_ns'] = wall
            report['scan_cpu_ns'] = cpu
            report['rusage_before'] = before
            report['rusage_after'] = after
            report['rusage_delta'] = {key: after[key] - before[key] for key in before
                                      if key != 'ru_maxrss'}
            report['maxrss_kib_before_after'] = [before['ru_maxrss'], after['ru_maxrss']]
            os.write(2, (end + '\n').encode('ascii'))
            started = False
        report['ordered_items'] = list(actual.items())
        report['map_matches_exact_contract'] = actual == expected and list(actual) == sorted(expected)
        report['ordered_map_sha256'] = sha256(json.dumps(
            report['ordered_items'], ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        if not report['map_matches_exact_contract']:
            raise AssertionError('actual ordered map differs from the complete original source contract')
        report['status'] = 'PASS'
    except BaseException as exc:
        report['status'] = 'FAIL'
        report['error'] = {'type': type(exc).__qualname__, 'args': repr(exc.args),
                           'traceback': traceback.format_exc()}
    finally:
        if started:
            os.write(2, (end + '\n').encode('ascii'))
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({key: value for key, value in report.items()
                          if key not in ('ordered_items', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
