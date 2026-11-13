"""One original 180/3 source owner; inspect child bodies only after bound ECHILD."""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import traceback
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as common

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request, materialization, request_pin = common.load_request(args.request, args.sha256)
    output = Path(request['output_root'])
    common.require(not output.exists(), 'fresh output root required')
    resource = os.statvfs(output.parent)
    common.require(resource.f_bavail * resource.f_frsize >= request['minimum_free_bytes']
                   and resource.f_favail >= request['minimum_free_inodes'], 'source capacity HOLD')
    before = common.source_snapshot(request, materialization)
    common.require_source_before(request, materialization, before)
    output.mkdir(mode=0o700)
    (output / 'scratch').mkdir(mode=0o700)
    final = {'schema': 'hia.pc-forwarding.source4-final.v1', 'status': 'HOLD',
             'request_sha256': request_pin['sha256'], 'closed': False,
             'natural_zero': False, 'product_native_or_compiler_executed': False,
             'fresh_space': {'bytes': resource.f_bavail * resource.f_frsize,
                             'inodes': resource.f_favail}, 'errors': []}
    wrapper = None
    try:
        common.save_json(output / 'parent-source-before.json', before)
        spec = importlib.util.spec_from_file_location('pc_source_owned_process',
                                                      request['owner_implementation']['path'])
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        wrapper = owner.run_owned(request['worker_command'], cwd=request['source_root'],
            env=request['environment'], stdout_path=output / 'child.stdout',
            stderr_path=output / 'child.stderr', receipt_path=output / 'process-owner.json',
            qualification_seconds=180, cleanup_seconds=3)
        common.save_json(output / 'owner-wrapper.json', wrapper)
        receipt, child_request, natural = common.bind_closed(
            request, wrapper, output / 'process-owner.json')
        final['closed'] = True
        final['natural_zero'] = natural
        common.save_json(output / 'OWNER-CLOSURE.json', {
            'closed': True, 'natural_zero': natural, 'owner': receipt,
            'child_request_sha256': common.read_regular(str(output / 'process-owner.json') + '.request.json')[1]['sha256'],
            'owner_wrapper': wrapper})
        # Current-bound cleanup is established independently of success before
        # any child report, generated source, log or child directory is opened.
        report = common.decode(common.read_regular(output / 'source4-report.json')[0])
        after = common.source_snapshot(request, materialization)
        final['changed_paths'] = common.require_source_after(request, before, after)
        common.save_json(output / 'parent-source-after.json', after)
        common.require(natural, 'original source owner did not finish naturally')
        common.require(report['status'] == 'SOURCE4_PASS_ONLY'
            and report['request_sha256'] == request_pin['sha256']
            and report['expected_ids'] == report['loaded_ids'] == report['started_ids']
                == report['stopped_ids'] == request['expected_ids']
            and report['testsRun'] == 4
            and all(not report[key] for key in ('failures', 'errors', 'skipped',
                'expectedFailures', 'unexpectedSuccesses', 'loader_errors', 'forbidden_attempts')),
            'complete source4 report required')
        common.require(report['generation']['count'] == 39
            and report['generation']['paths'] == [str(Path(request['source_root']) / p)
                                                for p in request['generated_assembly']],
            'actual generation population differs')
        final['status'] = 'SOURCE4_PASS_ONLY'
    except BaseException as error:
        final['errors'].append({'type': type(error).__name__, 'message': str(error),
                                'traceback': traceback.format_exc()})
    finally:
        if final['closed']:
            try:
                originals = []
                for path in sorted(output.rglob('*')):
                    if path.is_dir():
                        continue
                    originals.append(common.read_regular(path)[1])
                common.save_json(output / 'ORIGINALS.json', originals)
                final['originals'] = len(originals)
                for value in request['inputs']:
                    common.read_regular(value['path'], value)
            except BaseException as error:
                final['status'] = 'HOLD'
                final['errors'].append({'type': type(error).__name__, 'message': str(error),
                                        'traceback': traceback.format_exc()})
        else:
            final['child_body_custody'] = 'UNREAD_UNCONFIRMED_OWNER'
        common.save_json(output / 'FINAL.json', final)
    print(final['status'])
    return 0 if final['status'] == 'SOURCE4_PASS_ONLY' else 1

if __name__ == '__main__':
    raise SystemExit(main())
