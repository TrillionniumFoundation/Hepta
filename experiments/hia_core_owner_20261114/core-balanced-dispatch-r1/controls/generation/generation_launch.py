"""One original 180/3 source owner; inspect child bodies only after bound ECHILD."""
from __future__ import annotations
import argparse
import hashlib
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
    final = {'schema': 'hia.core-balanced-dispatch.generation-final.v1', 'status': 'HOLD',
             'request_sha256': request_pin['sha256'], 'closed': False,
             'natural_zero': False, 'product_native_or_machine_compiler_executed': False,
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
        report = common.decode(common.read_regular(output / 'generation-report.json')[0])
        after = common.source_snapshot(request, materialization)
        final['changed_paths'] = common.require_source_after(request, before, after)
        common.save_json(output / 'parent-source-after.json', after)
        common.require(natural, 'original source owner did not finish naturally')
        common.require(report['status'] == 'SOURCE_GENERATION_CAPS_ONLY'
            and report['request_sha256'] == request_pin['sha256']
            and report['generation_attempts'] == report['generation_completed'] == 1
            and report['document_order'] == [Path(p).stem for p in request['assembly_paths']]
            and [x['path'] for x in report['outputs']] == request['generated_write_paths']
            and [x['path'] for x in report['caps']] ==
                [p for p in request['generated_write_paths'] if p in request['assembly_paths']]
            and len(report['outputs']) == 40 and len(report['caps']) == 39
            and report['source_tests_executed'] is False and report['VM_executed'] is False
            and report['machine_compiler_or_native_executed'] is False
            and report['assembly_roundtrip_executed'] is False
            and report['transport_is_qualification'] is False
            and report['changed_paths'] == final['changed_paths']
            and set(report['changed_paths']) ==
                set(request['assembly_paths']) - set(request['unchanged_generated_paths'])
            and not report['errors'] and not report['forbidden_attempts'],
            'complete generation-only report required')
        limits = {'source_bytes': 1048576, 'source_lines': 16384, 'functions': 128,
                  'blocks': 1536, 'ops_and_terms': 8192, 'function_blocks': 256,
                  'parameters': 16, 'operation_arguments': 16, 'unique_ssa': 2048}
        for row in report['caps']:
            common.require(row['passed'] is True and set(row['counts']) == set(limits)
                and all(type(row['counts'][k]) is int and 0 <= row['counts'][k] <= limits[k]
                        for k in limits), 'original nine capacity counts')
        for row in report['outputs']:
            relative = row['path']
            common.require(row['source'] == after[relative]
                and row['copy']['path'] == str(output / 'generated' / Path(relative).name),
                'generated copy path/identity binding')
            raw, observed = common.read_regular(Path(request['source_root']) / relative, row['source'])
            copied, copy_pin = common.read_regular(row['copy']['path'], row['copy'])
            common.require(raw == copied and hashlib.sha1(
                b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob'],
                'whole generated original/copy/Git identity')
        transport = report['transport']
        common.require(transport['members'] == 40 and transport['qualification'] is False
            and transport['gzip_mtime'] == 0 and transport['gzip_filename'] == '',
            'data-only transport scope')
        for name, limit in (('zip', 40 << 20), ('gzip', 64 << 20)):
            suffix = 'generated40.zip' + ('.gz' if name == 'gzip' else '')
            common.require(transport[name]['path'] == str(output / suffix)
                           and transport[name]['bytes'] <= limit, 'transport path/size')
            common.read_regular(transport[name]['path'], transport[name])
        final['generation_scope'] = 'ONE_AUTHOR_WRITE_AND_39_NINE_CAP_COUNTS_ONLY'
        final['source_methods_run'] = 0
        final['VM_calls'] = 0
        final['transport'] = transport
        final['status'] = 'SOURCE_GENERATION_CAPS_ONLY'
    except BaseException as error:
        final['status'] = 'HOLD'
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
    return 0 if (final['status'] == 'SOURCE_GENERATION_CAPS_ONLY' and not final['errors']) else 1

if __name__ == '__main__':
    raise SystemExit(main())
