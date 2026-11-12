"""One explicitly developmental compiler-pair comparison; no application run.

The two existing, separately provenanced B3 images compile the same three HIA
inputs. Original 20s wall/10s CPU/1MiB child limits and one 180s/3s owner remain.
This does not recover the deleted CI executable or explain a runtime timeout.
"""
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import traceback


SOURCES = ('artifact_publication_policy', 'artifact_publication_packer', 'sha256_stream')
INVOKE_FIELDS = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format', 'runner_sha256', 'wall_elapsed_ns'}
COMPILE_FIELDS = {'produced_image', 'produced_bytes', 'produced_sha256'}


def write(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')


def snapshot(source, config):
    rows = {}
    for name, expected in config['source_pins'].items():
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('exact regular compiler input required: ' + name)
        raw = path.read_bytes()
        row = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
        if row != expected:
            raise ValueError('compiler source pin differs: ' + name)
        rows[name] = row
    return rows


def join_child(folder, label, image, source, config, produced=None):
    raw = (folder / (label + '.receipt.json')).read_bytes()
    receipt = json.loads(raw)
    stdout = (folder / (label + '.stdout.log')).read_bytes()
    child = json.loads(stdout)
    stderr = (folder / (label + '.stderr.log')).read_bytes()
    output = (folder / (label + '.output.bin')).read_bytes()
    request = json.loads((folder / (label + '.request.json')).read_bytes())
    image_raw = image.read_bytes()
    source_raw = (folder / (label + '.input.bin')).read_bytes()
    ignored = INVOKE_FIELDS | (COMPILE_FIELDS if produced is not None else set())
    if {key: value for key, value in receipt.items() if key not in ignored} != child:
        raise ValueError('full child stdout differs from producer receipt')
    if (stderr or child['status'] != 'returned' or child['abi_status'] != 0 or
            child['source_unchanged'] is not True or child['forbidden_compiler_modules_loaded'] or
            source_raw != source or len(output) != 1 << 20 or
            child['source_sha256'] != sha256(source).hexdigest() or
            child['image_sha256'] != sha256(image_raw).hexdigest() or
            child['output_sha256'] != sha256(output).hexdigest() or
            receipt['input_sha256'] != sha256(source).hexdigest() or
            receipt['artifact_sha256'] != sha256(image_raw).hexdigest() or
            receipt['runner_sha256'] != config['source_pins']['tools/hia_selfhost_child.py']['sha256'] or
            request != {'format': 'flat-x86-64', 'image': str(image.resolve()),
                        'image_sha256': sha256(image_raw).hexdigest(),
                        'source': str((folder / (label + '.input.bin')).resolve()),
                        'source_sha256': sha256(source).hexdigest(), 'capacity': 1 << 20,
                        'workspace_size': 1 << 20, 'workspace_fill': 0,
                        'output': str((folder / (label + '.output.bin')).resolve())}):
        raise ValueError('actual child/image/input/full-output binding differs')
    if child['limits'] != {'cpu_seconds': 10, 'address_bytes': 256 << 20, 'core_dumpable': False,
                           'stack_bytes': 8 << 20, 'output_capacity': 1 << 20, 'workspace_bytes': 1 << 20}:
        raise ValueError('original child limits differ')
    count = child['core_u32']
    if type(count) is not int or not 0 < count <= len(output):
        raise ValueError('native producer returned invalid extent')
    if produced is not None:
        body = produced.read_bytes()
        if (body != output[:count] or receipt['produced_image'] != str(produced) or
                receipt['produced_bytes'] != len(body) or receipt['produced_sha256'] != sha256(body).hexdigest()):
            raise ValueError('produced image differs from full native output')
    return {'receipt_sha256': sha256(raw).hexdigest(), 'stdout_sha256': sha256(stdout).hexdigest(),
            'output_sha256': sha256(output).hexdigest(), 'returned_bytes': count,
            'input_sha256': sha256(source).hexdigest(), 'image_sha256': sha256(image_raw).hexdigest(),
            'native_elapsed_ns': child['native_elapsed_ns'], 'wall_elapsed_ns': receipt['wall_elapsed_ns']}


def worker(args, config):
    source = args.source.resolve(); output = args.output.resolve()
    output.mkdir(mode=0o700)
    report = {'schema': config['schema'], 'status': 'HOLD', 'variants': {}, 'comparisons': {},
              'scope': 'existing-compiler development; no publication application execution',
              'python': {'path': sys.executable, 'version': sys.version, 'sha256': sha256(Path(sys.executable).read_bytes()).hexdigest()},
              'fresh_cold_replay': False, 'original_ci_app_recovered': False, 'original_39_run': False}
    try:
        report['source_before'] = snapshot(source, config)
        sys.path.insert(0, str(source))
        from tools import qualify_hia_selfhost as qualify
        from tools.generate_hia_artifact_publication import MAGIC
        if qualify.CAPACITY != 1 << 20 or qualify.NATIVE_OBSERVER is not None or qualify.NATIVE_LINKED_OBSERVER is not None:
            raise ValueError('original native child path and capacity required')
        for label, compiler_path in (('v79', args.old_compiler), ('v82', args.new_compiler)):
            folder = output / label; folder.mkdir(mode=0o700)
            variant = report['variants'][label] = {'status': 'HOLD', 'steps': []}
            try:
                compiler = compiler_path.read_bytes()
                if {'bytes': len(compiler), 'sha256': sha256(compiler).hexdigest()} != config['compilers'][label]:
                    raise ValueError('actual existing compiler input differs')
                pinned = folder / 'B3.image.bin'
                with pinned.open('xb') as stream:stream.write(compiler)
                pinned.chmod(0o400)
                images = {}
                for name in SOURCES:
                    text = (source / 'examples/hia_bootstrap' / (name + '.hiaasm')).read_bytes()
                    image, receipt = qualify.compile_stage(folder, name, pinned, text)
                    images[name] = image
                    variant['steps'].append({'name': name, **join_child(folder, name, pinned, text, config, image)})
                policy = images[SOURCES[0]].read_bytes(); hashing = images[SOURCES[2]].read_bytes()
                frame = struct.pack('<3Q', MAGIC, len(policy), len(hashing)) + policy + hashing
                packed, raw = qualify.invoke(folder, 'pack', images[SOURCES[1]], frame)
                joined = join_child(folder, 'pack', images[SOURCES[1]], frame, config)
                app = raw[:joined['returned_bytes']]
                if len(app) < 176 or app[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH', app, 16) != (2, 62):
                    raise ValueError('native packer output is not the expected ET_EXEC')
                with (folder / 'hia-artifact').open('xb') as stream:stream.write(app)
                variant['steps'].append({'name': 'pack', **joined})
                variant['outputs'] = {name: {'bytes': path.stat().st_size, 'sha256': sha256(path.read_bytes()).hexdigest()}
                                      for name, path in {**images, 'hia-artifact': folder / 'hia-artifact'}.items()}
                variant['compiler_after'] = {'bytes': len(pinned.read_bytes()), 'sha256': sha256(pinned.read_bytes()).hexdigest()}
                if variant['compiler_after'] != config['compilers'][label]:
                    raise ValueError('private compiler copy changed')
                variant['status'] = 'THREE_COMPILES_AND_NATIVE_PACK_COMPLETE'
            except BaseException as exc:
                variant['failure'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
            write(folder / 'RESULT.json', variant)
        for name in (*SOURCES, 'hia-artifact'):
            suffix = '.image.bin' if name in SOURCES else ''
            paths = [output / label / (name + suffix) for label in ('v79', 'v82')]
            if all(path.is_file() for path in paths):
                left, right = (path.read_bytes() for path in paths)
                report['comparisons'][name] = {'v79_bytes': len(left), 'v82_bytes': len(right),
                    'v79_sha256': sha256(left).hexdigest(), 'v82_sha256': sha256(right).hexdigest(),
                    'all_bytes_equal': left == right,
                    'first_differing_offset': next((i for i, (a, b) in enumerate(zip(left, right)) if a != b),
                                                   None if len(left) == len(right) else min(len(left), len(right)))}
            else:
                report['comparisons'][name] = {'comparison_unavailable': True}
        report['source_after'] = snapshot(source, config)
        if (report['source_after'] == report['source_before'] and
                all(row['status'] == 'THREE_COMPILES_AND_NATIVE_PACK_COMPLETE' for row in report['variants'].values()) and
                len(report['variants']) == 2):
            report['status'] = 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE'
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
    finally:
        write(output / 'REPORT.json', report)
    return 0 if report['status'] == 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE' else 1


def control(args, config):
    root = args.output.resolve(); root.mkdir(mode=0o700)
    owner_path = args.source.resolve() / 'tools/hia_selfhost_process_owner.py'
    environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1'}
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker',
               '--config', str(args.config.resolve()), '--source', str(args.source.resolve()),
               '--old-compiler', str(args.old_compiler.resolve()), '--new-compiler', str(args.new_compiler.resolve()),
               '--output', str(root / 'worker')]
    report = {'schema': config['schema'], 'status': 'HOLD', 'command': command, 'env': environment,
              'fresh_cold_replay': False, 'original_ci_app_recovered': False,
              'publication_application_execution': False, 'original_39_run': False}
    try:
        report['source_before'] = snapshot(args.source.resolve(), config)
        spec = importlib.util.spec_from_file_location('_publication_pair_owner', owner_path)
        owner = importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        returned = owner.run_owned(command, cwd=args.source.resolve(), env=environment,
            stdout_path=root / 'stdout.log', stderr_path=root / 'stderr.log', receipt_path=root / 'owner.json',
            qualification_seconds=180, cleanup_seconds=3)
        report['owner_returned'] = returned
        cleanup = returned.get('cleanup', {})
        closed = (cleanup.get('complete') is True and cleanup.get('observed_echild') is True and
                  cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == [] and
                  cleanup.get('errors') == [] and cleanup.get('deadline_exceeded') is False)
        report['closed_before_worker_read'] = closed
        if closed:
            raw = (root / 'owner.json').read_bytes(); actual = json.loads(raw)
            request_raw = (root / 'owner.json.request.json').read_bytes(); request = json.loads(request_raw)
            report['actual_owner_sha256'] = sha256(raw).hexdigest()
            if (returned != dict(actual, supervisor_returncode=0, receipt_sha256=sha256(raw).hexdigest()) or
                    actual['request_sha256'] != sha256(request_raw).hexdigest() or
                    request['command'] != command or request['cwd'] != str(args.source.resolve()) or request['env'] != environment or
                    request['qualification_seconds'] != 180 or request['cleanup_seconds'] != 3 or
                    request['implementation_sha256'] != config['source_pins']['tools/hia_selfhost_process_owner.py']['sha256']):
                report['owner_binding_failed'] = True
            else:
                worker_path = root / 'worker/REPORT.json'
                if worker_path.is_file():
                    report['worker'] = json.loads(worker_path.read_bytes())
                    report['worker_report_sha256'] = sha256(worker_path.read_bytes()).hexdigest()
                allowed = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}
                natural = (actual.get('owner_error') is None and actual['returncode'] == 0 and not actual['timed_out'] and
                           actual['exit_observed_before_deadline'] is True and not actual['event_overflow'] and
                           actual['interrupted_signals'] == [] and actual['status'] == 'OWNED_PROCESS_COMPLETED' and
                           actual['schema'] == owner.SCHEMA and actual['subreaper_enabled'] is True and
                           actual['qualification_started'] is True and actual['qualification_seconds'] == 180 and
                           actual['cleanup_seconds'] == 3 and {'qualification_started','qualification_exit_observed','owned_child_reaped'}
                               <= {event['kind'] for event in actual['events']} and
                           actual['events'] and all(event['kind'] in allowed for event in actual['events']))
                if natural and report.get('worker', {}).get('status') == 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE':
                    report['status'] = 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE'
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
    if report.get('closed_before_worker_read'):
        try:
            report['source_after'] = snapshot(args.source.resolve(), config)
            if report['source_after'] != report['source_before']:
                raise ValueError('actual compiler source inputs changed')
        except BaseException as exc:
            report['status'] = 'HOLD'
            report['source_after_error'] = {'type': type(exc).__name__, 'message': str(exc)}
    write(root / 'FINAL.json', report)
    print(json.dumps({'status': report['status'], 'report': str(root / 'FINAL.json')}))
    return 0 if report['status'] == 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    for name in ('config', 'source', 'old-compiler', 'new-compiler', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args();config_raw = args.config.read_bytes()
    if sha256(config_raw).hexdigest() != '19e9afd42b7b77604fb66a2fc6c2ad61b3edbb42ad935e1e084294a97be1eeb4':
        raise ValueError('exact frozen compiler-pair config required')
    config = json.loads(config_raw)
    if {name: config[name] for name in ('outer_seconds','cleanup_seconds','compile_wall_seconds','compile_cpu_seconds','capacity')} != {
            'outer_seconds': 180, 'cleanup_seconds': 3, 'compile_wall_seconds': 20, 'compile_cpu_seconds': 10, 'capacity': 1 << 20}:
        raise ValueError('all original compilation and owner limits are fixed')
    return worker(args, config) if args.worker else control(args, config)


if __name__ == '__main__':
    raise SystemExit(main())
