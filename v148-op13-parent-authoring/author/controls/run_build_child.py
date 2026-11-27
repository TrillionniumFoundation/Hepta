"""Three owned build stages, using the original two R5 bodies and Patch builder.

No compilation occurs at import. The actual ordinary compiler is bound before
calling a preserved body. This is development execution, never current cold.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys
import traceback
sys.path.insert(0, str(Path(__file__).absolute().parent))
from execution_support import *
from inspect_exec_support import json_bytes
B3 = None


def build_inspect(plan, directory):
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_cli_discovery_custody import admit_compilation
    from hepta.hia_inspect_program_native import SCHEMA, SOURCE_NAME, IMAGE_NAME, _capture_host_sources
    source = (Path(plan['source']) / 'examples/hia_bootstrap/inspect_program.hepta').read_bytes()
    hosts = _capture_host_sources()
    output = directory / 'inspect'; output.mkdir(mode=0o700)
    (output / SOURCE_NAME).write_bytes(source)
    image, returned = compile_stage(output, 'inspect-program', Path(B3['path']), source)
    receipt, observations = admit_compilation(output, 'inspect-program', Path(B3['path']), source, image)
    require(returned == receipt and Path(image) == output / IMAGE_NAME
            and _capture_host_sources() == hosts, 'actual original compile/host capture differs')
    image_raw = Path(image).read_bytes()
    require(0 < len(image_raw) <= CAPACITY, 'actual inspect image exceeds original limit')
    manifest = {'schema': SCHEMA, 'source_path': SOURCE_NAME,
        'source_sha256': hashlib.sha256(source).hexdigest(), 'image_path': IMAGE_NAME,
        'image_sha256': hashlib.sha256(image_raw).hexdigest(), 'compiler_sha256': B3['sha256'],
        'host_sources': hosts}
    publish(output / 'manifest.json', manifest)
    report = {'manifest': str(output / 'manifest.json'), 'source': pin(source),
        'image': pin(image_raw), 'receipt': receipt, 'observations': observations,
        'default_compile_receipt_is_not_a_full_workspace_observation': True,
        'matching_current_cold': False}
    publish(directory / 'BUILD.json', report)
    return report

def build_report(plan, directory):
    from tools.build_hia_cli_verified_report_bundle import build_development
    manifest = build_development(directory / 'six-image-bundle', Path(B3['path']))
    raw = Path(manifest).read_bytes()
    value = json_bytes(raw)
    components = ('control', 'format', 'discovery', 'routing', 'parser_context', 'verified_report')
    children = {}
    for name in components:
        path = Path(manifest).parent / value[name + '_manifest']
        child_raw = path.read_bytes()
        require(hashlib.sha256(child_raw).hexdigest() == value[name + '_manifest_sha256'],
                'real companion manifest changed')
        child = json_bytes(child_raw)
        image = path.parent / child['image_path']
        image_raw = image.read_bytes()
        require(0 < len(image_raw) <= CAPACITY and child['compiler_sha256'] == B3['sha256']
                and hashlib.sha256(image_raw).hexdigest() == child['image_sha256'],
                'real companion image/compiler differs')
        children[name] = {'manifest': str(path), 'manifest_pin': pin(child_raw),
                          'image': str(image), 'image_pin': pin(image_raw)}
    # The real loader, including the fixed optional-profile host pins, is used
    # by each test child. No invented cold record is created for this build.
    report = {'manifest': str(manifest), 'manifest_pin': pin(raw), 'children': children,
              'compiler': B3, 'six_real_compilations': True, 'matching_current_cold': False}
    publish(directory / 'BUILD.json', report)
    return report

def build_patch(plan, directory):
    from tools.build_hia_patch_result import build_development
    output = directory / 'patch'
    manifest = build_development(output, Path(B3['path']), compiler_sha256=B3['sha256'])
    actual = decode(checked(capture(output / 'BUILD.json')))
    require(actual['status'] == 'BUILT_AND_READ_BACK'
            and actual['compile_seconds'] == 20 and actual['cpu_seconds'] == 10
            and actual['output_capacity'] == actual['workspace_capacity'] == CAPACITY
            and actual['full_compile_workspace_observed'] is False
            and actual['manifest'] == str(manifest), 'actual Patch build receipt differs')
    report = {'manifest': str(manifest), 'actual_build': actual,
              'default_compile_receipt_is_not_a_full_workspace_observation': True,
              'matching_current_cold': False}
    publish(directory / 'BUILD.json', report)
    return report


def child(request_path, request_sha256):
    global B3
    raw = checked(capture(Path(request_path), maximum=8 << 20))
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'build request differs')
    request = decode(raw)
    plan = decode(checked(request['plan']))
    require(plan['schema'] == SCHEMA and plan['state'] == 'BOUND_AWAITING_ROOT_AUTHORIZATION'
            and request['schema'] == SCHEMA + '.build-request' and request['limits'] == LIMITS,
            'unbound/changed build request')
    group = request['group']; directory = Path(request['directory'])
    require(group in ('build-report-six','build-inspect','build-patch')
            and directory.parent == Path(plan['attempt']) and directory.is_dir(),
            'one explicitly owned build stage required')
    result = {'status':'FAIL', 'group':group, 'request_pin':pin(raw),
              'current_cold':False, 'whole':False, 'all_compile_workspaces_observed':False}
    guard = None
    try:
        require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3,14,4)
                and sys.flags.isolated and sys.flags.dont_write_bytecode, 'actual 3.14.4 -I -B required')
        control_guard(plan)
        require(Path(__file__).absolute() == Path(plan['controls']['run_build_child.py']['path']),
                'actual build child not bound')
        result['source_before'] = source_guard(plan, observer)
        runtime, _ = import_runtime(plan); guard = runtime.guard_runtime_context
        guard(plan['runtime'])
        B3 = {'path':plan['compiler']['path'], **plan['compiler']['pin']}
        checked(plan['compiler'])
        result['build'] = {'build-report-six':build_report, 'build-inspect':build_inspect,
                           'build-patch':build_patch}[group](plan, directory)
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        errors = []
        for name in ('source','controls','runtime','compiler'):
            try:
                if name == 'source':
                    result['source_after'] = source_guard(plan, observer)
                    require(result['source_after'] == result.get('source_before'), 'terminal source differs')
                elif name == 'controls': control_guard(plan)
                elif name == 'compiler': checked(plan['compiler'])
                else:
                    require(guard is not None, 'runtime was never admitted')
                    guard(plan['runtime'])
            except BaseException:
                errors.append({'guard':name,'traceback':traceback.format_exc()})
        if errors: result.update(status='FAIL', terminal_guard_errors=errors)
        try: publish(directory / 'RESULT.json', result)
        except BaseException:
            result.update(status='FAIL', publication_error=traceback.format_exc())
            sys.stderr.write(encoded(result).decode()); sys.stderr.flush()
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    raise SystemExit(child(args.request, args.request_sha256))
