"""Exact input and observation custody for the discovery JSON owner.

This is hosted qualification machinery, not part of JSON runtime policy.
No synthetic report, stale source map, or development image grants cold status.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1048576
OWNER_FILES = (
    'hepta/hia_cli_discovery_json_native.py',
    'hepta/hia_cli_discovery_selection.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_cli_native.py',
    'tools/qualify_hia_cli_discovery_callers.py',
    'tests/test_hia_cli_discovery_selection.py',
    'tests/fixtures/hia_cli_discovery_0daf_baseline.json',
    'tests/fixtures/hia_cli_discovery_r20_import.json',
    'tools/build_hia_cli_native.py',
    'tools/generate_hia_cli_control.py',
    'tools/hia_cli_control_phases.py',
    'tools/generate_hia_cli_format.py',
    'tools/hia_cli_unicode_tables.json',
    'examples/hia_bootstrap/cli_control.hepta',
    'examples/hia_bootstrap/cli_format.hepta',
    'tests/test_hia_cli_native.py',
    'tools/run_hia_unittest_gate.py',
    'tools/generate_hia_cli_discovery_json.py',
    'tools/build_hia_cli_discovery_json.py',
    'tools/hia_cli_discovery_custody.py',
    'tools/hia_cli_discovery_controls.py',
    'tools/hia_cli_discovery_child.py',
    'tools/qualify_hia_cli_discovery_json.py',
    'tests/test_hia_cli_discovery_json.py',
    'tests/fixtures/hia_cli_discovery_r5_cases.json',
    'docs/HIA_CLI_DISCOVERY_JSON.md',
    'examples/hia_bootstrap/cli_discovery_json.hepta',
    'hepta/cli.py', 'hepta/hia_opcodes.py', 'hepta/hia_schema.py',
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_agent_assembly.py', 'hepta/hia_program_runtime.py',
    'tools/generate_hia_selfhost.py', 'tools/generate_hia_sha256.py',
    'tools/build_hia_json_preflight.py', 'tools/build_hia_nominal_json.py',
    'tools/hia_selfhost_contract.py', 'tools/qualify_hia_selfhost.py',
    'tools/hia_selfhost_child.py', 'tools/hia_selfhost_process_owner.py',
)


def require(value, message):
    if not value:
        raise ValueError(message)


def read_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate discovery custody field')
            result[key] = value
        return result
    def constant(_value):
        raise ValueError('nonfinite discovery custody field')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def publish(path, value):
    raw = encoded(value)
    with Path(path).open('xb') as stream:
        stream.write(raw)
        stream.flush()
    require(Path(path).read_bytes() == raw, 'discovery custody publication differs')


def binding(path):
    path = Path(path).absolute()
    observed = path.lstat()
    require(stat.S_ISREG(observed.st_mode), 'regular discovery custody input required')
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'mode': stat.S_IMODE(observed.st_mode)}


def check_bindings(values):
    require(type(values) is list and values, 'complete discovery input bindings required')
    paths = []
    for item in values:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256', 'mode'}
                and type(item['path']) is str and Path(item['path']).is_absolute()
                and type(item['bytes']) is int and type(item['mode']) is int,
                'invalid discovery input binding')
        require(binding(item['path']) == item, 'discovery input changed: ' + item['path'])
        paths.append(item['path'])
    require(len(paths) == len(set(paths)), 'duplicate discovery input binding')


def owner_sources():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in OWNER_FILES}


def require_owner_sources(sources):
    require(type(sources) is dict, 'complete source map required')
    for name, digest in owner_sources().items():
        require(sources.get(name) == digest, 'discovery input missing or changed in cold closure: ' + name)


def admit_cold(cold_report):
    from tools.build_hia_json_preflight import admit_cold_build
    path = Path(cold_report).resolve(strict=True)
    raw = path.read_bytes()
    outer = read_json(raw)
    require(type(outer) is dict and outer.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
            and outer.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
            and type(outer.get('returncode')) is int and outer['returncode'] == 0,
            'completed matching cold replay required')
    require(type(outer.get('qualification_wall_limit_seconds')) is int
            and outer['qualification_wall_limit_seconds'] == 180
            and type(outer.get('cleanup_wall_limit_seconds')) is int
            and outer['cleanup_wall_limit_seconds'] == 3, 'original cold limits must remain 180+3')
    owner = outer.get('process_owner')
    require(type(owner) is dict and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(owner.get('returncode')) is int and owner['returncode'] == 0
            and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == 180
            and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == 3
            and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
            and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True
            and owner['cleanup'].get('observed_echild') is True,
            'actual cold owner completion and complete cleanup required')
    require(type(outer.get('nested_report')) is str and outer['nested_report']
            and type(outer.get('nested_report_sha256')) is str, 'nested cold report binding required')
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes()
    require(sha256(nested_raw).hexdigest() == outer['nested_report_sha256'], 'nested cold report changed')
    nested = read_json(nested_raw)
    require(type(nested) is dict and nested.get('schema') == 'hepta.hia.selfhost-qualification.v6'
            and nested.get('status') == 'SELF_HOSTED_FIXED_CORE_PASS'
            and type(nested.get('checks')) is dict and nested['checks']
            and all(value is True for value in nested['checks'].values()), 'nested cold qualification failed')
    generations = nested.get('generations')
    require(type(generations) is list and len(generations) == 3
            and all(type(row) is dict and type(row.get('produced_image')) is str for row in generations),
            'three actual cold generation images required')
    paths = [Path(row['produced_image']).resolve(strict=True) for row in generations]
    images = [image.read_bytes() for image in paths]
    hashes = [sha256(image).hexdigest() for image in images]
    require([row.get('produced_sha256') for row in generations] == hashes
            == outer.get('generation_sha256') and len(set(hashes)) == 1
            and all(image and len(image) <= CAPACITY for image in images)
            and all(type(row.get('produced_bytes')) is int and row['produced_bytes'] == len(image)
                    for row, image in zip(generations, images)), 'cold generation bytes differ')
    sources = admit_cold_build(images[-1], raw)
    require(nested.get('source_manifest') == sources and nested.get('profile') == outer.get('profile'),
            'cold nested and outer source/profile identities differ')
    require_owner_sources(sources)
    authority = {'cold_report': str(path), 'cold_report_sha256': sha256(raw).hexdigest(),
                 'compiler': str(paths[-1]), 'compiler_sha256': hashes[-1],
                 'source_manifest': sources,
                 'input_bindings': [binding(p) for p in dict.fromkeys((path, nested_path, *paths))]}
    guard_authority(authority)
    return authority


def guard_authority(authority):
    from tools.build_hia_json_preflight import current_sources
    check_bindings(authority['input_bindings'])
    require(current_sources() == authority['source_manifest'], 'complete current cold source map changed')
    require_owner_sources(authority['source_manifest'])


def admit_child_output(receipt, stdout, stderr):
    """Bind producer-added receipt fields to the exact actual child JSON."""
    host = {'artifact_sha256', 'case', 'format', 'input_bytes', 'input_sha256',
            'produced_bytes', 'produced_image', 'produced_sha256', 'runner_sha256', 'wall_elapsed_ns'}
    fields = {'abi_status', 'core_u32', 'forbidden_compiler_modules_loaded', 'image_sha256',
              'limits', 'loader_operations', 'native_elapsed_ns', 'output_sha256', 'output_unchanged',
              'result_u64', 'return_encoding', 'source_sha256', 'source_unchanged', 'status',
              'workspace_header'}
    child = read_json(stdout)
    require(type(child) is dict and set(child) == fields and type(receipt) is dict
            and set(receipt) == fields | host and stderr == b''
            and encoded(child) == encoded({key: receipt[key] for key in fields}),
            'actual child stdout/stderr does not match the discovery receipt')
    return child


# R20 receipt admission retained locally; no change to the baseline compiler.
def _compile_observation_size(result, output, *, image_format, compiler_sha256,
                              source_sha256, input_bytes):
    """Admit the existing child's byte ABI without importing a later builder.

    Seed images retain their packed return convention; linked self-host and
    flat images retain their zero-extended convention. A successful compile
    has zero status and the exact same positive u32 length in both views.
    This does not change the child, its limits, or the returned receipt schema.
    """
    encodings = {"seed-shared": "packed-ABI-status-and-u32",
                 "flat-x86-64": "zero-extended-u32",
                 "linked-selfhost": "zero-extended-u32"}
    if type(result) is not dict or type(output) is not bytes or image_format not in encodings:
        return None
    size = result.get("core_u32")
    limits = result.get("limits")
    if (result.get("status") != "returned"
            or type(result.get("abi_status")) is not int or result["abi_status"] != 0
            or type(size) is not int or not 0 < size <= CAPACITY
            or type(result.get("result_u64")) is not int or result["result_u64"] != size
            or result.get("format") != image_format
            or result.get("return_encoding") != encodings[image_format]
            or result.get("source_unchanged") is not True
            or type(result.get("forbidden_compiler_modules_loaded")) is not list
            or result["forbidden_compiler_modules_loaded"] != []
            or result.get("image_sha256") != compiler_sha256
            or result.get("artifact_sha256") != compiler_sha256
            or result.get("source_sha256") != source_sha256
            or result.get("input_sha256") != source_sha256
            or type(result.get("input_bytes")) is not int or result["input_bytes"] != input_bytes
            or len(output) != CAPACITY or result.get("output_sha256") != sha256(output).hexdigest()
            or type(limits) is not dict
            or type(limits.get("output_capacity")) is not int or limits["output_capacity"] != CAPACITY
            or type(limits.get("workspace_bytes")) is not int or limits["workspace_bytes"] != CAPACITY):
        return None
    return size


def admit_compilation(directory, label, compiler, source, image):
    """Read the real child request, receipt, full 1 MiB output and executable."""
    from tools.build_hia_nominal_json import admit_compile_receipt
    from tools.qualify_hia_selfhost import CHILD
    directory, compiler, image = Path(directory), Path(compiler), Path(image)
    compiler_bytes, image_bytes = compiler.read_bytes(), image.read_bytes()
    receipt_path = directory / (label + '.receipt.json')
    request_path = directory / (label + '.request.json')
    receipt, request = read_json(receipt_path.read_bytes()), read_json(request_path.read_bytes())
    admit_child_output(receipt, (directory / (label + '.stdout.log')).read_bytes(),
                       (directory / (label + '.stderr.log')).read_bytes())
    input_path, output_path = directory / (label + '.input.bin'), directory / (label + '.output.bin')
    output = output_path.read_bytes()
    require(type(request) is dict and set(request) == {'capacity', 'format', 'image', 'image_sha256',
                'output', 'source', 'source_sha256', 'workspace_fill', 'workspace_size'}
            and request['image'] == str(compiler.resolve())
            and request['image_sha256'] == sha256(compiler_bytes).hexdigest()
            and request['source'] == str(input_path.resolve()) and input_path.read_bytes() == source
            and request['source_sha256'] == sha256(source).hexdigest()
            and request['output'] == str(output_path.resolve()) and request['format'] == 'flat-x86-64'
            and type(request['capacity']) is int and request['capacity'] == CAPACITY
            and type(request['workspace_size']) is int and request['workspace_size'] == CAPACITY
            and type(request['workspace_fill']) is int and request['workspace_fill'] == 0,
            'actual discovery compiler request differs')
    size = _compile_observation_size(receipt, output, image_format='flat-x86-64',
            compiler_sha256=sha256(compiler_bytes).hexdigest(), source_sha256=sha256(source).hexdigest(),
            input_bytes=len(source))
    require(size is not None and len(output) == CAPACITY and output[:size] == image_bytes
            and receipt.get('case') == label and receipt.get('runner_sha256') == sha256(CHILD.read_bytes()).hexdigest()
            and receipt.get('produced_image') == str(image), 'actual compiler output binding differs')
    limits = receipt.get('limits')
    expected = {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                'output_capacity': CAPACITY, 'stack_bytes': 8388608, 'workspace_bytes': CAPACITY}
    require(limits == expected and limits['core_dumpable'] is False
            and all(type(limits[name]) is int for name in limits if name != 'core_dumpable'),
            'original compiler child limits changed')
    admit_compile_receipt(receipt, compiler_bytes=compiler_bytes, source_bytes=source, image_bytes=image_bytes)
    files = [compiler, image, input_path, output_path, receipt_path, request_path,
             directory / (label + '.stdout.log'), directory / (label + '.stderr.log')]
    return receipt, [binding(p) for p in files]
