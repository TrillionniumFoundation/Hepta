"""Execute the byte-pinned v8 catalog baseline separately from today's v9 API.

Only archived HIA images run for the historical CLI. The unchanged original
methods retain their v8 default, v9 refusal, VM bound and 20-second native budget.
This is a compatibility oracle, never an ordinary release provider.
"""
from __future__ import annotations
import ast
import base64
import builtins
from hashlib import sha1, sha256
import io
import json
from pathlib import Path
import struct
import subprocess
import textwrap
from types import SimpleNamespace
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_agent_stdio_catalog_v8.json'
FIXTURE_SHA256 = 'a845fc58edc1e0b9f42d498754d4d59b66f54db097ddb7bf2dda1858619c43d2'
BASE_COMMIT = '699f0607118b56af57abbefe22f341c84f9d024d'
SOURCES = (
    'tools/generate_hia_agent_stdio.py',
    'examples/hia_bootstrap/agent_stdio_dispatch.hepta',
    'examples/hia_bootstrap/agent_stdio_packer.hepta',
    'examples/hia_bootstrap/core_json_frontend.hepta',
    'tests/test_hia_agent_stdio.py',
)
NATIVE_METHOD = 'test_catalog_matches_all_hosted_versions_under_empty_path'
VM_METHOD = 'test_catalog_short_output_and_invalid_table_do_not_publish'


def archived():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('archived v8 stdio catalog fixture changed')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.agent-stdio-catalog-v8-history.v1'
            or value['base_commit'] != BASE_COMMIT
            or set(value['sources']) != set(SOURCES)
            or value['original_native_calls'] != 19
            or value['original_runtime_timeout_seconds'] != 20
            or value['original_VM_max_steps'] != 4000000):
        raise ValueError('archived v8 stdio catalog identity differs')
    decoded = {}
    for name in SOURCES:
        row = value['sources'][name]
        data = zlib.decompress(base64.b64decode(row['data'], validate=True))
        blob = sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if (len(data) != row['bytes'] or sha256(data).hexdigest() != row['sha256']
                or blob != row['git_blob']):
            raise ValueError('archived v8 stdio source changed: ' + name)
        decoded[name] = data
    from tools.hia_cli_discovery_compat import legacy_catalog_owner, word_original_source
    for name, pin in value['oracle_sha256'].items():
        if sha256(word_original_source(name)).hexdigest() != pin:
            raise ValueError('independent v8 schema/catalog source differs')
    return value, decoded, legacy_catalog_owner()


def original_function(raw, owner, name):
    source = raw.decode()
    body = ast.parse(source).body
    if owner:
        classes = [node for node in body if isinstance(node, ast.ClassDef) and node.name == owner]
        if len(classes) != 1:
            raise ValueError('archived test class identity differs')
        body = classes[0].body
    functions = [node for node in body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(functions) != 1:
        raise ValueError('archived function identity differs: ' + name)
    return textwrap.dedent(ast.get_source_segment(source, functions[0])) + '\n'


def run_catalog_v8_baseline(output, compiler):
    """Run the original VM method and all 19 native catalog calls on v8 HIA."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import execute_program
    from tools.qualify_hia_selfhost import compile_stage, invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable

    output, compiler = Path(output), Path(compiler)
    output.mkdir(mode=0o700)
    metadata, sources, oracle = archived()
    compiler_bytes = compiler.read_bytes()
    snapshot = {name: row['sha256'] for name, row in metadata['sources'].items()}
    (output / 'original-sources.json').write_text(json.dumps({
        'fixture_sha256': FIXTURE_SHA256, 'base_commit': BASE_COMMIT,
        'source_sha256': snapshot, 'method_sha256': metadata['method_sha256'],
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'historical_scope_only': True, 'matching_current_production_claimed': False,
    }, indent=2, sort_keys=True) + '\n')
    paths = {}
    for name, raw in sources.items():
        if name.endswith('.hepta'):
            target = output / Path(name).name
            target.write_bytes(raw)
            target.chmod(0o400)
            paths[name] = target

    original_import = builtins.__import__
    imports = []
    def frozen_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'hepta.hia_opcodes' and level == 0:
            if fromlist != ('opcode_catalog',):
                raise ValueError('archived catalog test imported an unexpected oracle')
            imports.append((name, fromlist))
            return oracle
        return original_import(name, globals, locals, fromlist, level)

    calls = []
    def observed_run(*args, **kwargs):
        if kwargs.get('timeout') != 20 or kwargs.get('env') != {'PATH': '', 'LANG': 'C'}:
            raise ValueError('original native catalog limits changed')
        result = subprocess.run(*args, **kwargs)
        calls.append({'argv': list(map(str, args[0])), 'returncode': result.returncode,
            'stdout_bytes': len(result.stdout), 'stdout_sha256': sha256(result.stdout).hexdigest(),
            'stderr_bytes': len(result.stderr), 'stderr_sha256': sha256(result.stderr).hexdigest(),
            'timeout_seconds': kwargs['timeout']})
        return result

    namespace = {'__builtins__': {**vars(builtins), '__import__': frozen_import},
        'json': json, 'struct': struct, 'subprocess': SimpleNamespace(run=observed_run),
        'DISPATCH': paths['examples/hia_bootstrap/agent_stdio_dispatch.hepta'],
        'assemble_program': assemble_program, 'execute_program': execute_program}
    test_raw = sources['tests/test_hia_agent_stdio.py']
    for owner, name in ((None, 'vm_window'), ('AgentStdioNativeTests', 'invoke'),
                        ('AgentStdioSourceTests', VM_METHOD), ('AgentStdioNativeTests', NATIVE_METHOD)):
        text = original_function(test_raw, owner, name)
        if name in (VM_METHOD, NATIVE_METHOD):
            if sha256(text.encode()).hexdigest() != metadata['method_sha256'][owner + '.' + name]:
                raise ValueError('archived test method changed')
        exec(compile(text, '<pinned-v8-stdio-' + name + '>', 'exec'), namespace)

    def run_case(kind, method, attributes):
        case_type = type(kind, (unittest.TestCase,), {method: namespace[method], **attributes})
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(case_type(method))
        (output / (kind + '.log')).write_text(stream.getvalue())
        if (result.testsRun != 1 or not result.wasSuccessful() or result.skipped
                or result.expectedFailures or result.unexpectedSuccesses):
            raise AssertionError('frozen v8 baseline failed:\n' + stream.getvalue())

    # Original three VM output/canary/refusal controls precede compiling and
    # entering these archived HIA components natively.
    run_case('FrozenV8CatalogVM', VM_METHOD, {})
    generation, images = {}, {}
    for label, name in (('dispatch', 'agent_stdio_dispatch'),
                        ('frontend', 'core_json_frontend'), ('packer', 'agent_stdio_packer')):
        image, receipt = compile_stage(output, 'v8-' + label, compiler,
            sources['examples/hia_bootstrap/' + name + '.hepta'])
        images[label] = image
        generation[label] = receipt

    # The pinned recipe helpers use only the independently restored pre-v9
    # schema/opcode module; current catalog bytes never seed this table.
    recipe_namespace = {'json': json, 'struct': struct,
        'opcode_catalog': oracle.opcode_catalog, 'PRIMITIVE_PROFILES': oracle.PRIMITIVE_PROFILES}
    author = sources['tools/generate_hia_agent_stdio.py']
    for name in ('catalog_pieces', 'pack_catalog_recipes', 'catalog_table'):
        exec(compile(original_function(author, None, name),
                     '<pinned-v8-stdio-' + name + '>', 'exec'), recipe_namespace)
    catalog = recipe_namespace['catalog_table']()
    (output / 'original-catalog-table.bin').write_bytes(catalog)
    products, pack_receipts = {}, {}
    dispatch, frontend = images['dispatch'].read_bytes(), images['frontend'].read_bytes()
    for profile, kind in enumerate(('flat', 'elf', 'exec')):
        payload = struct.pack('<6Q', int.from_bytes(b'HIAAGNT2', 'little'),
            len(dispatch), len(frontend), len(compiler_bytes), profile, len(catalog))
        payload += dispatch + frontend + compiler_bytes + catalog
        receipt, raw = invoke(output, 'v8-pack-' + kind, images['packer'], payload)
        count = receipt.get('core_u32')
        if (receipt.get('status') != 'returned' or type(count) is not int
                or not 0 < count <= len(raw)):
            raise ValueError('historical v8 native packer refused')
        binary = raw[:count]
        inspect_executable(binary)
        if not binary.endswith(catalog):
            raise ValueError('historical native catalog table changed in its ELF')
        target = output / ('hia-native-v8-' + kind)
        target.write_bytes(binary)
        target.chmod(0o500)
        products[kind] = target
        pack_receipts[kind] = receipt

    run_case('FrozenV8CatalogNative', NATIVE_METHOD,
        {'invoke': namespace['invoke'], 'executables': products})
    if len(calls) != 19 or imports != [('hepta.hia_opcodes', ('opcode_catalog',))]:
        raise ValueError('complete frozen v8 native call plan changed')
    if compiler.read_bytes() != compiler_bytes:
        raise ValueError('historical control compiler changed')
    for name, path in paths.items():
        if path.read_bytes() != sources[name]:
            raise ValueError('historical HIA source changed during control')
    report = {
        'schema': 'hepta.hia.agent-stdio-catalog-v8-observations.v1',
        'status': 'ORIGINAL_V8_CATALOG_PASS', 'base_commit': BASE_COMMIT,
        'fixture_sha256': FIXTURE_SHA256, 'source_sha256': snapshot,
        'method_sha256': metadata['method_sha256'],
        'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'original_VM_controls': 3, 'original_VM_max_steps': 4000000,
        'original_native_methods': 1, 'original_native_calls': len(calls),
        'original_runtime_timeout_seconds': 20, 'calls': calls,
        'catalog_table_sha256': sha256(catalog).hexdigest(),
        'compile_receipts': generation, 'pack_receipts': pack_receipts,
        'executables': {kind: {'path': str(path), 'sha256': sha256(path.read_bytes()).hexdigest()}
                        for kind, path in products.items()},
        'original_default': 8, 'original_explicit_v9': 'usage-refused',
        'current_v9_default_tested_separately': True,
        'matching_current_production_claimed': False,
    }
    (output / 'history.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report
