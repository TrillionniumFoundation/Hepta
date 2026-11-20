"""Independently read back the complete v6 kernel campaign or audit its protocol.

Protocol audit emits object candidates in memory; it executes no native kernel,
driver, linker, solver or source-controlled benchmark function. A raw RESULT
readback additionally requires its original sidecar files. A public projection
can be checked without those bytes, and the output explicitly records that
lesser scope. This tool never changes the supplied source or evidence files.
Raw readback also reopens the compiler, linker and libc paths recorded by the
campaign; run it on that host while those exact tool/runtime files remain
available. Relocating --root or --evidence-dir does not relax those identities.

This reader is deliberately protocol-v6-specific: 763 cases, 21 samples per
case, 807 successful command receipts, 33 binaries and 18 wide builds with 356
proof queries. It retains every one of v5's 671 case bindings and 14 wide object
and final-image identities, anchored to the exact historical public artifact.
The existing C/Rust/runtime sources, build flags and tool/runtime identities
remain fixed. A changed inventory is a new protocol and needs a new reader;
these limits are not silently inferred from a candidate's self-reported counts.

Examples, using only caller-selected paths:
    python -B tools/read_hia_verified_kernel_campaign_v6.py --root . --protocol-only
    python -B tools/read_hia_verified_kernel_campaign_v6.py --root SOURCE_CHECKOUT \
        --result EVIDENCE/RESULT.json --expected-commit EXACT_COMMIT
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import gzip
from hashlib import sha256
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys


PREVIOUS_RELATIVE = 'benchmarks/hia_verified_kernels/results/ai395-20261120-bounded.json.gz'
PREVIOUS_GZIP_SHA256 = '1f6745da0821ed7a64c2b84add4344947a80d9ce3bc4ef9c6bc26de5c1233ee9'
PREVIOUS_JSON_SHA256 = '968dbe823b86968c21fbec3e218a55b8597a1fd6f0759b7dd77ac357f2623e30'
FIXED_SOURCES = ('driver.c', 'reference.c', 'reference.rs', 'runtime_identity.c')
LENGTHS = [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
           255, 256, 257, 4095, 4096, 4097, 65535, 65536]
MASK = (1 << 64) - 1
SEED = 0x123456789abcdef
KIND_FOR_MODE = {'sum': 'sum_u8', 'zero': 'all_zero_u8', 'copy': 'copy_u8'}
SINGLE_BYTE_OBLIGATIONS = {'decoded_single_byte_entry_partition',
                           'single_byte_access_bounds',
                           'single_byte_result_and_register_frame'}
Z3_BINDING_FILES = {'__init__.py', 'z3.py', 'z3consts.py', 'z3core.py', 'z3num.py',
                    'z3poly.py', 'z3printer.py', 'z3rcf.py', 'z3types.py', 'z3util.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def require_identity_inventory(identity, required, description):
    require(isinstance(identity, dict) and set(required) <= set(identity),
            description + ' is missing required source identities')
    for name, value in identity.items():
        require(isinstance(name, str) and isinstance(value, str) and
                re.fullmatch('[0-9a-f]{64}', value) is not None,
                description + ' has an invalid source digest')


def validate_solver_identity(root, solver, previous, *, public, solver_library=None):
    """Retain the four old hashes and require the new executed-code binding."""
    old_fields = {'name', 'version', 'binding_sha256', 'library_sha256'}
    require(set(solver) == old_fields | {'load_binding'}, 'unexpected solver identity inventory')
    require(all(solver[field] == previous[field] for field in old_fields),
            'pinned solver implementation identity changed')
    binding = solver['load_binding']
    require(set(binding) == {'profile', 'controlled_import', 'binding_code_matches_source',
                            'binding_files', 'monitor_sha256', 'preloaded_solver_authorized', 'library'},
            'incomplete loaded solver identity inventory')
    require(binding['profile'] == 'hia.loaded-z3.python-source-and-library.linux.v1' and
            binding['controlled_import'] is True and binding['binding_code_matches_source'] is True and
            binding['preloaded_solver_authorized'] is False,
            'solver did not establish controlled executed-source admission')
    files = binding['binding_files']
    require_identity_inventory(files, Z3_BINDING_FILES, 'executed Z3 Python modules')
    require(set(files) == Z3_BINDING_FILES, 'unexpected executed Z3 Python module inventory')
    require(binding['monitor_sha256'] == digest(root / 'hepta/hia_solver_identity.py'),
            'solver loaded-identity monitor source differs')
    library = binding['library']
    require(set(library) == {'device_major', 'device_minor', 'inode', 'source_size', 'anchor_symbol',
                            'mapped_executable_segments', 'file_identity_rechecked', 'loaded_mapping_bound'},
            'incomplete solver library mapping identity')
    require(all(type(library[field]) is int and library[field] >= 0 for field in ('device_major', 'device_minor')) and
            all(type(library[field]) is int and library[field] > 0
                for field in ('inode', 'source_size', 'mapped_executable_segments')) and
            library['source_size'] <= 128 * 1024 * 1024 and library['anchor_symbol'] == 'Z3_get_version' and
            library['file_identity_rechecked'] is True and library['loaded_mapping_bound'] is True,
            'invalid solver library mapping admission')
    if public:
        return
    # Finding the top-level spec does not import/execute Z3. This reader must
    # never preload the solver ahead of the package's controlled admission.
    spec = importlib.util.find_spec('z3')
    require(spec is not None and spec.origin is not None, 'cannot locate the retained Z3 source package')
    package = Path(spec.origin).resolve(strict=True).parent
    require({p.name for p in package.glob('*.py')} == Z3_BINDING_FILES, 'actual Z3 Python source inventory differs')
    aggregate = sha256()
    for name in sorted(Z3_BINDING_FILES):
        raw = (package / name).read_bytes()
        require(sha256(raw).hexdigest() == files[name], 'actual executed Z3 source differs: ' + name)
        aggregate.update(name.encode() + b'\0' + raw + b'\0')
    require(aggregate.hexdigest() == solver['binding_sha256'], 'actual Z3 binding aggregate differs')
    def matches(path):
        value = path.stat()
        return (os.major(value.st_dev), os.minor(value.st_dev), value.st_ino, value.st_size) == (
            library['device_major'], library['device_minor'], library['inode'], library['source_size'])
    if solver_library is not None:
        actual = Path(solver_library).resolve(strict=True)
        require(matches(actual), 'explicit solver library is not the recorded original file identity')
    else:
        candidates = {p.resolve() for p in package.rglob('*') if p.is_file() and matches(p)}
        require(len(candidates) == 1,
                'recorded solver library is not uniquely present in the package; supply its original --solver-library path')
        actual = candidates.pop()
    require(digest(actual) == solver['library_sha256'], 'actual mapped solver library bytes differ')


def read_json(path):
    data = path.read_bytes()
    if data.startswith(b'\x1f\x8b'):
        data = gzip.decompress(data)
    return json.loads(data), data


def relative_file(root, name):
    path = Path(name)
    require(not path.is_absolute() and all(p not in ('.', '..') for p in path.parts),
            'expected a relative artifact path: ' + name)
    result = root / path
    require(result.is_file(), 'missing required file: ' + name)
    return result


def expected_cases(protocol):
    """Independent construction, without evaluating the harness case loop."""
    cases = [('scalar', arm, 0) for arm in ('scalar-direct', 'scalar-verified', 'c', 'rust')]
    for mode in ('sum', 'zero', 'copy'):
        for length in protocol['lengths']:
            cases += [(mode, arm, length) for arm in ('verified-sse2-64', 'verified-sse2-16',
                        'verified-avx2-128', 'verified-avx512-256')]
            if mode == 'copy':
                cases += [(mode, 'verified-' + isa + '-copy-byte-tail', length) for isa in ('avx2', 'avx512')]
            cases += [(mode, 'verified-' + isa + ('-copy-endpoints-fast' if mode == 'copy' else '-bounded-tail'),
                       length) for isa in ('avx2', 'avx512')]
            if mode != 'copy':
                cases += [(mode, 'verified-' + isa + '-bounded-one', length) for isa in ('avx2', 'avx512')]
            cases += [(mode, arm, length) for arm in ('direct-packed-u32', 'c', 'rust')]
    require(len(cases) == len(set(cases)) == 763, 'independent v6 case inventory differs')
    return cases


def expected_binding(key):
    mode, arm, _ = key
    if arm in ('c', 'rust'):
        return 'reference-' + arm + '.so', 'reference_madd' if mode == 'scalar' else 'reference_' + mode
    if mode == 'scalar':
        require(arm in ('scalar-direct', 'scalar-verified'), 'unknown scalar arm')
        return arm + '.so', 'multiply_add'
    kind = KIND_FOR_MODE[mode]
    if arm == 'direct-packed-u32':
        return kind + '-direct-packed-u32.so', 'calculate'
    if arm == 'verified-sse2-64':
        return kind + '.so', 'calculate'
    if arm == 'verified-sse2-16':
        return kind + '-sse2-16.so', 'calculate'
    for isa, width in (('avx2', 128), ('avx512', 256)):
        if arm == 'verified-' + isa + '-' + str(width):
            return kind + '-' + isa + '-' + str(width) + '.so', 'calculate'
        for arm_suffix, library_suffix in (('-copy-byte-tail', '-byte-tail'),
                                            ('-copy-endpoints-fast', '-endpoints-fast'),
                                            ('-bounded-tail', '-bounded-tail'),
                                            ('-bounded-one', '-bounded-one')):
            if arm == 'verified-' + isa + arm_suffix:
                require((mode == 'copy') == arm_suffix.startswith('-copy-'), 'wrong workload/profile binding')
                return kind + '-' + isa + '-' + str(width) + library_suffix + '.so', 'calculate'
    raise ValueError('unknown span arm: ' + arm)


def expected_wide_profiles():
    result = {}
    for isa, width in (('avx2', 128), ('avx512', 256)):
        for kind in ('sum_u8', 'all_zero_u8', 'copy_u8'):
            root = kind + '-' + isa + '-' + str(width)
            copy = kind == 'copy_u8'
            result[root] = (isa, kind, 'endpoints' if copy else None, None if copy else 'byte',
                            (21 if isa == 'avx2' else 23) if copy else 14)
            suffix = '-endpoints-fast' if copy else '-bounded-tail'
            result[root + suffix] = (isa, kind, 'endpoints-fast' if copy else None, None if copy else 'bounded',
                                     (21 if isa == 'avx2' else 23) if copy else 22)
            if not copy:
                result[root + '-bounded-one'] = (isa, kind, None, 'bounded-one', 25)
        result['copy_u8-' + isa + '-' + str(width) + '-byte-tail'] = (isa, 'copy_u8', 'byte', None, 12)
    require(len(result) == 18 and sum(row[-1] for row in result.values()) == 356, 'wide inventory arithmetic differs')
    return result


def fixed_build_commands(protocol):
    return {
        'build-driver': ['tool:cc', '-O3', '-std=c11', 'source/driver.c', '-ldl', '-o', 'evidence/driver'],
        'build-runtime-identity': ['tool:cc', '-O2', '-march=x86-64', '-std=c11',
                                   'source/runtime_identity.c', '-ldl', '-o', 'evidence/runtime-identity'],
        'build-c': ['tool:cc', *protocol['compiler_flags_c'], 'source/reference.c', '-o', 'evidence/reference-c.so'],
        'build-rust': ['tool:rustc', *protocol['compiler_flags_rust'], 'source/reference.rs', '-o', 'evidence/reference-rust.so'],
    }


def audit_fixed_build_commands(function, protocol):
    expected = fixed_build_commands(protocol)
    seen = {}
    namespace = {'tools': {'cc': 'tool:cc', 'rustc': 'tool:rustc'}, 'source': Path('source'),
                 'driver': Path('evidence/driver'), 'runtime_probe': Path('evidence/runtime-identity'),
                 'c_library': Path('evidence/reference-c.so'), 'rust_library': Path('evidence/reference-rust.so'),
                 'protocol': protocol, 'str': str, '__builtins__': {}}
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run'
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in expected):
            continue
        label = node.args[1].value
        require(label not in seen, 'duplicate fixed build command in harness: ' + label)
        expression = node.args[0]
        for child in ast.walk(expression):
            if isinstance(child, ast.Call):
                require(isinstance(child.func, ast.Name) and child.func.id == 'str',
                        'unexpected effect in fixed command expression')
        words = eval(compile(ast.Expression(body=deepcopy(expression)), '<audited-build-command>', 'eval'), namespace)
        seen[label] = [str(word) for word in words]
    require(seen == expected, 'actual fixed build flags or source/output choices differ')
    return seen


class RemoveConstructionWrites(ast.NodeTransformer):
    """Only strip the two observed construction-side effects; reject others."""
    def visit_Expr(self, node):
        call = node.value
        if isinstance(call, ast.Call):
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'mkdir':
                return None
            if isinstance(call.func, ast.Name) and call.func.id == 'save':
                return None
        raise ValueError('unexpected expression in construction audit: ' + ast.unparse(node))


def audit_protocol(root, previous):
    protocol_path = root / 'benchmarks/hia_verified_kernels/PROTOCOL.json'
    script = root / 'tools/benchmark_hia_verified_kernels.py'
    protocol = json.loads(protocol_path.read_text())
    require(protocol['schema'] == 'hepta.hia.verified-kernel-microbench.v6', 'v6 protocol required')
    require(protocol['cases'] == 763 and protocol['samples_per_case'] == 21, 'v6 sample count differs')
    require(protocol['lengths'] == LENGTHS, 'original complete length inventory changed')
    for name, value in previous['protocol'].items():
        if name not in ('schema', 'cases', 'simd_variants'):
            require(protocol[name] == value, 'original protocol setting changed: ' + name)
    for name, value in previous['protocol']['simd_variants'].items():
        require(protocol['simd_variants'].get(name) == value, 'original variant description changed: ' + name)
    require(set(protocol['simd_variants']) - set(previous['protocol']['simd_variants']) == {
        'verified-avx2-bounded-one', 'verified-avx512-bounded-one'}, 'unexpected added/removed v6 variants')
    fixed_hashes = {}
    for name in FIXED_SOURCES:
        relative = 'benchmarks/hia_verified_kernels/' + name
        fixed_hashes[relative] = digest(root / relative)
        require(fixed_hashes[relative] == previous['benchmark_source_sha256'][relative],
                'fixed driver/reference/runtime source changed: ' + relative)

    # These imports only generate candidate object bytes. They do not link,
    # solve, select host features or execute a native image.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    from hepta.hia_program import verify_program
    from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
    tree = ast.parse(script.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'benchmark')
    commands = audit_fixed_build_commands(function, protocol)
    body = next(n for n in function.body if isinstance(n, ast.Try)).body
    loops = [n for n in body if isinstance(n, ast.For) and isinstance(n.target, ast.Tuple)
             and all(isinstance(x, ast.Name) for x in n.target.elts)
             and [x.id for x in n.target.elts] == ['isa', 'width']]
    require(len(loops) == 4, 'expected four complete wide construction loops')
    profiles = {}

    def candidate_only(core, output, **options):
        require(options['strategy'] == 'simd', 'non-SIMD construction in wide audit')
        image = emit_verified_simd(core, isa=options['simd_isa'],
                                   copy_tail=options.get('simd_copy_tail'),
                                   reduce_tail=options.get('simd_reduce_tail'))
        label = output.stem
        require(label not in profiles, 'duplicate wide construction: ' + label)
        profiles[label] = {'object_sha256': sha256(image.object_bytes).hexdigest(),
                           'text_sha256': sha256(image.text_bytes).hexdigest(),
                           'copy_tail': image.copy_tail, 'reduce_tail': image.reduce_tail,
                           'explicit_copy_tail': options.get('simd_copy_tail'),
                           'explicit_reduce_tail': options.get('simd_reduce_tail')}
        return profiles[label]

    sources = {kind: verify_program(simd_kernel_program(kind)) for kind in KIND_FOR_MODE.values()}
    namespace = {'sources': sources, 'destination': Path('not-executed'), 'report': {'builds': {}},
                 'libraries': {}, 'build_verified_kernel': candidate_only}
    code = ast.Module(body=[RemoveConstructionWrites().visit(deepcopy(n)) for n in loops], type_ignores=[])
    exec(compile(ast.fix_missing_locations(code), str(script), 'exec'), namespace)
    expected_profiles = expected_wide_profiles()
    require(set(profiles) == set(expected_profiles), 'actual harness wide-build inventory differs')
    require(len(previous['wide_builds']) == 14, 'complete previous wide inventory missing')
    for label, old in previous['wide_builds'].items():
        for field in ('object_sha256', 'text_sha256'):
            require(profiles[label][field] == old[field], 'old wide bytes changed: ' + label + '/' + field)
    for label, (isa, kind, copy_tail, reduce_tail, _) in expected_profiles.items():
        expected = (copy_tail, reduce_tail)
        got = profiles[label]
        require((got['copy_tail'], got['reduce_tail']) == expected, 'selected profile differs: ' + label)
        require((got['explicit_copy_tail'], got['explicit_reduce_tail']) == expected,
                'harness must explicitly retain profile choices: ' + label)
    libraries = namespace['libraries']
    for name in ('scalar-direct', 'scalar-verified', *sources,
                 *(kind + '-sse2-16' for kind in sources)):
        libraries[name] = (Path('not-executed') / (name + '.so'),
                           'multiply_add' if name.startswith('scalar-') else 'calculate')
    namespace.update(protocol=protocol, c_library=Path('not-executed/reference-c.so'),
                     rust_library=Path('not-executed/reference-rust.so'),
                     direct_spans={kind: (Path('not-executed') / (kind + '-direct-packed-u32.so'), 'calculate')
                                   for kind in sources})
    start = next(i for i, n in enumerate(body) if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'cases')
    end = next(i for i in range(start, len(body)) if isinstance(body[i], ast.If)
               and 'len(cases)' in ast.unparse(body[i].test))
    exec(compile(ast.fix_missing_locations(ast.Module(body=deepcopy(body[start:end + 1]), type_ignores=[])),
                 str(script), 'exec'), namespace)
    actual = namespace['cases']
    ordered = expected_cases(protocol)
    require([(m, a, n) for m, a, p, symbol, n in actual] == ordered,
            'actual unshuffled cases differ from independent v6 construction')
    inventory = {(m, a, n): (p.name, symbol) for m, a, p, symbol, n in actual}
    require(len(actual) == len(inventory) == 763, 'duplicate or missing cases')
    for key, binding in inventory.items():
        require(binding == expected_binding(key), 'wrong case/library/symbol binding: ' + str(key))
    old_inventory = {(r['mode'], r['arm'], r['length']): (r['library'], r['symbol']) for r in previous['rows']}
    require(len(old_inventory) == 671 and old_inventory.keys() <= inventory.keys(), 'previous cases missing')
    for key, binding in old_inventory.items():
        require(inventory[key] == binding, 'previous library/symbol binding changed: ' + str(key))
    added = {(mode, 'verified-' + isa + '-bounded-one', n) for mode in ('sum', 'zero')
             for isa in ('avx2', 'avx512') for n in protocol['lengths']}
    require(set(inventory) - set(old_inventory) == added and len(added) == 92, 'unexpected case extension')
    return protocol, profiles, {
        'scope': 'protocol_and_candidate_object_audit', 'ok': True,
        'benchmark_source_sha256': digest(script), 'protocol_sha256': digest(protocol_path),
        'previous_cases_retained': 671, 'new_cases': 92, 'cases': 763, 'samples': 16023,
        'wide_builds': 18, 'expected_wide_queries': 356, 'old_wide_objects_byte_identical': 14,
        'fixed_driver_reference_runtime_sha256': fixed_hashes,
        'fixed_build_commands': commands,
        'no_driver_or_native_kernel_executed': True, 'native_benchmark_observed': False,
        'final_source_qualified': False, 'profiles': profiles,
    }


def readback(root, path, previous, protocol, profiles, evidence_dir=None, expected_commit=None, solver_library=None):
    result, data = read_json(path)
    public = 'wide_builds' in result and 'builds' not in result
    evidence = evidence_dir if evidence_dir is not None else path.parent
    require(result.get('ok') is True and result.get('status') == 'completed', 'campaign is not completed successfully')
    require(result['protocol'] == protocol, 'result protocol differs from audited source')
    require(result['protocol_sha256'] == digest(root / 'benchmarks/hia_verified_kernels/PROTOCOL.json'),
            'result protocol bytes differ')
    require(re.fullmatch('[0-9a-f]{40}', result['source_commit']) is not None, 'invalid source commit')
    if expected_commit is not None:
        require(result['source_commit'] == expected_commit, 'unexpected campaign source commit')
    benchmark_identities = result['benchmark_source_sha256'] if public else result['source_identity']
    require_identity_inventory(benchmark_identities, previous['benchmark_source_sha256'],
                               'benchmark source inventory')
    if public:
        require_identity_inventory(result['kernel_source_sha256'],
                                   set(previous['kernel_source_sha256']) |
                                   {'hepta/hia_loaded_source.py', 'hepta/hia_solver_identity.py'},
                                   'public kernel source inventory')
    source_sections = ('benchmark_source_sha256', 'kernel_source_sha256') if public else ('source_identity',)
    checked_sources = set()
    for section in source_sections:
        for name, expected in result[section].items():
            require(digest(relative_file(root, name)) == expected, 'source hash differs: ' + name)
            checked_sources.add(name)
    ordered = expected_cases(protocol)
    random.Random(20261119).shuffle(ordered)
    rows = result['rows']
    keys = [(r['mode'], r['arm'], r['length']) for r in rows]
    require(keys == ordered, 'missing, duplicated or reordered complete cases')
    require([(r['mode'], r['arm'], r['length']) for r in result['case_order']] == ordered,
            'recorded deterministic order differs')
    index = dict(zip(keys, rows))
    scalar = SEED
    for iteration in range(protocol['scalar_iterations']):
        scalar = (scalar * 0x9e3779b97f4a7c15 + iteration) & MASK
    state = 0x3c79ac492ba7b653
    source = bytearray()
    for _ in range(max(protocol['lengths']) + 32):
        state ^= state >> 12
        state ^= (state << 25) & MASK
        state ^= state >> 27
        source.append(((state * 0x2545f4914f6cdd1d) & MASK) >> 56)
    sums = {n: [sum(source[offset:offset + n]) for offset in range(1, 17)] for n in protocol['lengths']}
    samples_checked = 0
    for key, row in index.items():
        mode, arm, n = key
        require((row['library'], row['symbol']) == expected_binding(key), 'result binding differs: ' + str(key))
        calls = protocol['scalar_iterations'] if mode == 'scalar' else protocol['span_iterations'][str(n)]
        expected = (scalar if mode == 'scalar' else (SEED + n * calls) & MASK if mode == 'copy' else
                    (SEED + calls) & MASK if mode == 'zero' else
                    (SEED + sum(value * (calls // 16 + (i < calls % 16)) for i, value in enumerate(sums[n]))) & MASK)
        samples = row['samples']
        require(len(samples) == 21 and [s['batch'] for s in samples] == list(range(21)), 'incomplete batches: ' + str(key))
        for sample in samples:
            require(type(sample['calls']) is int and sample['calls'] == calls, 'iteration count changed')
            require(type(sample['checksum']) is int and sample['checksum'] == expected, 'checksum differs: ' + str(key))
            require(type(sample['elapsed_ns']) is int and sample['elapsed_ns'] > 0, 'invalid elapsed time')
            require(type(sample['ns_per_call']) in (int, float) and math.isfinite(sample['ns_per_call']) and
                    sample['ns_per_call'] > 0 and abs(sample['ns_per_call'] - sample['elapsed_ns'] / calls) <= 5.1e-10,
                    'per-call timing differs from raw nanoseconds')
            samples_checked += 1
        require(row['median_ns_per_call'] == statistics.median(s['ns_per_call'] for s in samples), 'median differs')
        require(row['max_ns_per_call'] == max(s['ns_per_call'] for s in samples), 'maximum differs')
        if public:
            rust = index[mode, 'rust', n]['median_ns_per_call']
            require(row['rust_median_ns_per_call'] == rust and
                    row['median_ratio_to_rust'] == row['median_ns_per_call'] / rust and
                    row['median_difference_from_rust_ns'] == row['median_ns_per_call'] - rust, 'Rust ratio differs')
    require(samples_checked == 16023, 'incomplete sample inventory')
    commands = result['commands']
    labels = [c['label'] for c in commands]
    require(len(labels) == len(set(labels)), 'duplicate command labels')
    noncases = {label for label in labels if not label.startswith('case-')}
    old_noncases = {c['label'] for c in previous['commands'] if not c['label'].startswith('case-')}
    new_profiles = set(profiles) - set(previous['wide_builds'])
    require(noncases == old_noncases | {'disassembly-' + label for label in new_profiles},
            'non-case command inventory changed')
    require(len(commands) == len(previous['commands']) + 92 + 4 == 807,
            'protocol v6 requires exactly 807 commands: 763 case calls plus 44 fixed build/identity/disassembly receipts')
    by_label = {c['label']: c for c in commands}
    for command in commands:
        require(command['returncode'] == 0 and command['timed_out'] is False, 'failed/timed-out command: ' + command['label'])
        require(re.fullmatch('[A-Za-z0-9_.-]+', command['label']) is not None, 'invalid command label')
        for suffix in ('stdout', 'stderr'):
            value = command[suffix + '_sha256']
            require(re.fullmatch('[0-9a-f]{64}', value) is not None, 'invalid command digest')
            if not public:
                require(digest(relative_file(evidence, command['label'] + '.' + suffix)) == value,
                        'original command-output bytes differ: ' + command['label'] + '.' + suffix)
    def normalized_build_word(word):
        for tool in ('cc', 'rustc'):
            if word == 'tool:' + tool or word == result['toolchain'][tool].get('path'):
                return 'tool:' + tool
        name = Path(word).name
        if name in FIXED_SOURCES:
            return 'source/' + name
        if name in ('driver', 'runtime-identity', 'reference-c.so', 'reference-rust.so'):
            return 'evidence/' + name
        return word
    for label, expected in fixed_build_commands(protocol).items():
        require([normalized_build_word(word) for word in by_label[label]['argv']] == expected,
                'actual fixed compiler flags or file roles changed: ' + label)
    for i, row in enumerate(rows):
        mode, arm, n = row['mode'], row['arm'], row['length']
        label = f'case-{i:02d}-{mode}-{arm}-{n}'
        command = by_label[label]
        calls = protocol['scalar_iterations'] if mode == 'scalar' else protocol['span_iterations'][str(n)]
        argv = command['argv']
        require(len(argv) == 7 and Path(argv[0]).name == 'driver' and argv[1] == mode and
                Path(argv[2]).name == row['library'] and argv[3:] == [row['symbol'], '21', str(calls), str(n)],
                'actual driver invocation differs: ' + label)
        if not public:
            observed = [json.loads(line) for line in relative_file(evidence, label + '.stdout').read_text().splitlines()]
            require(observed == row['samples'], 'driver stdout differs from recorded samples: ' + label)
    expected_binaries = set(previous['binaries']) | {label + '.so' for label in new_profiles}
    require(set(result['binaries']) == expected_binaries and len(expected_binaries) == 33,
            'protocol v6 requires exactly 33 binaries, preserving the complete prior inventory')
    for name, record in result['binaries'].items():
        require(Path(name).name == name, 'invalid binary name')
        require(type(record['bytes']) is int and record['bytes'] > 0 and
                re.fullmatch('[0-9a-f]{64}', record['sha256']) is not None,
                'invalid binary byte count or digest: ' + name)
        if not public:
            binary = relative_file(evidence, name)
            require(binary.stat().st_size == record['bytes'] and digest(binary) == record['sha256'],
                    'original binary differs: ' + name)
    builds = result['wide_builds'] if public else {
        name: build for name, build in result['builds'].items() if build.get('simd_isa') in ('avx2', 'avx512')}
    require(set(builds) == set(expected_wide_profiles()), 'wide result build inventory differs')
    queries_checked = 0
    checked_solver = None
    for label, (isa, kind, copy_tail, reduce_tail, obligation_count) in expected_wide_profiles().items():
        build = builds[label]
        proof = build['validation']
        require(build['ok'] is True and proof['ok'] is True and proof['complete'] is True, 'incomplete proof: ' + label)
        require(build['selected_strategy'] == 'simd' and proof['kind'] == kind and proof['target_isa'] == isa and
                proof['subject']['entry_symbol'] == 'calculate' and
                proof['checker']['producer_reemission_used'] is False,
                'proof subject or independent-consumer mode differs: ' + label)
        solver = proof['checker']['solver']
        if checked_solver is None:
            validate_solver_identity(root, solver,
                                     next(iter(previous['wide_builds'].values()))['validation']['checker']['solver'],
                                     public=public, solver_library=solver_library)
            checked_solver = solver
        else:
            require(solver == checked_solver, 'solver loaded identity changed between wide builds')
        require(build['simd_isa'] == isa and build['simd_unroll'] == 4 and build['runtime_solver_calls'] == 0,
                'build profile differs: ' + label)
        require((build['simd_copy_tail'], build['simd_reduce_tail']) == (copy_tail, reduce_tail), 'build strategy changed')
        for field in ('object_sha256', 'text_sha256'):
            require(build[field] == profiles[label][field], 'actual candidate bytes differ: ' + label + '/' + field)
        if label in previous['wide_builds']:
            old = previous['wide_builds'][label]
            for field in ('object_sha256', 'text_sha256', 'artifact_sha256'):
                require(build[field] == old[field], 'old complete object/final-image bytes changed: ' + label + '/' + field)
            require(build['toolchain']['sha256'] == old['toolchain']['sha256'], 'old linker identity changed')
        else:
            old = previous['wide_builds'][label.removesuffix('-bounded-one') + '-bounded-tail']
            require(build['toolchain']['sha256'] == old['toolchain']['sha256'], 'new profile linker identity changed')
        expected_profile = old['validation']['profile']
        if reduce_tail == 'bounded-one':
            expected_profile = expected_profile.removesuffix('v2.reduce-bounded') + 'v3.reduce-bounded-one'
        require(proof['profile'] == expected_profile, 'proof profile differs: ' + label)
        if not public:
            require(digest(Path(build['toolchain']['path'])) == build['toolchain']['sha256'],
                    'actual linker bytes differ: ' + label)
        require(proof['subject']['final_image_sha256'] == build['artifact_sha256'] ==
                result['binaries'][label + '.so']['sha256'], 'final-image receipt binding differs')
        require(build['artifact_bytes'] == result['binaries'][label + '.so']['bytes'], 'final-image size binding differs')
        require(proof['subject']['object_sha256'] == build['object_sha256'], 'object receipt binding differs')
        obligations = proof['obligations']
        require(len(obligations) == obligation_count and
                [o['result'] for o in obligations] == ['sat'] + ['unsat'] * (obligation_count - 1),
                'missing/failed obligation: ' + label)
        require(len({o['name'] for o in obligations}) == obligation_count, 'duplicate obligations')
        old_names = [o['name'] for o in old['validation']['obligations']]
        names = [o['name'] for o in obligations]
        if reduce_tail == 'bounded-one':
            require(set(names) == set(old_names) | SINGLE_BYTE_OBLIGATIONS,
                    'new single-byte proof does not retain the complete old obligations')
        else:
            require(names == old_names, 'old proof obligation inventory changed: ' + label)
        for i, obligation in enumerate(obligations, 1):
            require(re.fullmatch('[A-Za-z0-9_]+', obligation['name']) is not None, 'invalid obligation name')
            require(re.fullmatch('[0-9a-f]{64}', obligation['query_sha256']) is not None, 'invalid SMT-query hash')
            if not public:
                query = label + '-queries/' + str(i).zfill(2) + '-' + obligation['name'] + '.smt2'
                require(digest(relative_file(evidence, query)) == obligation['query_sha256'], 'SMT-query bytes differ: ' + query)
            queries_checked += 1
        if not public:
            require(digest(relative_file(evidence, label + '-artifacts/candidate.o')) == build['object_sha256'],
                    'original candidate object differs')
            require(digest(relative_file(evidence, kind + '.core.hepta')) == proof['subject']['core_sha256'],
                    'original Core artifact differs')
        else:
            require(result['core_artifacts_sha256'][kind + '.core.hepta'] == proof['subject']['core_sha256'],
                    'public Core binding differs')
        admission = build['cpu_admission']
        require(admission['affinity'] == result['host']['actual_affinity'] == previous['host']['actual_affinity'],
                'CPU affinity changed')
        require([c['cpu'] for c in admission['cpus']] == admission['affinity'], 'CPU probe inventory incomplete')
        require(set(proof['required_cpu_features']) <= set(admission['common_features']), 'required ISA not admitted')
        require(admission['common_xcr0'] & proof['required_xcr0_mask'] == proof['required_xcr0_mask'], 'OS vector state not admitted')
        require(admission['source_sha256'] == digest(root / 'hepta/hia_verified_cpu.py'), 'CPU admission source differs')
        for identities, old_identities, description in (
                (build['source_identity'], old['source_identity'], 'producer'),
                (proof['checker']['source_identity'], old['validation']['checker']['source_identity'], 'checker')):
            required_identities = set(old_identities) | {'hia_loaded_source.py'}
            if description == 'checker':
                required_identities.add('hia_solver_identity.py')
            require_identity_inventory(identities, required_identities,
                                       description + ' source inventory for ' + label)
            for name, expected in identities.items():
                if name.endswith('.py'):
                    relative = 'hepta/' + name
                    require(digest(relative_file(root, relative)) == expected, 'producer/checker source differs: ' + relative)
                    checked_sources.add(relative)
    require(queries_checked == 356, 'incomplete wide-query inventory')
    for tool in ('cc', 'rustc'):
        current, old = result['toolchain'][tool], previous['toolchain'][tool]
        for field in ('sha256', 'compiler_sha256'):
            if field in old:
                require(current[field] == old[field], 'compiler identity changed: ' + tool + '/' + field)
        if not public:
            require(digest(Path(current['path'])) == current['sha256'], 'actual compiler/launcher bytes differ')
            require(relative_file(evidence, tool + '-version.stdout').read_text().strip() == current['version'],
                    'original compiler version receipt differs: ' + tool)
            if 'compiler_path' in current:
                require(digest(Path(current['compiler_path'])) == current['compiler_sha256'], 'actual Rust compiler differs')
                sysroot = relative_file(evidence, 'rust-sysroot.stdout').read_text().strip()
                require(Path(sysroot) / 'bin/rustc' == Path(current['compiler_path']),
                        'original Rust sysroot receipt differs')
    runtime = result['runtime_dependency']
    for field in ('glibc_version', 'libc_sha256', 'memcpy_ifunc_offset', 'binding'):
        require(runtime[field] == previous['runtime_dependency'][field], 'runtime identity changed: ' + field)
    if not public:
        require(digest(Path(runtime['libc_path'])) == runtime['libc_sha256'], 'actual libc bytes differ')
        before = relative_file(evidence, 'runtime-identity.stdout').read_bytes()
        after = relative_file(evidence, 'runtime-identity-after.stdout').read_bytes()
        require(before == after, 'runtime IFUNC changed during campaign')
        observed_runtime = before.decode().splitlines()
        require(len(observed_runtime) == 3 and observed_runtime[0] == runtime['glibc_version'] and
                Path(observed_runtime[1]).resolve(strict=True) == Path(runtime['libc_path']) and
                observed_runtime[2] == str(runtime['memcpy_ifunc_offset']),
                'original runtime version/path/IFUNC receipt differs')
        require(relative_file(evidence, 'source-commit.stdout').read_text().strip() == result['source_commit'] ==
                relative_file(evidence, 'source-commit-after.stdout').read_text().strip(), 'source commit changed during run')
        require(not relative_file(evidence, 'source-status-before.stdout').read_text().strip() and
                not relative_file(evidence, 'source-status-after.stdout').read_text().strip(), 'tracked source dirty during run')
        require(digest(relative_file(evidence, 'protocol.json')) == result['protocol_sha256'], 'retained protocol bytes differ')
    summary = {'scope': 'public_projection_record_readback' if public else 'original_files_and_record_readback',
               'ok': True, 'source_commit': result['source_commit'], 'result_sha256': sha256(data).hexdigest(),
               'cases': len(rows), 'samples_checked': samples_checked, 'samples_per_case': 21,
               'previous_case_bindings_preserved': 671, 'old_wide_object_and_final_images_preserved': 14,
               'wide_builds': len(builds), 'wide_queries': queries_checked, 'commands': len(commands),
               'binaries': len(result['binaries']), 'source_files_compared': len(checked_sources),
               'scalar_checksum_method': 'direct 10000000-step u64 recurrence',
               'span_checksum_method': 'independent xorshift64* bytearray and exact slice sums',
               'original_command_output_binary_and_query_bytes_checked': not public,
               'compiler_and_runtime_identities_match_previous_campaign': True,
               'solver_original_four_identity_fields_match_previous_campaign': True,
               'solver_executed_python_and_native_mapping_receipt_checked': True,
               'solver_original_source_library_files_checked': not public,
               'completed_campaign_record_checked': True, 'native_benchmark_observed': not public,
               'native_components_or_installation_qualified': False}
    comparisons = []
    for mode in ('sum', 'zero', 'copy'):
        for length in protocol['lengths']:
            rust = index[mode, 'rust', length]['median_ns_per_call']
            row = {'mode': mode, 'length': length, 'rust_ns': rust}
            for isa in ('avx2', 'avx512'):
                arm = 'verified-' + isa + ('-copy-endpoints-fast' if mode == 'copy' else '-bounded-one')
                value = index[mode, arm, length]['median_ns_per_call']
                row[isa + '_ns'] = value
                row[isa + '_ratio_to_rust'] = value / rust
            comparisons.append(row)
    summary['candidate_rows_vs_rust'] = comparisons
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='Exact source checkout or snapshot to audit')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--protocol-only', action='store_true')
    group.add_argument('--result', type=Path, help='Completed raw RESULT.json or public JSON/gzip projection')
    parser.add_argument('--previous', type=Path, help='Pinned complete v5 public JSON/gzip; defaults inside --root')
    parser.add_argument('--evidence-dir', type=Path, help='Original raw-result sidecars; defaults to result parent')
    parser.add_argument('--expected-commit', help='Require this exact 40-hex source commit for result readback')
    parser.add_argument('--solver-library', type=Path,
                        help='Original solver library when its recorded dev/inode is outside the discovered Z3 package')
    args = parser.parse_args()
    if args.expected_commit is not None:
        require(re.fullmatch('[0-9a-f]{40}', args.expected_commit) is not None,
                '--expected-commit must be one exact lowercase 40-hex Git commit')
    root = args.root.resolve(strict=True)
    previous_path = args.previous if args.previous is not None else root / PREVIOUS_RELATIVE
    previous, previous_bytes = read_json(previous_path)
    require(sha256(previous_bytes).hexdigest() == PREVIOUS_JSON_SHA256, 'previous complete public record identity differs')
    if previous_path.read_bytes().startswith(b'\x1f\x8b'):
        require(digest(previous_path) == PREVIOUS_GZIP_SHA256, 'previous gzip identity differs')
    require(previous['source_commit'] == 'e9de97cee2a44cfbe044b245f2cf344c2cc3ef47', 'wrong previous source')
    protocol, profiles, audit = audit_protocol(root, previous)
    output = {'protocol_audit': audit}
    if args.result is not None:
        output['result_readback'] = readback(root, args.result, previous, protocol, profiles,
                                           args.evidence_dir, args.expected_commit, args.solver_library)
    print(json.dumps(output, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, StopIteration, json.JSONDecodeError) as exc:
        print(json.dumps({'ok': False, 'error': {'type': type(exc).__name__, 'message': str(exc)}}), file=sys.stderr)
        raise SystemExit(1)
