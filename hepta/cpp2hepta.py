"""P5 bootstrap: fail-closed C++20 integer free-function to Hepta L1 source.

Only specifically accepted Clang ASTs are lowered. This changes C++ mangled
symbol identity to C exports and therefore cannot replace an existing C++ binary
ABI. The caller must revalidate the target in real rustc and differential tests.
Do not invoke Clang on untrusted input without a true operating-system sandbox.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .c2hepta import MAX_AST_BYTES, MAX_SOURCE_BYTES, MigrationRejected, Translation, _Function, _children, _ident


def _reject(node: dict, why: str) -> None:
    at = node.get('loc') or node.get('range', {}).get('begin', {})
    raise MigrationRejected('E_CPP2HEPTA_UNSUPPORTED %s %s:%s: %s' % (
        node.get('kind', '?'), at.get('line', '?'), at.get('col', '?'), why))


def convert_cpp(path: str | Path, *, clangxx: str = 'clang++', module: str = 'cpp_migrated') -> Translation:
    source = Path(path).resolve(strict=True)
    src = source.read_bytes()
    if len(src) > MAX_SOURCE_BYTES:
        raise MigrationRejected('E_CPP2HEPTA_LIMIT: source file too large')
    try:
        text = src.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise MigrationRejected('E_CPP2HEPTA_ENCODING: UTF-8 required') from exc
    if re.search(r'(?m)^\s*#', text):
        raise MigrationRejected('E_CPP2HEPTA_PREPROCESSOR: headers/macros require exact build graph')
    module = _ident(module, {'kind': 'module'})
    compiler = shutil.which(clangxx)
    if not compiler:
        raise MigrationRejected('E_CPP2HEPTA_TOOLCHAIN: Clang++ not found')
    args = [compiler, '-x', 'c++', '-std=c++20', '-Werror', '-ferror-limit=3',
            '-fsyntax-only', '-Xclang', '-ast-dump=json', str(source)]
    try:
        with tempfile.TemporaryFile() as out:
            status = subprocess.run(args, stdout=out, stderr=subprocess.PIPE,
                                    timeout=15, check=False)
            out.seek(0)
            data = out.read(MAX_AST_BYTES + 1)
    except subprocess.TimeoutExpired as exc:
        raise MigrationRejected('E_CPP2HEPTA_TOOLCHAIN: Clang++ timed out') from exc
    if status.returncode:
        raise MigrationRejected('E_CPP2HEPTA_CLANG: Clang++ rejected source: ' +
                                status.stderr[:1024].decode('utf-8', 'replace'))
    if len(data) > MAX_AST_BYTES:
        raise MigrationRejected('E_CPP2HEPTA_LIMIT: AST too large')
    try:
        tree = json.loads(data)
    except (UnicodeDecodeError, ValueError) as exc:
        raise MigrationRejected('E_CPP2HEPTA_AST: invalid JSON') from exc
    if tree.get('kind') != 'TranslationUnitDecl':
        raise MigrationRejected('E_CPP2HEPTA_AST: invalid AST root')
    abi = subprocess.run([compiler, '-dM', '-E', '-x', 'c++', '-'], input='',
                         capture_output=True, text=True, timeout=5, check=False)
    if (abi.returncode or not re.search(r'(?m)^#define __SIZEOF_INT__ 4$', abi.stdout)
            or not re.search(r'(?m)^#define __CHAR_BIT__ 8$', abi.stdout)):
        raise MigrationRejected('E_CPP2HEPTA_ABI: only int32 with 8-bit bytes supported')
    version = subprocess.run([compiler, '--version'], capture_output=True, text=True,
                             timeout=5, check=False)
    if version.returncode or not version.stdout:
        raise MigrationRejected('E_CPP2HEPTA_TOOLCHAIN: version unknown')
    decls = []
    for node in _children(tree):
        if 'offset' not in node.get('loc', {}):
            continue  # Compiler synthetic builtins lack source location
        if node.get('kind') != 'FunctionDecl':
            _reject(node, 'globals, namespaces, classes, templates are unsupported')
        if node.get('storageClass') or node.get('inline') or node.get('constexpr') or node.get('variadic'):
            _reject(node, 'storage/linkage/inline/constexpr/variadic are unsupported')
        if not re.fullmatch(r'int \((?:int(?:, int)*)?\) noexcept', node.get('type', {}).get('qualType', '')):
            _reject(node, 'only noexcept signed int(int...) functions are supported')
        decls.append(node)
    if not decls:
        raise MigrationRejected('E_CPP2HEPTA_EMPTY: no C++ function bodies')
    out = [f'module {module};', '',
           '// L1 C++20 value-only migration candidate; no C++ ABI equivalence claimed.']
    seen = set()
    for fn in decls:
        children = _children(fn)
        if any(x.get('kind') not in {'ParmVarDecl', 'CompoundStmt'} for x in children):
            _reject(fn, 'attributes, constructor initializers, and C++ declarations unsupported')
        bodies = [x for x in children if x.get('kind') == 'CompoundStmt']
        if len(bodies) != 1:
            _reject(fn, 'external declarations and missing bodies unsupported')
        name = _ident(fn.get('name'), fn)
        if name in seen:
            _reject(fn, 'C++ overloads/duplicate symbols unsupported')
        seen.add(name)
        params = []
        for p in (x for x in children if x.get('kind') == 'ParmVarDecl'):
            # Defaults change call arity and parameter attributes can carry
            # semantics. Neither is representable in this L1 migration tier.
            if p.get('init') is not None or _children(p):
                _reject(p, 'default arguments and parameter attributes are unsupported')
            if p.get('type', {}).get('qualType') != 'int':
                _reject(p, 'only plain int values are supported')
            param = _ident(p.get('name'), p)
            if param in params:
                _reject(p, 'duplicate parameter names')
            params.append(param)
        lowerer = _Function(name, params)
        try:
            stmts = lowerer.statements(bodies[0])
        except MigrationRejected as exc:
            raise MigrationRejected(str(exc).replace('E_C2HEPTA_', 'E_CPP2HEPTA_')) from exc
        if not stmts:
            _reject(fn, 'empty body unsupported')
        sig = ', '.join(f'{p}: i32' for p in params)
        out.extend([f'export "C" fn {name}({sig}) -> i32 effects {{ panic }}',
                    'resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }',
                    '{', *stmts, '}', ''])
    output = '\n'.join(out)
    if source.read_bytes() != src:
        raise MigrationRejected('E_CPP2HEPTA_RACE: source changed during conversion')
    return Translation(output, {
        'schema': 'hepta.cpp2hepta.v0', 'ok': True, 'status': 'candidate_unverified',
        'tier': 'L1', 'profile': 'standalone-C++20-noexcept-signed-int-free-functions',
        'source_sha256': sha256(src).hexdigest(), 'hepta_sha256': sha256(output.encode()).hexdigest(),
        'clangxx': version.stdout.splitlines()[0], 'functions': sorted(seen),
        'semantic_equivalence_proved': False, 'cpp_abi_preserved': False,
        'native_hepta_validation': 'not_run', 'differential_validation': 'not_run',
        'memory_safety_proved': False, 'resources_verified': False,
        'assumptions': ['C++20 source has no headers/templates/classes/overloads',
                        'All inputs have defined C++ signed-int arithmetic behavior',
                        'C++ mangled names change to extern C symbols; original binary ABI is not preserved',
                        'Runtime native verification and differential testing required'],
    })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Fail-closed Clang++ AST to Hepta L1 profile')
    parser.add_argument('source')
    parser.add_argument('--output', '-o', required=True)
    parser.add_argument('--module', default='cpp_migrated')
    parser.add_argument('--clangxx', default='clang++')
    opts = parser.parse_args(argv)
    try:
        original = Path(opts.source).resolve(strict=True)
        destination = Path(opts.output).resolve()
        if original == destination or destination.suffix != '.hepta':
            raise MigrationRejected('E_CPP2HEPTA_OUTPUT: separate .hepta file required')
        translated = convert_cpp(original, clangxx=opts.clangxx, module=opts.module)
        if sha256(original.read_bytes()).hexdigest() != translated.report['source_sha256']:
            raise MigrationRejected('E_CPP2HEPTA_RACE: source changed before write')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise MigrationRejected('E_CPP2HEPTA_OUTPUT: cannot overwrite candidate')
        tmp = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=destination.parent,
                                             prefix='.cpp2hepta-', suffix='.tmp', delete=False) as fd:
                tmp = fd.name
                fd.write(translated.source)
                fd.flush()
                os.fsync(fd.fileno())
            os.link(tmp, destination)
        finally:
            if tmp:
                Path(tmp).unlink(missing_ok=True)
        print(json.dumps({**translated.report, 'output': str(destination)}, indent=2, sort_keys=True))
        return 0
    except (MigrationRejected, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'schema': 'hepta.cpp2hepta.v0', 'ok': False,
                          'status': 'rejected', 'error': str(exc)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
