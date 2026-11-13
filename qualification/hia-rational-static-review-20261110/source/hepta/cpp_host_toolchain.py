"""Narrow native C++20 driver selection for generated C ABI bridges.

Predefined macros establish the selected compiler and target. No cross-host
execution is inferred from this probe; a separate qualifier must run artifacts.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import tempfile

from .c_migrate import MigrationRejected

PROBE = r'''#if defined(__clang__)
HEPTA_CXX_FAMILY clang
HEPTA_CXX_VERSION __clang_major__ __clang_minor__ __clang_patchlevel__
#elif defined(_MSC_VER)
HEPTA_CXX_FAMILY msvc
HEPTA_CXX_VERSION _MSC_FULL_VER _MSC_BUILD
#elif defined(__GNUC__)
HEPTA_CXX_FAMILY gcc
HEPTA_CXX_VERSION __GNUC__ __GNUC_MINOR__ __GNUC_PATCHLEVEL__
#else
#error Unsupported C++ compiler
#endif
#if defined(_WIN32)
HEPTA_CXX_SYSTEM Windows
#elif defined(__APPLE__)
HEPTA_CXX_SYSTEM Darwin
#elif defined(__linux__)
HEPTA_CXX_SYSTEM Linux
#else
#error Unsupported C++ system
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
HEPTA_CXX_MACHINE aarch64
#elif defined(__x86_64__) || defined(_M_X64)
HEPTA_CXX_MACHINE x86_64
#else
#error Unsupported C++ architecture
#endif
#if defined(_MSVC_LANG)
HEPTA_CXX_STANDARD _MSVC_LANG
#else
HEPTA_CXX_STANDARD __cplusplus
#endif
'''


def parse_probe(text):
    fields = {}
    for line in text.splitlines():
        words = line.split()
        if words and words[0].startswith('HEPTA_CXX_'):
            if words[0] in fields:
                raise MigrationRejected('E_CPP_TOOLCHAIN', 'Duplicate C++ identity marker')
            fields[words[0]] = words[1:]
    names = {'FAMILY', 'VERSION', 'SYSTEM', 'MACHINE', 'STANDARD'}
    if set(fields) != {'HEPTA_CXX_' + n for n in names}:
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'Incomplete C++ identity probe')
    family = fields['HEPTA_CXX_FAMILY']
    system = fields['HEPTA_CXX_SYSTEM']
    machine = fields['HEPTA_CXX_MACHINE']
    version = fields['HEPTA_CXX_VERSION']
    if (family not in (['gcc'], ['clang'], ['msvc'])
            or system not in (['Linux'], ['Darwin'], ['Windows'])
            or machine not in (['x86_64'], ['aarch64'])
            or fields['HEPTA_CXX_STANDARD'] not in (['202002L'], ['202002UL'], ['202002'])
            or len(version) != (2 if family == ['msvc'] else 3)
            or not all(re.fullmatch(r'[0-9]{1,10}', x) for x in version)
            or family == ['msvc'] and system != ['Windows']):
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'Unsupported C++ compiler, target or language mode')
    return {'family': family[0], 'system': system[0], 'machine': machine[0],
            'version_components': [int(x) for x in version], 'cpp_standard': 202002}


def compiler_identity(cxx, run, *, family='auto'):
    if family not in {'auto', 'gcc', 'clang', 'msvc'}:
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'Unknown requested C++ family')
    found = shutil.which(cxx)
    if not found:
        raise MigrationRejected('E_CPP_ENV', 'C++ compiler is unavailable')
    # The invocation name selects the C++ linker driver for clang++. Hash the
    # actual bytes through the symlink, but do not rewrite argv[0] to clang.
    compiler = str(Path(found).absolute())
    name = Path(found).name.lower()
    # clang-cl deliberately needs a separate driver contract. Do not send it
    # GNU arguments or label it Microsoft cl.exe from _MSC_VER alone.
    if name in {'clang-cl', 'clang-cl.exe'}:
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'clang-cl driver is not in this contract; select clang++ or cl.exe')
    driver = 'msvc' if name in {'cl', 'cl.exe'} else 'gnu'
    before = hashlib.sha256(Path(compiler).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='hepta-cxx-identity-') as td:
        source = Path(td) / 'identity.cpp'
        source.write_text(PROBE, encoding='utf-8')
        argv = ([compiler, '/nologo', '/std:c++20', '/Zc:__cplusplus', '/EP', '/TP', str(source)]
                if driver == 'msvc' else [compiler, '-std=c++20', '-E', '-P', '-x', 'c++', str(source)])
        probe = run(argv)
    identity = parse_probe(probe.stdout)
    if ((identity['family'] == 'msvc') != (driver == 'msvc')
            or family != 'auto' and identity['family'] != family):
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'Actual C++ compiler differs from selected driver/family')
    if driver == 'msvc':
        a, b = identity['version_components']
        version = f'MSVC _MSC_FULL_VER={a} _MSC_BUILD={b}'
        target = identity['machine'] + '-pc-windows-msvc'
    else:
        version = run([compiler, '--version']).stdout.splitlines()[0]
        target = run([compiler, '-dumpmachine']).stdout.strip()
        numeric = '.'.join(map(str, identity['version_components']))
        if not re.search(r'(?<![0-9])' + re.escape(numeric) + r'(?![0-9])', version):
            raise MigrationRejected('E_CPP_TOOLCHAIN', 'C++ version output differs from actual macros')
    if hashlib.sha256(Path(compiler).read_bytes()).hexdigest() != before:
        raise MigrationRejected('E_CPP_TOOLCHAIN', 'C++ compiler changed during identity probe')
    return {'path': compiler, 'version': version, 'target': target,
            'executable_sha256': before, 'driver': driver, 'identity': identity,
            'macro_probe': {'source': PROBE, 'argv': argv, 'stdout': probe.stdout,
                            'stderr': probe.stderr, 'exit_code': probe.returncode}}


def compile_flags(info):
    if info['driver'] == 'msvc':
        return ['/nologo', '/std:c++20', '/Zc:__cplusplus', '/O2', '/EHsc', '/MD', '/W3', '/WX']
    return ['-std=c++20', '-O2', '-Werror'] + (
        [] if info['identity']['system'] == 'Windows' else ['-fPIC', '-pthread'])


def compile_command(info, source, output, *, includes=(), dependency=None):
    args = [info['path'], *compile_flags(info)]
    if info['driver'] == 'msvc':
        args += ['/I' + str(p) for p in includes]
        if dependency is not None:
            args += ['/sourceDependencies', str(dependency)]
        return args + ['/c', str(source), '/Fo' + str(output)]
    args += ['-I' + str(p) for p in includes]
    if dependency is not None:
        args += ['-MMD', '-MF', str(dependency)]
    return args + ['-c', str(source), '-o', str(output)]


def link_command(info, objects, output):
    if info['driver'] == 'msvc':
        return [info['path'], '/nologo', '/EHsc', '/MD', *map(str, objects),
                '/Fe' + str(output), '/link', '/INCREMENTAL:NO']
    return [info['path'], *map(str, objects), *(
        [] if info['identity']['system'] == 'Windows' else ['-pthread']), '-o', str(output)]
