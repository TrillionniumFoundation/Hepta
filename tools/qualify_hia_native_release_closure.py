"""Qualify release DAG registration with actual source-compiled native roles.

The component fixture stops at the source-capture syscall plan. It never runs
those syscalls or publishes a package. Whole cold/release/install qualification
must still use the complete matching source admission.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import mmap
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

from tools.hia_native_release_dependencies import (
    AUTHORITY, COLD_FILES, PROGRAMS, check_authorities, read_recipe,
    release_dependencies, source_path,
)

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_BYTES = 4194304


class NativeRole:
    def __init__(self, raw):
        self.memory = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.memory.write(raw)
        address = ctypes.addressof(ctypes.c_char.from_buffer(self.memory))
        abi = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
        self.entry = abi(address)

    def call(self, wire, output, workspace):
        source = ctypes.create_string_buffer(wire)
        return self.entry(source, len(wire), output, len(output), workspace, len(workspace))

    def close(self):
        self.memory.close()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def compile_role(root, compiler, output, name):
    source = (root / PROGRAMS / (name + '.hepta')).read_bytes()
    result = subprocess.run([str(compiler), 'compile'], input=source,
                            capture_output=True, env={'PATH': ''}, timeout=60)
    (output / (name + '.stderr')).write_bytes(result.stderr)
    check(result.returncode == 0 and not result.stderr and bool(result.stdout),
          'actual native compilation failed: ' + name)
    (output / (name + '.flat')).write_bytes(result.stdout)
    return result.stdout, {'source_sha256': sha256(source).hexdigest(),
                           'flat_sha256': sha256(result.stdout).hexdigest(),
                           'flat_bytes': len(result.stdout)}


def route_fixture(owner, names, pins, *, omit=None):
    workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
    output = ctypes.create_string_buffer(128)
    result = owner.call(bytes(128), output, workspace)
    check(result == 1 and struct.unpack_from('<2Q', output) == (60, 65),
          'owner constant initialization did not refuse the empty request')
    wire = bytearray(256)
    struct.pack_into('<Q', wire, 24, 3)
    included = [name for name in names if name != omit]
    struct.pack_into('<Q', workspace, 80, len(included))
    for index, name in enumerate(included):
        path = (PROGRAMS + 'release_stage_' + name + '.hiastd').encode('ascii')
        at = len(wire)
        wire += struct.pack('<Q', len(path)) + pins[name] + path
        struct.pack_into('<2Q', workspace, 131200 + index * 16, at, len(path))
    return bytes(wire), output, workspace


def native_routes(owner_raw, dag_raw, recipes):
    owner, dag = NativeRole(owner_raw), NativeRole(dag_raw)
    names = [recipe['name'] for recipe in recipes]
    pins = {recipe['name']: bytes.fromhex(recipe['sha256']) for recipe in recipes}
    cases = []
    try:
        for index, recipe in enumerate(recipes):
            name = recipe['name']
            wire, output, workspace = route_fixture(owner, names, pins)
            struct.pack_into('<Q', workspace, 0, 5000)
            struct.pack_into('<Q', workspace, 1519984, index)
            result = dag.call(wire, output, workspace)
            check(result == 1 and struct.unpack_from('<Q', output)[0] == 319,
                  'registered DAG did not request a captured source: ' + name)
            pn, an, reserved = struct.unpack_from('<3Q', workspace, 393248)
            check(reserved == 0 and 0 < pn <= 4095 and 0 < an <= 127,
                  'invalid native source capture extent: ' + name)
            actual_pin = bytes(workspace[393272:393304])
            actual_path = bytes(workspace[393304:393304 + pn]).decode('ascii')
            alias = bytes(workspace[393304 + pn:393304 + pn + an])
            check(actual_path == recipe['path'] and actual_pin == pins[name] and alias == b'data',
                  'native role captured a different recipe or source pin: ' + name)
            cases.append({'case': 'capture-' + name, 'passed': True,
                          'captured_path': actual_path, 'sha256': actual_pin.hex()})

            wire, output, workspace = route_fixture(owner, names, pins, omit=name)
            struct.pack_into('<Q', workspace, 0, 5000)
            struct.pack_into('<Q', workspace, 1519984, index)
            result = dag.call(wire, output, workspace)
            check(result == 1 and struct.unpack_from('<2Q', output) == (60, 65),
                  'native role did not refuse a missing source pin: ' + name)
            cases.append({'case': 'missing-source-refused-' + name, 'passed': True})

        wire, output, workspace = route_fixture(owner, names, pins)
        struct.pack_into('<Q', workspace, 0, 5000)
        struct.pack_into('<Q', workspace, 1519984, len(names))
        result = dag.call(wire, output, workspace)
        check(result == 4 and struct.unpack_from('<Q', workspace)[0] == 6000,
              'native role did not advance after the final registered DAG')
        cases.append({'case': 'advance-only-after-final-DAG', 'passed': True})
        return cases
    finally:
        owner.close()
        dag.close()


def dependency_controls(root, dependency):
    cases = []

    def reject(name, action):
        try:
            action()
        except ValueError as exc:
            cases.append({'case': name, 'passed': True, 'refusal': str(exc)})
        else:
            raise ValueError('dependency control was accepted: ' + name)

    names = tuple(dependency['registered_dags'])
    check('runtime' in names, 'the runtime release DAG must be registered')
    reject('unregistered-runtime-refused',
           lambda: release_dependencies(root, names=tuple(name for name in names if name != 'runtime')))
    reject('reordered-publications-refused',
           lambda: release_dependencies(root, names=tuple(reversed(names))))
    for recipe in dependency['recipes']:
        raw = (root / recipe['path']).read_bytes()
        reject('truncated-' + recipe['name'], lambda: read_recipe(raw[:-1]))
        reject('trailing-' + recipe['name'], lambda: read_recipe(raw + b'x'))
    reject('source-path-traversal-refused', lambda: source_path('../escape.hepta'))
    for omitted_catalog in (AUTHORITY, COLD_FILES):
        with tempfile.TemporaryDirectory(prefix='hia-release-dependency-control-') as directory:
            target = Path(directory)
            for path, key in ((AUTHORITY, 'paths'), (COLD_FILES, 'files')):
                value = json.loads((root / path).read_bytes())
                if path == omitted_catalog:
                    value[key].remove(PROGRAMS + 'release_stage_runtime.hiastd')
                (target / path).parent.mkdir(parents=True, exist_ok=True)
                (target / path).write_text(json.dumps(value))
            reject('missing-runtime-in-' + Path(omitted_catalog).stem,
                   lambda: check_authorities(target, dependency['required_sources']))
    return cases


def qualify(root, compiler, output, expected_compiler_sha256=None):
    check(platform.machine().lower() in ('x86_64', 'amd64'), 'native component requires an x86-64 host')
    root, compiler, output = (Path(path).resolve() for path in (root, compiler, output))
    compiler_sha256 = sha256(compiler.read_bytes()).hexdigest()
    if expected_compiler_sha256 is not None:
        check(compiler_sha256 == expected_compiler_sha256, 'source compiler identity differs')
    dependency = release_dependencies(root)
    catalogs = check_authorities(root, dependency['required_sources'])
    output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'hepta.hia.native-release-closure-qualification.v1',
              'scope': 'ACTUAL_NATIVE_REGISTERED_SOURCE_CAPTURE_AND_SOURCE_CATALOG_CLOSURE',
              'passed': False, 'whole_release_passed': False,
              'whole_native_only_install_passed': False, 'production_activated': False,
              'compiler_sha256': compiler_sha256, 'roles': {},
              'registered_dags': dependency['registered_dags'],
              'publication_count': dependency['publication_count'],
              'required_source_count': len(dependency['required_sources']),
              **catalogs, 'cases': []}
    try:
        owner, report['roles']['release_owner'] = compile_role(root, compiler, output, 'release_owner')
        dag, report['roles']['release_dag'] = compile_role(root, compiler, output, 'release_dag')
        report['cases'].extend(native_routes(owner, dag, dependency['recipes']))
        report['cases'].extend(dependency_controls(root, dependency))
        report['passed'] = True
    finally:
        (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler-sha256')
    args = parser.parse_args()
    print(json.dumps(qualify(args.source, args.compiler, args.output, args.compiler_sha256), indent=2))


if __name__ == '__main__':
    main()
