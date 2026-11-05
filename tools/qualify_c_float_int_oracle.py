#!/usr/bin/env python3
"""Native exported float-to-integer casts against an independent Python oracle.

All 20 binary32/binary64 to integer pairs, exact raw-bit injection by memcpy,
C O0/O3 with nonrecovering undefined/float-cast-overflow sanitizers. Evidence
is retained in /tmp. HEPTA_ENUM_REQUIRE_RUST=1 requires pinned native Rust
exports to pass the same client, vectors, and independent expected output.
"""
from pathlib import Path
import hashlib
import json
import math
import os
import platform
import random
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c
from hepta.backend import emit_rust

SEED = 7051106
RANDOM_CASES = 512
TARGETS = ('i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize')
CTYPES = dict(i8='int8_t', u8='uint8_t', i16='int16_t', u16='uint16_t',
              i32='int32_t', u32='uint32_t', i64='int64_t', u64='uint64_t',
              isize='intptr_t', usize='size_t')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(bits, width):
    return struct.unpack('>f' if width == 32 else '>d', bits.to_bytes(width // 8, 'big'))[0]


def encode(value, width):
    return int.from_bytes(struct.pack('>f' if width == 32 else '>d', value), 'big')


def vectors(width):
    sign = 1 << (width - 1)
    fraction = 23 if width == 32 else 52
    infinity = ((1 << (8 if width == 32 else 11)) - 1) << fraction
    values = {0, sign, 1, sign | 1, (1 << fraction) - 1,
              sign | ((1 << fraction) - 1), 1 << fraction, sign | (1 << fraction)}
    for raw in (infinity - 1, infinity, infinity + 1,
                infinity | (1 << (fraction - 1)), infinity | ((1 << fraction) - 1)):
        values.update((raw, sign | raw))
    # Every destination boundary plus neighbors in the actual source format.
    for exponent in range(65):
        raw = encode(float(1 << exponent), width)
        for neighbor in (raw - 1, raw, raw + 1):
            values.update((neighbor, sign | neighbor))
    for x in (0.25, 0.5, 0.75, 1.25, 1.5, 1.75, 127.5, 128.5, 255.5,
              256.5, 32767.5, 65535.5, 2147483647.5, 4294967295.5):
        values.update((encode(x, width), encode(-x, width)))
    rng = random.Random(SEED + width)
    for _ in range(RANDOM_CASES):
        while True:
            raw = rng.getrandbits(width)
            if math.isfinite(decode(raw, width)):
                values.add(raw)
                break
    return sorted(values)


def reference(value, target):
    bits = 64 if target in ('isize', 'usize') else int(target[1:])
    signed = target.startswith('i')
    lower = -(1 << (bits - 1)) if signed else 0
    upper = (1 << (bits - int(signed))) - 1
    if math.isnan(value):
        return 0
    if value == math.inf:
        return upper
    if value == -math.inf:
        return lower
    return min(upper, max(lower, math.trunc(value)))


def fixtures():
    source, expected = [], []
    client = ['#include <stdint.h>', '#include <stddef.h>', '#include <string.h>',
              '#include <stdio.h>', '#include <inttypes.h>',
              '_Static_assert(sizeof(float)==4 && sizeof(double)==8 && sizeof(size_t)==8 && sizeof(intptr_t)==8,"qualified ABI required");',
              '#ifndef ORACLE_CORRUPT', '#define ORACLE_CORRUPT 0', '#endif']
    corpus = {}
    for width in (32, 64):
        corpus[str(width)] = vectors(width)
        for target in TARGETS:
            name = f'cast_f{width}_{target}'
            source.append(f'pub export "C" fn {name}(x:f{width})->{target} effects {{}} {{return x as {target};}}')
            client.append(f'extern {CTYPES[target]} {name}({"float" if width == 32 else "double"});')
        client.append(f'static const uint{width}_t bits{width}[] = {{' + ','.join(f'UINT{width}_C({x})' for x in corpus[str(width)]) + '};')
    client.append('int main(void) {')
    for width in (32, 64):
        client.append(f'for(size_t i=0;i<sizeof(bits{width})/sizeof(bits{width}[0]);++i) {{ {"float" if width == 32 else "double"} x; memcpy(&x,&bits{width}[i],sizeof x);')
        for target in TARGETS:
            signed = target.startswith('i')
            ctype, fmt = ('int64_t', 'PRId64') if signed else ('uint64_t', 'PRIu64')
            corrupt = ' + (i == 0 && ORACLE_CORRUPT)' if width == 32 and target == 'i8' else ''
            client.append(f'printf("%" {fmt} "\\n", ({ctype})cast_f{width}_{target}(x){corrupt});')
        client.append('}')
        for raw in corpus[str(width)]:
            expected.extend(str(reference(decode(raw, width), t)) for t in TARGETS)
    client.append('return 0;}')
    return '\n'.join(source), '\n'.join(client), '\n'.join(expected) + '\n', corpus


def main():
    directory = Path(tempfile.mkdtemp(prefix='hepta-float-int-oracle-', dir='/tmp'))
    required = os.environ.get('HEPTA_ENUM_REQUIRE_RUST') == '1'
    inputs = sorted((ROOT / 'hepta').glob('*.py')) + [Path(__file__).resolve(), ROOT / 'toolchain-lock.json']
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = dict(schema=1, seed=SEED, random_cases_per_source=RANDOM_CASES,
                  scope='20 exported float-to-integer pairs; Python math/integer expectations; shared frontend',
                  python=sys.version, host=platform.platform(), evidence_directory=str(directory),
                  input_sha256=hashes, rust_required=required, rust_executed=False,
                  commands=[], runs=[], complete_pass=False)

    def save():
        (directory / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')

    def command(argv):
        entry = {'argv': [str(a) for a in argv]}
        result['commands'].append(entry)
        save()
        completed = subprocess.run(entry['argv'], capture_output=True, timeout=120)
        entry.update(returncode=completed.returncode,
                     stdout=completed.stdout.decode(errors='replace'),
                     stderr=completed.stderr.decode(errors='replace'))
        save()
        return completed

    try:
        save()
        source, client, expected, corpus = fixtures()
        (directory / 'program.hepta').write_text(source)
        (directory / 'client.c').write_text(client)
        (directory / 'vectors.json').write_text(json.dumps(corpus))
        (directory / 'expected.stdout').write_text(expected)
        result['observations'] = len(expected.splitlines())
        result['pairs'] = 20
        result['vector_counts'] = {k: len(v) for k, v in corpus.items()}
        program = parse(source)
        checked = check(program)
        if not checked.ok:
            raise RuntimeError(f'Frontend rejected fixture: {checked.diagnostics}')
        (directory / 'program.c').write_text(emit_c(program, checked, crate_type='obj'))
        cc = shutil.which(os.environ.get('CC', 'gcc'))
        if not cc:
            raise RuntimeError('Native C compiler is required')
        result['cc_sha256'] = digest(Path(cc).read_bytes())
        if command([cc, '--version']).returncode:
            raise RuntimeError('C compiler identity failed')
        languages = ['c']
        rustc = None
        if required:
            rustc = shutil.which(os.environ.get('RUSTC', 'rustc'))
            if not rustc:
                raise RuntimeError('HEPTA_ENUM_REQUIRE_RUST=1 but native Rust is unavailable')
            version = command([rustc, '--version'])
            locked = next(e['package'].split('-')[1] for e in json.loads((ROOT / 'toolchain-lock.json').read_text()) if e['package'].startswith('rustc-'))
            if version.returncode or version.stdout.decode().split()[:2] != ['rustc', locked]:
                raise RuntimeError('Rust compiler does not match pinned version ' + locked)
            result['rustc_sha256'] = digest(Path(rustc).read_bytes())
            (directory / 'program.rs').write_text(emit_rust(program, checked, crate_type='staticlib'))
            languages.append('rust')
        for language in languages:
            for opt in (0, 3):
                label = f'{language}-O{opt}'
                flags = [f'-O{opt}', '-std=c11', '-fexcess-precision=standard', '-ffp-contract=off',
                         '-fsanitize=undefined,float-cast-overflow', '-fno-sanitize-recover=all']
                artifact = directory / (label + ('.o' if language == 'c' else '.a'))
                if language == 'c':
                    args = [cc, *flags, '-c', directory / 'program.c', '-o', artifact]
                else:
                    args = [rustc, '--edition=2021', '--crate-type=staticlib', '-C', f'opt-level={opt}', directory / 'program.rs', '-o', artifact]
                if command(args).returncode:
                    raise RuntimeError(label + ' export compilation failed')
                for corrupt in (False, True):
                    binary = directory / (label + ('-wrong' if corrupt else ''))
                    args = [cc, *flags, f'-DORACLE_CORRUPT={int(corrupt)}', directory / 'client.c', artifact, '-lm', '-ldl', '-lpthread', '-o', binary]
                    if command(args).returncode:
                        raise RuntimeError(label + ' client linking failed')
                    completed = command([binary])
                    run = dict(language=language, optimization=f'O{opt}', negative_control=corrupt,
                               artifact_sha256=digest(artifact.read_bytes()), binary_sha256=digest(binary.read_bytes()),
                               returncode=completed.returncode, stdout_sha256=digest(completed.stdout),
                               stderr=completed.stderr.decode(errors='replace'))
                    result['runs'].append(run)
                    (directory / (binary.name + '.stdout')).write_bytes(completed.stdout)
                    (directory / (binary.name + '.stderr')).write_bytes(completed.stderr)
                    matches = completed.stdout == expected.encode()
                    if completed.returncode or completed.stderr or matches == corrupt:
                        raise RuntimeError(label + (' wrong-output negative control failed' if corrupt else ' independent native oracle mismatch'))
                    run['passed'] = True
                    if language == 'rust':
                        result['rust_executed'] = True
                    save()
        if any(digest((ROOT / name).read_bytes()) != value for name, value in hashes.items()):
            raise RuntimeError('Inputs changed during qualification; rerun against stable tree')
        result['evidence_sha256'] = {p.name: digest(p.read_bytes()) for p in directory.iterdir() if p.is_file() and p.name != 'result.json'}
        result['complete_pass'] = True
    except Exception as error:
        result['error'] = str(error)
    save()
    print(json.dumps(result, sort_keys=True))
    return 0 if result['complete_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
