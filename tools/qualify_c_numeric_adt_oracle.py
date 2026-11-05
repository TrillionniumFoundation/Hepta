#!/usr/bin/env python3
"""Native numeric-cast / Copy-ADT composition against independent Python results.

All 42 directional pairs in aggregate source contexts, exact raw-bit memcpy,
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

SEED = 57970511
RANDOM_CASES = 128
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


def integer_float_bits(value, width):
    # Python integer quotient/remainder rounding avoids intermediate binary64
    # double rounding for i64/u64 -> f32. No production helper is consulted.
    negative = value < 0
    magnitude = abs(value)
    precision = 24 if width == 32 else 53
    shift = max(0, magnitude.bit_length() - precision)
    if shift:
        quotient, remainder = divmod(magnitude, 1 << shift)
        half = 1 << (shift - 1)
        magnitude = (quotient + int(remainder > half or (remainder == half and quotient % 2))) << shift
    return encode(-float(magnitude) if negative else float(magnitude), width)


def integer_vectors(target):
    bits = 64 if target in ('isize', 'usize') else int(target[1:])
    signed = target.startswith('i')
    low = -(1 << (bits-1)) if signed else 0
    high = (1 << (bits-int(signed))) - 1
    values = {low, low+1, high-1, high, 0, 1}
    for exponent in range(bits):
        for delta in (-1, 0, 1):
            for sign in (-1, 1):
                value = sign * ((1 << exponent) + delta)
                if low <= value <= high:
                    values.add(value)
    rng = random.Random(SEED + bits + int(signed))
    values.update(rng.randint(low, high) for _ in range(RANDOM_CASES))
    return sorted(values)


def converted(value, source, target):
    if target in TARGETS:
        return str(reference(value, target))
    width = int(target[1:])
    if source in TARGETS:
        return str(integer_float_bits(value, width))
    if math.isnan(value):
        return 'nan'  # Payload/sign is intentionally not a cross-backend promise.
    try:
        raw = encode(value, width)
    except OverflowError:
        raw = encode(math.copysign(math.inf, value), width)
    return str(raw)


def fixtures():
    source = ['struct Box<T>{value:T,token:Unit} enum Event<T>{Value(T),Empty}',
              'fn unit()->Unit effects {} {}']
    expected = []
    types = {**CTYPES, 'f32':'float', 'f64':'double'}
    client = ['#include <stdint.h>', '#include <stddef.h>', '#include <string.h>',
              '#include <stdio.h>', '#include <inttypes.h>', '#include <math.h>',
              '_Static_assert(sizeof(float)==4 && sizeof(double)==8 && sizeof(size_t)==8 && sizeof(intptr_t)==8,"qualified ABI required");',
              '#ifndef ORACLE_CORRUPT', '#define ORACLE_CORRUPT 0', '#endif']
    corpus = {}
    sources = (*TARGETS, 'f32', 'f64')
    for src in sources:
        floating = src.startswith('f')
        width = 64 if src in ('isize', 'usize') else int(src[1:])
        values = vectors(width) if floating else integer_vectors(src)
        corpus[src] = values
        targets = (*TARGETS, 'f64' if src == 'f32' else 'f32') if floating else ('f32', 'f64')
        for target in targets:
            name = f'cast_{src}_{target}'
            zero = '0.0' if target.startswith('f') else '0'
            # The conversion lives inside nested generic/Result/enum construction.
            # Reading a snapshot after replacing the original forces Copy semantics.
            source.append(f'pub export "C" fn {name}(x:{src})->{target} effects {{write}} {{'
                f'let mut b=Box::<Result<Event<{target}>,Unit>>{{value:Result::Ok(Event::Value(x as {target})),token:unit()}};'
                'let saved=b;b.value=Result::Err(unit());'
                f'match saved.value {{Result::Ok(e)=>{{match e {{Event::Value(v)=>{{return v;}},Event::Empty=>{{return {zero};}}}}}},Result::Err(_)=>{{return {zero};}}}}}}')
            client.append(f'extern {types[target]} {name}({types[src]});')
        raw = values if floating else [v % (1 << width) for v in values]
        client.append(f'static const uint{width}_t bits_{src}[] = {{' + ','.join(f'UINT{width}_C({x})' for x in raw) + '};')
    source.append('fn consume(xs:read [Box<f64>])->i64 effects {panic} {return (xs[0].value as i16) as i64 + (xs[1].value as i16) as i64;}\nfn mutate(xs:mut [Box<f64>])->Unit effects {write,panic} {xs[0].value=99.5;xs[0].token=unit();}\npub export "C" fn borrowed(x:f64)->i64 effects {write,panic} {\nlet mut xs:[Box<f64>;2]=[Box{value:x,token:unit()},Box{value:3.75,token:unit()}];\nlet saved=xs;mutate(mut xs);return consume(read saved);\n}')
    client.append('extern int64_t borrowed(double);')
    client.append('int main(void) {')
    for src in sources:
        floating = src.startswith('f')
        width = 64 if src in ('isize', 'usize') else int(src[1:])
        targets = (*TARGETS, 'f64' if src == 'f32' else 'f32') if floating else ('f32', 'f64')
        client.append(f'for(size_t i=0;i<sizeof(bits_{src})/sizeof(bits_{src}[0]);++i) {{ {types[src]} x; memcpy(&x,&bits_{src}[i],sizeof x);')
        for target in targets:
            name = f'cast_{src}_{target}'
            if target.startswith('f'):
                tw = int(target[1:])
                corrupt = ' + (i == 0 && ORACLE_CORRUPT)' if src == 'i8' and target == 'f32' else ''
                client.append(f'{{ {types[target]} y={name}(x); uint{tw}_t raw;memcpy(&raw,&y,sizeof raw);if(isnan(y)) puts("nan");else printf("%" PRIu64 "\\n", (uint64_t)raw{corrupt}); }}')
            else:
                ctype, fmt = ('int64_t','PRId64') if target.startswith('i') else ('uint64_t','PRIu64')
                client.append(f'printf("%" {fmt} "\\n", ({ctype}){name}(x));')
        if src == 'f64':
            client.append('printf("%" PRId64 "\\n", borrowed(x));')
        client.append('}')
        for raw in corpus[src]:
            value = decode(raw, width) if floating else raw
            expected.extend(converted(value, src, t) for t in targets)
            if src == 'f64':
                expected.append(str(reference(value, 'i16') + 3))
    client.append('return 0;}')
    return '\n'.join(source), '\n'.join(client), '\n'.join(expected) + '\n', corpus


def main():
    directory = Path(tempfile.mkdtemp(prefix='hepta-numeric-adt-oracle-', dir='/tmp'))
    required = os.environ.get('HEPTA_ENUM_REQUIRE_RUST') == '1'
    inputs = sorted((ROOT / 'hepta').glob('*.py')) + [Path(__file__).resolve(), ROOT / 'toolchain-lock.json']
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = dict(schema=1, seed=SEED, random_cases_per_source=RANDOM_CASES,
                  scope='42 numeric cast pairs inside Copy generic/enum/Result/Unit snapshots, plus borrowed aggregate/slices; independent Python expectations; shared frontend',
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
        result['pairs'] = 42
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
