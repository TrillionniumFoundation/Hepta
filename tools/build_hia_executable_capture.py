"""Build the isolated HIA seal owner and its one-attempt kernel primitive.

Matching-cold admission and the existing compile_stage budget remain unchanged.
Raw assembly has a separate fixed 30-second body plus 3-second owned cleanup.
Neither receipt independently establishes the new component's original domain.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_executable_capture import (
    BUILD_SCHEMA, SCHEMA, PROFILE, SOURCE_INPUTS, POLICY_SOURCE, RAW_SOURCE)
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_store_file_capture_originals import stop_owned

INPUTS = SOURCE_INPUTS

def capture_text(raw):
    if len(raw)<64 or raw[:16]!=b'\x7fELF\x02\x01\x01'+b'\0'*9:
        raise ValueError('executable capture object must be exact little-endian ELF64')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    if header[1:4]!=(1,62,1) or header[8]!=64 or header[11]!=64 or header[12]<1:
        raise ValueError('executable capture object type or section layout differs')
    offset,count,names_index=header[6],header[12],header[13]
    if names_index>=count or offset+64*count>len(raw):
        raise ValueError('executable capture object section table is out of range')
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+64*i) for i in range(count)]
    def bytes_for(section):
        start,size=section[4:6]
        if start+size>len(raw):raise ValueError('ELF section is out of range')
        return raw[start:start+size]
    names=bytes_for(sections[names_index])
    def name_at(start):
        if start>=len(names):raise ValueError('section name is out of range')
        stop=names.find(b'\0',start)
        if stop<0:raise ValueError('section name is unterminated')
        return names[start:stop]
    matches=[i for i,s in enumerate(sections) if name_at(s[0])==b'.text']
    if len(matches)!=1:raise ValueError('executable capture object lacks one complete text section')
    text_index=matches[0];section=sections[text_index];text=bytes_for(section)
    if section[1]!=1 or section[2]&6!=6 or not text:
        raise ValueError('executable capture text is not an executable allocated section')
    for row in sections:
        if row[1] in (4,9) and row[7]==text_index and row[5]:
            raise ValueError('raw executable capture entry must contain no linker relocations')
    found=[]
    for row in sections:
        if row[1]!=2:continue
        if row[9]!=24 or row[5]%24 or row[6]>=count:raise ValueError('ELF symbol table differs')
        symbols=bytes_for(row);strings=bytes_for(sections[row[6]])
        for point in range(0,len(symbols),24):
            n,info,other,index,value,size=struct.unpack_from('<IBBHQQ',symbols,point)
            if n>=len(strings):raise ValueError('ELF symbol string differs')
            stop=strings.find(b'\0',n)
            if stop<0:raise ValueError('ELF symbol is unterminated')
            if strings[n:stop]==b'hia_executable_capture_syscalls_entry':
                found.append((info,other,index,value,size))
    if found!=[(18,0,text_index,0,len(text))]:
        raise ValueError('raw executable capture must be the single complete global function at entry zero')
    return text


def assemble(output, source, assembler):
    output.mkdir(mode=0o700)
    compiler = assembler.read_bytes()
    (output / 'input.S').write_bytes(source)
    command = [str(assembler), '-c', '-x', 'assembler', '-target', 'x86_64-linux-gnu',
               str(output / 'input.S'), '-o', str(output / 'effects.o')]
    started = time.monotonic()
    process = None
    timeout = False
    cleanup = None
    cleanup_error = None
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=output, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            (output / 'start.json').write_text(json.dumps({
                'argv': command, 'cwd': str(output), 'pid': process.pid, 'pgid': process.pid,
                'body_seconds': 30, 'cleanup_seconds': 3}, sort_keys=True) + '\n')
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                timeout = True
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = type(error).__name__ + ': ' + str(error)
    receipt = {
        'command': command, 'pid': None if process is None else process.pid,
        'returncode': None if process is None else process.returncode,
        'timeout': timeout, 'cleanup': cleanup, 'cleanup_error': cleanup_error,
        'elapsed_seconds': time.monotonic() - started, 'body_seconds': 30,
        'cleanup_seconds': 3, 'assembler_path': str(assembler),
        'assembler_sha256': sha256(compiler).hexdigest(),
        'source_sha256': sha256(source).hexdigest(),
    }
    (output / 'result.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    if process is None or process.returncode != 0 or timeout or cleanup_error:
        raise RuntimeError('executable-capture assembly did not complete normally')
    raw = (output / 'effects.o').read_bytes()
    text = capture_text(raw)
    if assembler.read_bytes() != compiler:
        raise ValueError('executable-capture assembler changed')
    receipt['object_sha256'] = sha256(raw).hexdigest()
    return text, receipt


def build(output, compiler, assembler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose exactly one matching cold report or explicit development')
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    assembler = Path(assembler).resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    source_raw = {name: (ROOT / name).read_bytes() for name in INPUTS}
    runtime_names = tuple(sorted(p.relative_to(ROOT).as_posix()
                                 for p in (ROOT / 'hepta').rglob('*.py')
                                 if p.relative_to(ROOT / 'hepta').parts[0] != '_data'))
    runtime_raw = {name: (ROOT / name).read_bytes() for name in runtime_names}
    cold_raw = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_raw, cold_raw)
    cold_inputs, custody, development_inputs = None, None, {}
    if sources is not None:
        from tools.hia_native_cold_admission import SCHEMA as NATIVE_SCHEMA, read_json
        if read_json(cold_raw).get('schema') == NATIVE_SCHEMA:
            from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS, read_cold_build_inputs
            cold_inputs = read_cold_build_inputs(cold_report)
            if (cold_inputs.report_bytes != cold_raw or cold_inputs.compiler_bytes != compiler_raw
                    or cold_inputs.sources != sources):
                raise ValueError('capture compiler or source differs from admitted native cold inputs')
            development_inputs = {name: (ROOT / name).read_bytes() for name in NATIVE_CUSTODY_INPUTS}
            custody = cold_inputs.capture_custody(
                {**source_raw, **runtime_raw, **development_inputs}, root=ROOT)
        elif any(sources.get(name) != sha256(raw).hexdigest()
                 for name, raw in {**source_raw, **runtime_raw}.items()):
            raise ValueError('capture component inputs differ from matching cold source')
    output.mkdir(mode=0o700)
    image, compile_receipt = compile_stage(
        output, 'executable-capture', compiler, source_raw[POLICY_SOURCE])
    policy = image.read_bytes()
    full_output = (output / 'executable-capture.output.bin').read_bytes()
    checked = _check_pack_output(compile_receipt, full_output,
                                artifact=compiler_raw, source=source_raw[POLICY_SOURCE])
    if checked != policy:
        raise ValueError('capture policy and native compiler output differ')
    effects, assembly_receipt = assemble(output / 'raw', source_raw[RAW_SOURCE], assembler)
    if (compiler.read_bytes() != compiler_raw
            or any((ROOT / name).read_bytes() != raw for name, raw in source_raw.items())
            or tuple(sorted(p.relative_to(ROOT).as_posix()
                            for p in (ROOT / 'hepta').rglob('*.py')
                            if p.relative_to(ROOT / 'hepta').parts[0] != '_data')) != runtime_names
            or any((ROOT / name).read_bytes() != raw for name, raw in runtime_raw.items())
            or (not development and (Path(cold_report).read_bytes() != cold_raw
                                      or current_sources() != sources))):
        raise ValueError('capture component construction input drift')
    if custody is not None:
        from tools.hia_component_input_custody import verify_component_custody
        verify_component_custody(custody, compiler_raw, cold_raw, sources,
                                 {**source_raw, **runtime_raw, **development_inputs}, root=ROOT)
        cold_inputs.unchanged()
    (output / 'policy.bin').write_bytes(policy)
    (output / 'effects.bin').write_bytes(effects)
    component_inputs = {name: sha256(raw).hexdigest() for name, raw in source_raw.items()}
    runtime_modules = {name: sha256(raw).hexdigest() for name, raw in runtime_raw.items()}
    scope = 'DEVELOPMENT_COMPONENT' if development else 'MATCHING_SOURCE_COLD_COMPONENT'
    cold_digest = None if development else sha256(cold_raw).hexdigest()
    report = {
        'schema': BUILD_SCHEMA, 'scope': scope, 'profile': PROFILE,
        'component_inputs': component_inputs, 'runtime_modules': runtime_modules,
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'policy_sha256': sha256(policy).hexdigest(),
        'effects_sha256': sha256(effects).hexdigest(),
        'cold_report_sha256': cold_digest, 'source_manifest': sources,
        'native_compile_receipt': compile_receipt, 'assembly_receipt': assembly_receipt,
        'default_cutover': False, 'ordinary_entry_python_free': False,
        'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False,
    }
    if custody is not None:
        report['component_input_custody'] = custody
        report['development_inputs'] = {
            name: sha256(raw).hexdigest() for name, raw in development_inputs.items()}
    report_raw = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    (output / 'build.json').write_bytes(report_raw)
    manifest = {
        'schema': SCHEMA, 'profile': PROFILE, 'scope': scope,
        'policy_path': 'policy.bin', 'policy_sha256': sha256(policy).hexdigest(),
        'effects_path': 'effects.bin', 'effects_sha256': sha256(effects).hexdigest(),
        'receipt_path': 'build.json', 'receipt_sha256': sha256(report_raw).hexdigest(),
        'component_inputs': component_inputs, 'runtime_modules': runtime_modules,
        'compiler_sha256': sha256(compiler_raw).hexdigest(), 'cold_report_sha256': cold_digest,
    }
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    for name in ('policy.bin', 'effects.bin', 'build.json', 'manifest.json'):
        (output / name).chmod(0o600)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--assembler', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--development', action='store_true')
    choice.add_argument('--cold-report', type=Path)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.assembler, args.cold_report,
                development=args.development))


if __name__ == '__main__':
    main()
