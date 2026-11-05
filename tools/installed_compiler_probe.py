#!/usr/bin/env python3
"""Run only inside an isolated environment; no checkout imports or broad discovery."""
from __future__ import annotations
import argparse
import base64
import bisect
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import sysconfig


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installed_identity(expected):
    import hepta
    from hepta.pipeline import compiler_hash
    site = Path(sysconfig.get_path('purelib')).resolve()
    require(sys.prefix != sys.base_prefix, 'not running inside a venv')
    require(Path(hepta.__file__).resolve().parent == site / 'hepta', 'checkout import detected')
    actual = {'hepta/' + p.name: digest(p.read_bytes()) for p in (site / 'hepta').glob('*.py')}
    require(actual == expected, 'installed runtime payload mismatch')
    package = importlib.metadata.distribution('hepta-language')
    require(package.version == '0.2.0', 'wrong distribution version')
    require({(p.name, p.value) for p in package.entry_points} == {('hepta', 'hepta.cli:main')}, 'entrypoint mismatch')
    return {'site_packages': str(site), 'module': hepta.__file__, 'runtime_sha256': actual,
            'compiler_sha256': compiler_hash(), 'version': package.version, 'python': sys.version,
            'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'sys_path': sys.path}


def source_case(index, text, query, error=None, wire=None):
    raw = text.encode('utf-8')
    wire = wire if wire is not None else base64.b64encode(len(raw).to_bytes(2, 'big') + raw)
    scratch = [165] * (len(raw) + 8)
    scalars = [999] * (len(text) + 4)
    if error == 'ScalarCapacity':
        scalars = [999, 999]
    decoded = None if error == 'Decode' else base64.b64decode(wire)
    if decoded is not None:
        scratch[1:len(decoded)+1] = decoded
    ordered = sorted(map(ord, text))
    if error is None:
        scalars[1:len(ordered)+1] = ordered
    arr = lambda xs: '[' + ','.join(map(str, xs)) + ']'
    body = f'''let w{index}:[u8;{len(wire)}]={arr(wire)};
let mut b{index}:[u8;{len(scratch)}]={arr([165]*len(scratch))};
let mut u{index}:[u64;{len(scalars)}]={arr([999]*len(scalars))};
let r{index}=typed::index_packet(read w{index},0,{len(wire)},mut b{index},mut u{index},{query});
match r{index} {{ Result::Ok(c)=>{{'''
    if error is None:
        body += f'let unit=c.done;assert(c.value.scalars=={len(text)});assert(c.value.lower=={1+bisect.bisect_left(ordered,query)});assert(c.value.upper=={1+bisect.bisect_right(ordered,query)});'
    else:
        body += 'assert(false);'
    body += '},Result::Err(e)=>{'
    if error is None:
        body += 'assert(false);'
    else:
        body += 'match e {'
        for variant in ('Decode','ShortHeader','LengthMismatch','InvalidText','ScalarCapacity'):
            check = 'assert(false);' if error != variant else 'assert(x==2);' if variant == 'ScalarCapacity' else 'let unit=x;'
            body += 'typed::PacketError::' + variant + '(x)=>{' + check + '},'
        body += '}'
    body += '}}\n'
    for name, values in [('w', wire), ('b', scratch), ('u', scalars)]:
        body += ''.join(f'assert({name}{index}[{i}]=={v});\n' for i,v in enumerate(values))
    return body


def consumer():
    rng = random.Random(314159)
    texts = ['', 'aaaa', '\0é😀é', '\u007f\u0080\u07ff\u0800\uffff\U00010000\U0010ffff']
    alphabet = [0, 65, 233, 1024, 0x20ac, 0x1f600, 0x10ffff]
    texts += [''.join(chr(rng.choice(alphabet)) for _ in range(rng.randrange(1,8))) for _ in range(12)]
    parts = [source_case(i,t,233) for i,t in enumerate(texts)]
    for i,(name,wire,text) in enumerate([
        ('Decode',b'!!!!',''),('ShortHeader',base64.b64encode(b'x'),''),
        ('LengthMismatch',base64.b64encode(b'\0\2a'),''),
        ('InvalidText',base64.b64encode(b'\0\1\xff'),''),
        ('ScalarCapacity',base64.b64encode(b'\0\2aa'),'aa')],len(texts)):
        parts.append(source_case(i,text,233,name,wire))
    return 'import typed;\nfn main()->Unit effects {panic,write}\nresources { heap_allocations=0; may_block=false; may_suspend=false; may_spawn=false; }\n{\n' + '\n'.join(parts) + '\n}\n'


def main():
    require(__debug__, 'assertions disabled')
    parser=argparse.ArgumentParser()
    parser.add_argument('--expected',required=True)
    parser.add_argument('--fixtures',required=True)
    parser.add_argument('--cc',required=True)
    parser.add_argument('--rustc')
    parser.add_argument('--backend',choices=['c','rust'],default='c')
    args=parser.parse_args()
    expected=json.loads(Path(args.expected).read_bytes())
    identity=installed_identity(expected)
    root=Path(args.fixtures).resolve()
    app=root/'examples/packages/typed_text'
    from hepta.packages import write_lock
    from hepta.pipeline import analyze_project
    from hepta.c_backend import compile_c
    from hepta.backend import compile_rust
    source=consumer()
    (app/'src/main.hepta').write_text(source,encoding='utf-8')
    write_lock(app)
    analysis=analyze_project(app,backend=args.backend,crate_type='bin',locked=True,cc=args.cc,rustc=args.rustc)
    require(analysis.report['ok'], 'installed native analysis rejected: '+json.dumps(analysis.report))
    require(len(analysis.project.modules)==7, 'incorrect module graph')
    require(analysis.report['compiler_sha256']==identity['compiler_sha256'], 'compiler identity drift')
    receipts=[]
    for wrong in (False,True):
        if wrong:
            (app/'src/main.hepta').write_text(source.replace('assert(c.value.scalars==0);','assert(c.value.scalars==1);',1),encoding='utf-8')
            write_lock(app)
            analysis=analyze_project(app,backend=args.backend,crate_type='bin',locked=True,cc=args.cc,rustc=args.rustc)
            require(analysis.report['ok'], 'wrong-output control did not compile')
        for optimize in (False,True):
            out=root/f'native-{int(wrong)}-{int(optimize)}'
            build=(compile_c(analysis.c,cc=args.cc,output=out,optimize=optimize,sanitize=True) if args.backend=='c'
                   else compile_rust(analysis.rust,rustc=args.rustc,output=out,crate_type='bin',optimize=optimize))
            require(build['ok'], 'installed compiler build failed: '+json.dumps(build))
            if args.backend=='c':require('-fno-sanitize-recover=all' in build['flags'],'missing sanitizer')
            run=subprocess.run([str(out)],capture_output=True,timeout=30)
            require(run.returncode==(-signal.SIGABRT if wrong else 0),'wrong native outcome')
            require(run.stdout==b'', 'unexpected native stdout')
            if args.backend=='c' or not wrong:require(run.stderr==b'','unexpected native stderr')
            elif wrong:require(b'panicked' in run.stderr,'Rust did not report assertion failure')
            receipts.append({'wrong_output':wrong,'optimize':optimize,'build':build,'returncode':run.returncode,
                             'stdout':run.stdout.decode(),'stderr':run.stderr.decode(),
                             'artifact_sha256':digest(out.read_bytes()),
                             'source_sha256':digest((app/'src/main.hepta').read_bytes())})
    require(installed_identity(expected)==identity,'installed identity changed')
    print(json.dumps({'complete_pass':True,'identity':identity,'vectors':21,'native_receipts':receipts,
                      'backend':args.backend,'whole_project_blockers_closed':False},sort_keys=True))

if __name__=='__main__':
    main()
