#!/usr/bin/env python3
"""Offline compiler-wheel installation and native qualification, not a release."""
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT=Path(__file__).resolve().parents[1]
RECEIPTS=[]


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def snapshot(root):
    return {p.relative_to(root).as_posix():p.read_bytes() for p in sorted(root.rglob('*'))
            if p.is_file() and '.git' not in p.relative_to(root).parts and '__pycache__' not in p.parts and p.suffix!='.pyc'}


def clean_env():
    env=dict(os.environ)
    for key in tuple(env):
        if key.startswith(('PYTHON','PIP_')) or key in ('VIRTUAL_ENV','__PYVENV_LAUNCHER__'):
            env.pop(key)
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1')
    return env


def command(args,cwd,expected=0):
    run=subprocess.run([str(a) for a in args],cwd=cwd,env=clean_env(),capture_output=True,text=True,timeout=180)
    RECEIPTS.append({'command':[str(a) for a in args],'cwd':str(cwd),'returncode':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
    require(run.returncode==expected,'unexpected command status: '+repr(args)+'\n'+run.stdout+run.stderr)
    return run


def materialize(root,files):
    root.mkdir()
    for name,data in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)


def wheel_members(path):
    with zipfile.ZipFile(path) as archive:
        names=archive.namelist()
        require(len(names)==len(set(names)),'duplicate wheel members')
        require(all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts for n in names),'invalid wheel member')
        return {n:archive.read(n) for n in names if not n.endswith('/')}


def validate_wheel(files,expected):
    runtime={n:b for n,b in files.items() if n.startswith('hepta/')}
    require(runtime==expected,'wheel runtime mismatch')
    prefix='hepta_language-0.2.0.dist-info/'
    metadata={'METADATA','WHEEL','entry_points.txt','top_level.txt','RECORD'}
    require(set(files)==set(expected)|{prefix+n for n in metadata},'wheel member inventory mismatch')
    require(files[prefix+'entry_points.txt']==b'[console_scripts]\nhepta = hepta.cli:main\n','wheel entrypoint mismatch')
    rows=list(csv.reader(io.StringIO(files[prefix+'RECORD'].decode())))
    require(len(rows)==len(files) and len({r[0] for r in rows})==len(rows),'wheel RECORD inventory mismatch')
    require({r[0] for r in rows}==set(files),'wheel RECORD members mismatch')
    for name,value,size in rows:
        if name==prefix+'RECORD':require(value==size=='','RECORD self identity mismatch');continue
        digest=base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).decode().rstrip('=')
        require(value=='sha256='+digest and size==str(len(files[name])),'wheel RECORD payload mismatch')


def sdist_members(path):
    files={};roots=set()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            parts=PurePosixPath(member.name)
            require(not parts.is_absolute() and '..' not in parts.parts,'invalid sdist member')
            roots.add(parts.parts[0])
            if member.isdir():continue
            require(member.isfile() and len(parts.parts)>1,'invalid sdist file')
            name=PurePosixPath(*parts.parts[1:]).as_posix()
            require(name not in files,'duplicate sdist member')
            files[name]=archive.extractfile(member).read()
    require(len(roots)==1,'sdist root mismatch')
    return files


def build(source,output,hook):
    output.mkdir()
    command([sys.executable,'-I','-B','-c',f'import setuptools.build_meta as b;b.{hook}({str(output)!r})'],source)
    products=list(output.glob('*.tar.gz' if hook=='build_sdist' else '*.whl'))
    require(len(products)==1,'build product inventory mismatch')
    return products[0]


def expect_rejection(name,files,expected,reason):
    try:validate_wheel(files,expected)
    except ValueError as exc:
        require(str(exc)==reason,'control rejected for unrelated reason: '+str(exc))
        return {'name':name,'rejected':True,'reason':str(exc)}
    raise ValueError('negative control accepted: '+name)


def main():
    require(__debug__,'assertions must remain enabled')
    parser=argparse.ArgumentParser()
    parser.add_argument('--target-python',default=sys.executable)
    parser.add_argument('--backend',choices=['c','rust'],default='c')
    parser.add_argument('--cc',default='gcc')
    parser.add_argument('--rustc',default='rustc')
    args=parser.parse_args()
    require(sys.platform=='linux','qualified installer/native profile is Linux only')
    target=shutil.which(args.target_python);cc=shutil.which(args.cc)
    require(target and cc,'selected Python or C compiler missing')
    target=str(Path(target).absolute());cc=str(Path(cc).resolve())
    rustc=shutil.which(args.rustc) if args.backend=='rust' else None
    if args.backend=='rust':require(rustc is not None,'required Rust compiler missing')
    source=snapshot(ROOT)
    components=json.loads(source['tools/installed_compiler_components.json'])
    require(components['parent_commit']=='0594a85f2f1e05ef50a61bf9c5a18ae191499502','wrong parent')
    require(len(components['files'])==34,'component inventory mismatch')
    for path,digest in components['files'].items():require(sha(source[path])==digest,'parent component changed: '+path)
    expected={n:b for n,b in source.items() if n.startswith('hepta/') and n.endswith('.py')}
    require(len(expected)==16,'compiler runtime inventory mismatch')
    config=tomllib.loads(source['pyproject.toml'].decode())
    require(config['tool']['setuptools']['packages']==['hepta'] and config['project']['dependencies']==[],'packaging scope changed')
    require(config['build-system']['build-backend']=='setuptools.build_meta','unexpected build backend')
    installed=[];controls=[]
    with tempfile.TemporaryDirectory(prefix='hepta-installed-qualification-') as temporary:
        root=Path(temporary)
        neutral=root/'neutral';neutral.mkdir()
        poison=neutral/'hepta';poison.mkdir();(poison/'__init__.py').write_text('raise RuntimeError("checkout import sentinel")\n')
        compiler={'path':cc,'sha256':sha(Path(cc).read_bytes()),'version':command([cc,'--version'],neutral).stdout,'target':command([cc,'-dumpmachine'],neutral).stdout.strip()}
        if rustc:
            rustc=str(Path(rustc).absolute())
            version=command([rustc,'--version'],neutral).stdout
            require(version.startswith('rustc 1.90.0 '),'required Rust version mismatch')
            compiler['rust']={'path':rustc,'version':version,'sha256':sha(Path(rustc).read_bytes())}
        stage=root/'source';materialize(stage,source)
        direct=build(stage,root/'direct','build_wheel')
        # A second clean full-source copy prevents wheel build metadata from
        # affecting sdist inputs; no dependency resolver/network invocation.
        ssource=root/'sdist-source';materialize(ssource,source)
        archive=build(ssource,root/'sdist','build_sdist')
        members=sdist_members(archive)
        require(all(members.get(n)==b for n,b in expected.items()),'sdist lost compiler source')
        unpacked=root/'unpacked';materialize(unpacked,members)
        rebuilt=build(unpacked,root/'rebuilt','build_wheel')
        wheels=[('direct',direct),('sdist-rebuilt',rebuilt)]
        direct_files=wheel_members(direct);rebuilt_files=wheel_members(rebuilt)
        validate_wheel(direct_files,expected);validate_wheel(rebuilt_files,expected)
        require(direct_files==rebuilt_files,'direct/rebuilt wheel member bytes differ')
        for name,files,reason in [
            ('missing_runtime',{n:b for n,b in direct_files.items() if n!='hepta/c_float_conversions.py'},'wheel runtime mismatch'),
            ('changed_runtime',{**direct_files,'hepta/c_backend.py':direct_files['hepta/c_backend.py']+b'\n'},'wheel runtime mismatch'),
            ('missing_entrypoint',{n:b for n,b in direct_files.items() if not n.endswith('/entry_points.txt')},'wheel member inventory mismatch'),
            ('changed_record',{**direct_files,'hepta_language-0.2.0.dist-info/RECORD':b''},'wheel RECORD inventory mismatch')]:
            controls.append(expect_rejection(name,files,expected,reason))
        # Delete only disposable copies we just created. Execution must not need
        # their paths; archives remain until all installed checks finish.
        shutil.rmtree(stage);shutil.rmtree(ssource);shutil.rmtree(unpacked)
        fixture_files={n:source[n] for n in components['files'] if n.startswith(('stdlib/','examples/'))}
        expected_file=root/'runtime.json';expected_file.write_text(json.dumps({n:sha(b) for n,b in expected.items()}))
        probe=root/'probe.py';probe.write_bytes(source['tools/installed_compiler_probe.py'])
        independent_hash=hashlib.sha256()
        for n,b in sorted(expected.items()):independent_hash.update(Path(n).name.encode()+b'\0'+b+b'\0')
        for label,wheel in wheels:
            env=root/(label+'-env')
            command([target,'-I','-B','-m','venv','--without-pip',env],neutral)
            py=env/'bin/python';console=env/'bin/hepta'
            require('include-system-site-packages = false' in (env/'pyvenv.cfg').read_text(),'system-site packages enabled')
            # Existing trusted installer targets a fresh environment; no backend
            # or package dependencies are fetched, built, or resolved here.
            command([sys.executable,'-I','-B','-m','pip','--python',py,'install','--no-index','--no-deps','--no-compile',wheel],neutral)
            for invocation in ([console],[py,'-I','-B','-m','hepta']):
                run=command(invocation+['--version'],neutral)
                require(run.stdout=='hepta 0.2.0\n' and run.stderr=='','installed version output mismatch')
            sentinel=subprocess.run([str(py),'-B','-m','hepta','--version'],cwd=neutral,env=clean_env(),capture_output=True,text=True,timeout=30)
            require(sentinel.returncode!=0 and 'checkout import sentinel' in sentinel.stderr,'import sentinel was ineffective')
            controls.append({'name':label+'_cwd_import','rejected':True,'returncode':sentinel.returncode,'stderr':sentinel.stderr})
            fixture=root/(label+'-fixtures');materialize(fixture,fixture_files)
            moved=root/(label+'-relocated');fixture.rename(moved)
            app=moved/'examples/packages/typed_text'
            original_lock=(app/'Hepta.lock').read_bytes()
            selectors=['--backend',args.backend,'--cc',cc]+(['--rustc',rustc] if rustc else [])
            for invocation in ([console],[py,'-I','-B','-m','hepta']):
                run=command(invocation+['run',app,'--locked','--json']+selectors,neutral)
                report=json.loads(run.stdout)
                require(report['ok'] and report['returncode']==0 and report['stdout']==report['stderr']==run.stderr=='','installed CLI execution mismatch')
            dep=moved/'stdlib/utf8/src/lib.hepta';data=dep.read_bytes();dep.write_bytes(data+b'\n// installed stale-lock control\n')
            run=command([console,'check',app,'--locked','--json']+selectors,neutral,1)
            rejected=json.loads(run.stdout)
            require([d['code'] for d in rejected['diagnostics']]==['E_LOCK_STALE'],'incorrect stale-lock rejection')
            require((app/'Hepta.lock').read_bytes()==original_lock,'stale check changed lock')
            dep.write_bytes(data)
            destination=moved/'program'
            run=command([console,'build',app,'--locked','--json','--output',destination]+selectors,neutral)
            built=json.loads(run.stdout)
            require(built['ok'] and built['validation']['compiler_sha256']==independent_hash.hexdigest(),'build compiler mismatch')
            run=command([destination],neutral);require(run.stdout==run.stderr=='','native artifact output mismatch')
            require((app/'Hepta.lock').read_bytes()==original_lock,'relocation changed lock')
            cmd=[py,'-I','-B',probe,'--expected',expected_file,'--fixtures',moved,'--cc',cc,'--backend',args.backend]
            if rustc:cmd+=['--rustc',rustc]
            # The installed verifier must reject actual missing installed bytes,
            # not merely a synthetic in-memory wheel mutation.
            site=Path(command([py,'-I','-B','-c',"import sysconfig;print(sysconfig.get_path('purelib'))"],neutral).stdout.strip())
            runtime_file=site/'hepta/c_float_conversions.py'
            parked=site/'hepta/c_float_conversions.saved'
            runtime_file.rename(parked)
            try:
                missing=command(cmd,neutral,1)
                require('installed runtime payload mismatch' in missing.stderr,'installed absence rejected for unrelated reason')
                controls.append({'name':label+'_missing_installed_module','rejected':True,'returncode':missing.returncode,'stderr':missing.stderr})
            finally:
                parked.rename(runtime_file)
            probed=command(cmd,neutral)
            result=json.loads(probed.stdout)
            require(result['complete_pass'] and result['identity']['compiler_sha256']==independent_hash.hexdigest(),'installed probe identity mismatch')
            require(len(result['native_receipts'])==4 and result['vectors']==21,'native probe coverage mismatch')
            installed.append({'label':label,'wheel_sha256':sha(wheel.read_bytes()),'probe':result,'cli_native_runs':3,'stale_lock_rejected':True,'lock_relocation_unchanged':True})
        require(installed[0]['probe']['identity']['runtime_sha256']==installed[1]['probe']['identity']['runtime_sha256'],'installed payloads differ')
        require(sha(Path(cc).read_bytes())==compiler['sha256'],'C compiler changed')
    require(snapshot(ROOT)==source,'qualification source changed')
    print(json.dumps({'complete_pass':True,'parent_commit':components['parent_commit'],
        'python':sys.version,'setuptools':importlib.metadata.version('setuptools'),'pip':importlib.metadata.version('pip'),
        'target_python':target,'host':platform.platform(),'backend':args.backend,'compiler':compiler,
        'source_sha256':{n:sha(b) for n,b in source.items()},'runtime_files':len(expected),
        'wheel_member_count':len(direct_files),'wheel_member_bytes_equal':True,'installed':installed,
        'negative_controls':controls,'commands':RECEIPTS,'source_unchanged':True,'archives_uploaded':0,
        'whole_project_blockers_closed':False,'production_release_qualified':False},sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'complete_pass':False,'error':type(exc).__name__+': '+str(exc),'commands':RECEIPTS},sort_keys=True))
        raise
