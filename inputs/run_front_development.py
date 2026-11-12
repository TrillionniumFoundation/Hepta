"""Isolated actual CPython3.14.4 public-front development, revision1.

Exact4b checkout plus twelve declared source paths. Only public_front.hiaasm
and its fixed ports may be generated. No registered default or cold report is
used; the retained81b6 compiler is only an explicitly borrowed development input.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1,sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import traceback
import zlib
from source_custody import (digest,wire,write,safe,metadata,files,admit_git_snapshot,
                            source_identity,apply_files,export_source)

BASE='4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE='1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
PARENT='5f7f95367e8e395863801487e969d286b9091110'
OVERLAY_SHA='eab1ffb4478c22ceaef242e5b83a48f6f2a36ce0edef01076f42eff19c12c290'
OVERLAY_BYTES=223881
COMPILER_PACKET_SHA='df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
COMPILER_SHA='81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
GENERATED={'examples/hia_bootstrap/public_front.hiaasm','hepta/hia_public_front_ports.py'}
PACKAGES={'setuptools':'78.1.1','wheel':'0.46.3','z3-solver':'4.15.4.0','jsonschema':'4.26.0'}

def read_overlay(path,original):
    raw=path.read_bytes()
    if len(raw)!=OVERLAY_BYTES or digest(raw)!=OVERLAY_SHA:
        raise ValueError('frozen public-front overlay differs')
    value=json.loads(raw)
    if (value['schema']!='hia.public-front.development-overlay.v80.r1'
            or value['base_commit']!=BASE or value['base_tree']!=TREE
            or value['base_file_count']!=3153 or value['deleted']!=[]
            or len(value['files'])!=12 or set(value['generated_outputs'])!=GENERATED
            or value['scope']['current_cold'] is not False):
        raise ValueError('public-front scope/identity differs')
    for name,row in value['files'].items():
        safe(name)
        raw=row['text'].encode('utf-8')
        if (len(raw)!=row['bytes'] or digest(raw)!=row['sha256'] or row['mode']!='100644'
                or sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=row['git_blob_sha']):
            raise ValueError('complete source bytes differ: '+name)
        before=row['before']
        if before is None:
            if name in original:raise ValueError('new source overwrites existing file: '+name)
        elif name not in original or source_identity(original[name])!=source_identity(before):
            raise ValueError('exact4b source dependency differs: '+name)
    return value

def restore_compiler(path,out):
    raw=path.read_bytes()
    if digest(raw)!=COMPILER_PACKET_SHA:raise ValueError('retained compiler packet differs')
    saved=json.loads(raw)
    zipped=base64.b64decode(saved['compiler_zlib_base64'],validate=True)
    if len(zipped)!=saved['compressed_bytes'] or digest(zipped)!=saved['compressed_sha256']:
        raise ValueError('retained compiler compression differs')
    decoder=zlib.decompressobj()
    image=decoder.decompress(zipped,669495)
    if decoder.unconsumed_tail:raise ValueError('retained compiler exceeds original extent')
    image+=decoder.flush()
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(image)!=669494 or digest(image)!=COMPILER_SHA):
        raise ValueError('actual original compiler bytes differ')
    target=out/'retained-B3.image.bin';write(target,image);target.chmod(0o444)
    receipt=saved['original_receipt_utf8'].encode()
    if digest(receipt)!=saved['original_receipt_sha256']:raise ValueError('retained original receipt differs')
    write(out/'retained-B3.original-receipt.json',receipt)
    return target,{'actual_bytes':669494,'sha256':COMPILER_SHA,
        'original_artifact':saved['original_artifact'],
        'scope':'BORROWED_OLD_COMPILER_DEVELOPMENT_ONLY_NO_CURRENT_COLD_AUTHORITY'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--inputs',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    root=args.source.resolve(strict=True);inputs=args.inputs.resolve(strict=True)
    out=args.output.absolute();out.mkdir(mode=0o700,exist_ok=False)
    report={'schema':'hia.public-front.source-development-ci.v80.r1','status':'STARTED',
        'base_commit':BASE,'base_tree':TREE,'python':sys.version,'platform':platform.platform(),
        'scope':'NEW_OWNER_DEVELOPMENT_ONLY','current_source_cold':False,'public_selected':False,
        'whole_normalization':False,'physical_recursion':False,'default_activated':False,
        'commands':[],'compiler_child_seconds':20,'direct_group_seconds':240}
    expected=None;selected_inputs={};started=time.monotonic_ns();before_inputs=files(inputs)
    env=os.environ.copy()
    report['cleared_selectors']=sorted(k for k in env if k.startswith('HEPTA_'))
    for k in report['cleared_selectors']:del env[k]
    env['PYTHONDONTWRITEBYTECODE']='1'

    def command(label, argv, *, seconds=240, environment=None, allow_failure=False):
        row = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(root),
               'timeout_seconds': seconds}
        report['commands'].append(row)
        stdout, stderr = out / (label + '.stdout.log'), out / (label + '.stderr.log')
        begin = time.monotonic_ns()
        try:
            with stdout.open('xb') as so, stderr.open('xb') as se:
                child = subprocess.Popen(list(map(str, argv)), cwd=root,
                    env=env if environment is None else environment,
                    stdin=subprocess.DEVNULL, stdout=so, stderr=se, start_new_session=True)
                row['pid'] = child.pid
                try:
                    row['returncode'] = child.wait(timeout=seconds)
                    row['timed_out'] = False
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    os.killpg(child.pid, signal.SIGKILL)
                    row['returncode'] = child.wait()
                    if not allow_failure: raise
        finally:
            row['elapsed_ns'] = time.monotonic_ns() - begin
            for kind, path in (('stdout', stdout), ('stderr', stderr)):
                if path.exists():
                    row[kind] = {'path': path.name, 'bytes': path.stat().st_size,
                                 'sha256': digest(path.read_bytes())}
            write(out / (label + '.terminal.json'), wire(row))
        if row['returncode'] and not allow_failure:
            raise RuntimeError('original command failed: ' + label)
        return stdout.read_bytes()

    def guard(label):
        observed=files(root);write(out/(label+'.source.json'),wire(observed))
        if observed!=expected:raise ValueError('frozen source changed: '+label)
        if files(inputs)!=before_inputs:raise ValueError('frozen harness input changed: '+label)
        for path,row in selected_inputs.items():
            if metadata(path)!=row:raise ValueError('held native input changed: '+str(path))

    try:
        if (sys.implementation.name!='cpython' or sys.version_info[:3]!=(3,14,4)
                or platform.system()!='Linux' or platform.machine()!='x86_64'
                or platform.freedesktop_os_release().get('ID')!='ubuntu'
                or platform.freedesktop_os_release().get('VERSION_ID')!='24.04'):
            raise ValueError('actual CPython3.14.4 Ubuntu24.04 x86_64 required')
        report['packages']={name:importlib.metadata.version(name) for name in PACKAGES}
        if report['packages']!=PACKAGES:raise ValueError('pinned Python package differs')
        if command('base-head',['git','rev-parse','HEAD']).decode().strip()!=BASE:
            raise ValueError('actual base commit differs')
        if command('base-tree',['git','rev-parse','HEAD^{tree}']).decode().strip()!=TREE:
            raise ValueError('actual base tree differs')
        if command('base-parent',['git','rev-parse','HEAD^']).decode().strip()!=PARENT:
            raise ValueError('actual base parent differs')
        if command('base-status',['git','status','--porcelain=v1','--untracked-files=all']):
            raise ValueError('actual base checkout is not clean')
        original=files(root)
        admit_git_snapshot(root,original,command('base-records',['git','ls-tree','-r','-z','--full-tree','HEAD']))
        if len(original)!=3153:raise ValueError('complete3153 base required')
        write(out/'source-before.json',wire(original))
        overlay=read_overlay(inputs/'public-front-overlay.json',original)
        apply_files(root,overlay['files'])
        authored=files(root)
        wanted={name:source_identity(row) for name,row in original.items()}
        wanted.update({name:source_identity(row) for name,row in overlay['files'].items()})
        if ({name:source_identity(row) for name,row in authored.items()}!=wanted
                or len(authored)!=overlay['authored_file_count']):
            raise ValueError('complete authored source differs')
        write(out/'source-authored.json',wire(authored))
        command('generate-front',[sys.executable,'-B','-m','tools.generate_hia_public_front'])
        expected=files(root)
        changed={name for name in set(authored)|set(expected) if authored.get(name)!=expected.get(name)}
        if changed!=GENERATED or len(expected)!=overlay['generated_file_count']:
            raise ValueError('generation changed an unrelated source or omitted an output')
        command('regenerate-front-check',[sys.executable,'-B','-m','tools.generate_hia_public_front','--check'])
        guard('after-generation')
        report['source_files']=len(expected);write(out/'frozen-source.json',wire(expected))
        changes=sorted(set(overlay['files'])|GENERATED)
        actual_changes={name for name in set(original)|set(expected) if original.get(name)!=expected.get(name)}
        if not actual_changes<=set(changes):raise ValueError('unexpected source delta')
        report['actual_source_delta']=sorted(actual_changes)
        command('stage-source',['git','add','--',*changes])
        report['development_write_tree']=command('write-tree',['git','write-tree']).decode().strip()
        command('source-patch',['git','diff','--cached','--binary','--full-index','HEAD'])
        command('source-whitespace',['git','diff','--cached','--check'],allow_failure=True)
        compiler,report['retained_compiler']=restore_compiler(inputs/'retained-compiler.json',out)
        selected_inputs[compiler]=metadata(compiler)
        guard('before-direct-entries')
        command('direct-entries',[sys.executable,'-B',inputs/'run_front_entries.py',
            '--source',root,'--compiler',compiler,'--output',out/'direct-entries'],
            seconds=240,allow_failure=True)
        guard('after-direct-entries')
        report['direct']=json.loads((out/'direct-entries/REPORT.json').read_bytes())
        if report['direct']['status']!='DEVELOPMENT_DIRECT_ENTRY_PASS':
            raise ValueError('actual original/native direct entry differential failed')
        if any(row.get('returncode')!=0 or row.get('timed_out') is not False for row in report['commands']):
            raise ValueError('an actual development command failed')
        report['status']='DEVELOPMENT_DIRECT_ENTRY_PASS'
    except BaseException:
        report.update(status='FAIL',traceback=traceback.format_exc())
    finally:
        try:
            if expected is not None:
                guard('final');report['source_and_inputs_unchanged']=True
            observed=files(root);write(out/'source-final-observed.json',wire(observed))
            report['source_export']=export_source(root,out,observed)
        except BaseException:
            report.update(status='FAIL',custody_error=traceback.format_exc())
        report['elapsed_ns']=time.monotonic_ns()-started
        write(out/'REPORT.json',wire(report))
        write(out/'ARTIFACT-FILES.json',wire({p.relative_to(out).as_posix():metadata(p)
            for p in sorted(out.rglob('*')) if p.is_file()}))
        print(json.dumps({'status':report['status'],'source_files':report.get('source_files'),
                          'cold':False,'whole_normalization':False}),flush=True)
    return 0 if report['status']=='DEVELOPMENT_DIRECT_ENTRY_PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
