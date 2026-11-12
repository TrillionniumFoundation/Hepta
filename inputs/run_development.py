#!/usr/bin/env python3
"""Run the exact eight added controls in a separate retained-compiler scope."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import importlib.util
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import traceback
import zlib

HERE=Path(__file__).resolve().parent
HARNESS=HERE.parent
BASE='64f67ae897c3cb49d45a1e1a4622db974812e3fe'
BASE_TREE='b7cf3502931d5fae8f58444b0af04cc642414a4a'
AUTHORED_TREE='fe8fb1fdccdbaccb0d41ca6e1b18eb8cb7bb7380'
SOURCE_HARNESS_TREE='454ca062d3f7aa2a8fe27c332209e5c39d84990e'
COMPILER_SHA='81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module

HELPER=load('v80_exact_source_manifest',HERE/'source_manifest.py')
SUPERVISOR=load('v80_original_workflow_process',HERE/'workflow_process.py')

def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')

def git(root,*args):
    p=subprocess.run(['git','--no-replace-objects','-C',str(root),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout

def git_rows(root):
    result={}
    for item in git(root,'ls-tree','-r','-z','HEAD').split(b'\0'):
        if not item:continue
        info,name=item.split(b'\t',1);mode,kind,digest=info.decode().split()
        assert kind=='blob' and mode in ('100644','100755')
        result[name.decode()]={'mode':mode,'blob':digest}
    return result

def actual_rows(root,names):
    result={}
    for name in names:
        p=root/name;assert p.is_file() and not p.is_symlink(),name
        result[name]={**HELPER.identify(p.read_bytes()),'mode':'100755' if p.stat().st_mode & 0o111 else '100644'}
    return result

def process_complete(value):
    cleanup=value.get('cleanup',{})
    return (value.get('status')=='WORKFLOW_STEP_COMPLETED'
            and type(value.get('returncode')) is int and value['returncode']==0
            and value.get('timed_out') is False and cleanup.get('complete') is True
            and cleanup.get('errors')==[] and cleanup.get('full_process_tree_claimed') is False)


def materialize_git_archive(archive,source,expected,observations):
    """Verify Git file type/executable class, then write exact canonical modes."""
    seen=set()
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as tar:
        for member in tar:
            if member.isdir():continue
            observations[member.name]={'archive_mode':member.mode,'archive_type':member.type.hex()}
            assert member.isfile() and not member.issym() and not member.islnk(),member.name
            assert member.name in expected and member.name not in seen,member.name
            row=expected[member.name]
            assert row['mode'] in ('100644','100755'),member.name
            assert type(member.mode) is int and member.mode>=0 and member.mode & ~0o777==0,member.name
            canonical=0o755 if row['mode']=='100755' else 0o644
            assert bool(member.mode & 0o111)==(canonical==0o755),member.name
            raw=tar.extractfile(member).read()
            assert HELPER.identify(raw)=={k:row[k] for k in ('bytes','sha256','blob')},member.name
            target=source/member.name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw);target.chmod(canonical)
            assert target.is_file() and not target.is_symlink() and target.stat().st_mode & 0o777==canonical
            assert HELPER.identify(target.read_bytes())=={k:row[k] for k in ('bytes','sha256','blob')}
            observations[member.name].update(git_mode=row['mode'],materialized_mode=canonical,bytes_verified=True)
            seen.add(member.name)
    assert seen==set(expected)
    return {'bytes':len(archive),'sha256':sha256(archive).hexdigest(),'source_files':len(seen),
            'complete_source_recoverable_from_git':True,'materialization':'REGULAR_FILE_GIT_EXECUTABLE_CLASS_AND_EXACT_CANONICAL_TARGET_MODE'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--base-source',required=True);parser.add_argument('--development',required=True);parser.add_argument('--evidence',required=True)
    args=parser.parse_args();base=Path(args.base_source).resolve(strict=True);dev=Path(args.development).resolve();out=Path(args.evidence).resolve()
    assert not dev.exists() and not out.exists()
    assert not dev.is_relative_to(base) and not base.is_relative_to(dev)
    dev.mkdir();out.mkdir()
    report={'schema':'hia.global-import.eight-controls.development.v80.r2','status':'RUNNING',
            'scope':'EXACT_PUBLISHED_BASE_PLUS_FROZEN_REPAIR_AND_SEPARATELY_RECORDED_DEVELOPMENT_GENERATION',
            'python':sys.version,'source_generation_run':43294252598,'source_generation_result_transferred':False,
            'current_source_cold':False,'whole_native':False,'full_suite':False,'default_changed':False,
            'compiler_child_seconds':20,'ordinary_supervisor_seconds':1800,'commands':[]}
    save(out/'REPORT.json',report)
    env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_')}
    env.update(PYTHONDONTWRITEBYTECODE='1',HIA_V80_DEVELOPMENT_ROOT=str(dev))
    def run(label,argv,cwd):
        result=SUPERVISOR.run_workflow_step(argv,cwd=cwd,env=env,
            stdout_path=out/(label+'.stdout'),stderr_path=out/(label+'.stderr'),receipt_path=out/(label+'.PROCESS.json'),seconds=1800)
        report['commands'].append({'label':label,'argv':argv,'receipt':result})
        save(out/'REPORT.json',report)
        return process_complete(result)
    try:
        assert sys.version_info[:3]==(3,14,4),'exact Python 3.14.4 required'
        assert sys.platform=='linux'
        packages={'setuptools':'78.1.1','wheel':'0.46.3','z3-solver':'4.15.4.0','jsonschema':'4.26.0'}
        observed_packages={name:importlib.metadata.version(name) for name in packages}
        assert observed_packages==packages
        report['observed_packages']=observed_packages
        assert sha256((HERE/'workflow_process.py').read_bytes()).hexdigest()=='f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
        inputs=json.loads((HERE/'INPUTS.json').read_bytes())
        for name,expected in inputs['files'].items():
            assert HELPER.identify((HARNESS/name).read_bytes())==expected,name
        harness_rows=git_rows(HARNESS)
        harness_before=actual_rows(HARNESS,harness_rows)
        assert all({k:harness_before[n][k] for k in ('mode','blob')}==r for n,r in harness_rows.items())
        assert git(HARNESS,'ls-tree','HEAD','source-harness').decode().split()[:3]==['040000','tree',SOURCE_HARNESS_TREE]
        assert git(base,'rev-parse','HEAD').decode().strip()==BASE
        assert git(base,'rev-parse','HEAD^{tree}').decode().strip()==BASE_TREE
        assert not git(base,'status','--porcelain=v1','--untracked-files=all').strip()
        raw=(HARNESS/'source-harness/inputs/SOURCE-CHECKPOINT.zlib.json').read_bytes()
        assert HELPER.identify(raw)['blob']=='c32a398f344e10149d629b064356469baeaa32da'
        packet=json.loads(zlib.decompress(base64.b64decode(json.loads(raw)['payload'])))
        expected=packet['base_manifest'];rows=git_rows(base)
        assert len(rows)==len(expected)==3255 and set(rows)==set(expected)
        assert all(rows[n]=={k:expected[n][k] for k in ('mode','blob')} for n in rows)
        before=actual_rows(base,rows);assert before==expected
        assert HELPER.tree_hash(before)==BASE_TREE
        save(out/'BASE-SOURCE.json',before)
        archive=git(base,'archive','--format=tar','HEAD')
        source=dev/'source';source.mkdir()
        archive_modes={}
        try:
            report['base_archive']=materialize_git_archive(archive,source,expected,archive_modes)
        finally:
            save(out/'ARCHIVE-MODES.json',archive_modes)
        del archive
        copy=dev/'source-harness';shutil.copytree(HARNESS/'source-harness',copy)
        composed=run('compose',[sys.executable,'-B',str(copy/'tools/compose_global_repairs.py'),'--harness',str(copy),'--output',str(out/'composition')],dev)
        assert composed,'exact overlay composition failed'
        overlay=json.loads((copy/'overlay/source-overlay.json').read_bytes())
        assert overlay['base_commit']==BASE and overlay['base_tree']==BASE_TREE and len(overlay['files'])==24
        for row in overlay['files']:
            raw=row['content'].encode();assert HELPER.identify(raw)=={k:row[k] for k in ('bytes','sha256','blob')}
            target=source/row['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(int(row['mode'],8)&0o777)
        authored=HELPER.manifest(source);assert len(authored)==3257 and HELPER.tree_hash(authored)==AUTHORED_TREE
        save(out/'AUTHORED-SOURCE.json',authored)
        compiler=json.loads((HERE/'retained-compiler.json').read_bytes());binary=base64.b64decode(compiler['data'],validate=True)
        assert len(binary)==669494 and sha256(binary).hexdigest()==COMPILER_SHA
        compiler_path=dev/'retained-development-compiler.bin';compiler_path.write_bytes(binary);compiler_path.chmod(0o444)
        env['HIA_V80_RETAINED_COMPILER']=str(compiler_path)
        prepared=run('prepare-development-images',[sys.executable,'-B',str(HERE/'prepare_development_images.py')],dev)
        frozen=HELPER.manifest(source)
        changed=[n for n in authored if authored[n]!=frozen.get(n)]
        assert set(frozen)==set(authored) and set(changed)<={'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json','docs/HIA_SELFHOST_CORE_SUPPORT.json'}
        save(out/'FROZEN-DEVELOPMENT-SOURCE.json',frozen)
        inputs_before=HELPER.manifest(dev/'development-images-r2')
        controls=run('eight-added-controls',[sys.executable,'-B',str(HERE/'run_new_controls.py')],dev)
        final=HELPER.manifest(source);images_after=HELPER.manifest(dev/'development-images-r2')
        assert final==frozen and inputs_before==images_after
        assert compiler_path.read_bytes()==binary
        result_path=dev/'new-controls-r1/REPORT.json'
        result=json.loads(result_path.read_bytes()) if result_path.is_file() else None
        report['added_controls']=result
        inner_process=dev/'new-controls-r1/PROCESS.json'
        inner=json.loads(inner_process.read_bytes()) if inner_process.is_file() else {}
        report['original_added_control_supervisor']=inner
        native_ids=[] if result is None else result.get('loaded_ids',[])[3:]
        native_counts={name:sum(count for key,count in result.get('actual_native_returns',{}).items()
                               if key.endswith(':'+name)) for name in native_ids} if result else {}
        report['per_native_method_machine_returns']=native_counts
        passed=(prepared and controls and process_complete(inner)
                and len(native_counts)==5 and all(type(n) is int and n>0 for n in native_counts.values())
                and result is not None and result.get('status')=='PASS'
                and result.get('tests_run')==8 and result.get('loaded_ids')==result.get('executed_ids')
                and result.get('source_unchanged') is True and result.get('total_actual_native_returns',0)>0
                and all(result.get(k)==[] for k in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses')))
        changed_records=[]
        for name in sorted(set(final)|set(before)):
            if final.get(name)!=before.get(name):
                raw=(source/name).read_bytes();changed_records.append({'path':name,**final[name],'content':raw.decode('utf-8'),'before':before.get(name)})
        source_packet={'schema':'hia.global-import.development-source.v80.r1','base_commit':BASE,'base_tree':BASE_TREE,
                       'base_files':before,'final_files':final,'files':changed_records,'source_tree':HELPER.tree_hash(final),
                       'current_cold':False,'scope':'SEPARATE_DEVELOPMENT_GENERATION_NOT_THE_SOURCE_GATE_OUTPUT'}
        save(out/'SOURCE-PACKET.json',source_packet)
        assert actual_rows(base,rows)==before and actual_rows(HARNESS,harness_rows)==harness_before
        report.update(status='PASS' if passed else 'FAIL',source_tree=HELPER.tree_hash(final),source_files=len(final),
            source_and_all_image_inputs_unchanged=True,authored_tree=AUTHORED_TREE,development_generated_paths=changed,
            original_eight_selectors_preserved=True,original_test_bodies_unchanged=True,harness_unchanged=True,base_unchanged=True)
    except BaseException:
        report.update(status='FAIL',exception=traceback.format_exc());traceback.print_exc()
    finally:
        save(out/'REPORT.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('commands','added_controls')},sort_keys=True))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
