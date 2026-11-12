"""Independent exact-source CPython 3.14.4 development of nine Evaluation bodies.

Authentic Git HEAD remains published4b. A frozen joint source recipe is only a
development dependency. All generated files, reports and actual failures are
new observations. No current-cold/default/full-native qualification is inferred.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1,sha256
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import traceback
import zipfile
import zlib
from workflow_process import run_workflow_step

INPUTS=Path(__file__).resolve().parent
HEAD='4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE='1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
JOINT='794d441e1b44e3478f779c900d1fbf5319b8c2c5'
JOINT_TREE='4574f06c479e70849f955934d55d8b58a68f00ff'
JOINT_SOURCE_TREE='be497004503dba10759a5107caa43714910f511b'
JOINT_OVERLAY_SHA='eb26f329484558f4ff3639795d897f288230815715d10c93223bd9a14a69641c'
COMPILER_SHA='81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
STAGES=('prepare','generate','source','build','helper-binding','component','agent','namespace','ledger','finish')

def require(ok,message):
    if not ok:raise AssertionError(message)

def read(path):return json.loads(Path(path).read_bytes())
def sha(raw):return sha256(raw).hexdigest()
def blob(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def identity(raw):return {'bytes':len(raw),'sha256':sha(raw),'blob':blob(raw)}
def write(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with Path(path).open('xb') as stream:stream.write(raw)
    require(Path(path).read_bytes()==raw,'new report readback differs')
    return identity(raw)

def git(root,*args):
    return subprocess.check_output(['git','--no-replace-objects','-C',str(root),*args],timeout=30)

def tree_id(files):
    root={}
    for path,row in files.items():
        node=root
        parts=path.split('/')
        for part in parts[:-1]:node=node.setdefault(part,{})
        node[parts[-1]]=(row['mode'],row['blob'])
    def rec(node):
        items=[]
        for name,value in node.items():
            directory=type(value) is dict
            mode,digest=('40000',rec(value)) if directory else value
            items.append(((name+'/' if directory else name).encode(),mode,name,digest))
        body=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)
                      for _,mode,name,digest in sorted(items))
        return sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
    return rec(root)

def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        relative=path.relative_to(root).as_posix()
        if '.git' in path.relative_to(root).parts:continue
        if path.is_dir():continue
        require(path.is_file() and not path.is_symlink(),'source is not an ordinary file: '+relative)
        require('__pycache__' not in path.parts,'unexpected source bytecode')
        raw=path.read_bytes()
        result[relative]=dict(mode='100755' if path.stat().st_mode&0o111 else '100644',**identity(raw))
    return result

def admit_git(root,head,tree,count=None):
    require(git(root,'rev-parse','HEAD').decode().strip()==head,'authentic checkout HEAD differs')
    require(git(root,'rev-parse','HEAD^{tree}').decode().strip()==tree,'authentic checkout tree differs')
    entries=git(root,'ls-tree','-r','-z','HEAD')
    actual=snapshot(root)
    original={}
    for entry in entries.split(b'\0'):
        if not entry:continue
        meta,path=entry.split(b'\t',1);mode,kind,digest=meta.decode().split();path=path.decode()
        require(kind=='blob' and mode in ('100644','100755'),'unsupported tracked object')
        row=actual.get(path)
        require(row is not None and row['blob']==digest and row['mode']==mode,'actual checkout bytes differ: '+path)
        original[path]=row
    require(actual==original,'checkout includes untracked input')
    if count is not None:require(len(actual)==count,'complete source denominator differs')
    require(tree_id(actual)==tree,'independent complete Git tree reconstruction differs')
    return actual

def current_source(source,output):
    require(git(source,'rev-parse','HEAD').decode().strip()==HEAD,'actual product HEAD changed')
    expected=read(output/'GENERATED-SOURCE.json')
    actual=snapshot(source)
    require(actual==expected,'all frozen candidate bytes/modes/membership changed')
    return actual

def env():
    value=dict(os.environ)
    for key in tuple(value):
        if key.startswith('HEPTA_'):del value[key]
    value.update(PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',CLANG='clang-20',HEPTA_CLANG='clang-20')
    return value

def command(source,output,label,argv,environment=None,seconds=1800):
    print(json.dumps({'stage':label,'argv':list(argv),'limit_seconds':seconds}),flush=True)
    receipt=run_workflow_step(argv,cwd=source,env=env() if environment is None else environment,
        stdout_path=output/(label+'.stdout.log'),stderr_path=output/(label+'.stderr.log'),
        receipt_path=output/(label+'.terminal.json'),seconds=seconds)
    print(json.dumps({'stage':label,'status':receipt['status'],'returncode':receipt['returncode'],
                      'seconds':receipt['seconds']}),flush=True)
    if receipt['status']!='WORKFLOW_STEP_COMPLETED':
        for suffix in ('stdout','stderr'):
            raw=(output/(label+'.'+suffix+'.log')).read_bytes()
            print(raw[-12000:].decode('utf-8','backslashreplace'),flush=True)
    return receipt

def check_inputs():
    expected=read(INPUTS/'FROZEN-INPUTS.json')
    actual={p.name:identity(p.read_bytes()) for p in INPUTS.iterdir()
            if p.is_file() and p.name!='FROZEN-INPUTS.json'}
    require(actual==expected,'complete immutable P1 harness inputs differ')
    return actual

def runtime():
    require(sys.implementation.name=='cpython' and sys.version_info[:3]==(3,14,4)
            and sys.platform=='linux' and platform.machine()=='x86_64',
            'actual CPython3.14.4 Linux x86-64 required')
    versions={name:importlib.metadata.version(name) for name in ('setuptools','wheel','jsonschema','z3-solver')}
    require(versions=={'setuptools':'78.1.1','wheel':'0.46.3','jsonschema':'4.26.0','z3-solver':'4.15.4.0'},
            'explicit original package versions differ')
    return {'python':sys.version,'implementation':sys.implementation.name,
            'platform':platform.platform(),'versions':versions}

def apply_rows(source,current,rows,before=None):
    seen=set()
    for row in rows:
        path=row['path'];pure=PurePosixPath(path)
        require(str(pure)==path and not pure.is_absolute() and '..' not in pure.parts and path not in seen,
                'noncanonical overlay path')
        seen.add(path);raw=row['content'].encode()
        require(identity(raw)=={k:row[k] for k in ('bytes','sha256','blob')}
                and row['mode'] in ('100644','100755'),'overlay byte identity differs')
        if before is not None:
            require(current.get(path)==before[path],'P1 exact before identity differs: '+path)
        target=source/path;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(0o755 if row['mode']=='100755' else 0o644)
        current[path]={k:row[k] for k in ('bytes','sha256','blob','mode')}
    require(snapshot(source)==current,'overlay wrote an unexpected path or byte')

def prepare(source,joint,output):
    output.mkdir(mode=0o700)
    report={'status':'HOLD','runtime':runtime(),'claims':{'current_cold':False,'whole_native':False,'default_changed':False}}
    try:
        write(output/'HARNESS-INPUTS.json',check_inputs())
        harness=INPUTS.parent
        harness_head=os.environ['GITHUB_SHA']
        harness_tree=git(harness,'rev-parse','HEAD^{tree}').decode().strip()
        write(output/'AUTHENTIC-HARNESS.json',{'head':harness_head,'tree':harness_tree,
              'files':admit_git(harness,harness_head,harness_tree)})
        for path in INPUTS.glob('*.py'):
            compile(path.read_bytes(),str(path),'exec')
        before=admit_git(source,HEAD,TREE,3153)
        write(output/'AUTHENTIC-4B.json',before)
        joint_files=admit_git(joint,JOINT,JOINT_TREE,21)
        write(output/'JOINT-HARNESS-SOURCE.json',joint_files)
        require(tree_id(joint_files)==JOINT_TREE,'joint recipe tree identity differs')
        index=read(joint/'inputs/INPUTS.json');plan=read(joint/'inputs/MERGE-PLAN.json')
        compose=joint/'tools/compose_recoverable_owners.py'
        require(blob(compose.read_bytes())=='2030cb4bcabd971e9814210c951ae92b2e4cecb9','reviewed composition helper differs')
        spec=importlib.util.spec_from_file_location('frozen_joint_recipe',compose)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        owners={}
        for name,row in index['owners'].items():
            owners[name]=module.normalize(module.unpack(module.decode(module.read_owned(joint,row['path'],row['identity']))))
        derived=index['derived']
        derived=module.normalize(module.decode(module.read_owned(joint,derived['path'],derived['identity'])))
        rows=[]
        for path,selection in sorted(plan['selected_files'].items()):
            source_rows=derived if selection['owner']=='semantic-union' else owners[selection['owner']]
            row=source_rows[path]
            require({key:row[key] for key in ('bytes','sha256','blob','mode')}==selection['expected'],'selected dependency differs')
            rows.append(row)
        overlay={'schema':'hepta.hia.source-overlay.v1','base_commit':plan['base_commit'],
                 'base_tree':plan['base_tree'],'files':rows,
                 'expected_generated_paths':plan['expected_generated_paths'],'extra_controls':[]}
        raw=(json.dumps(overlay,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
        require(len(raw)==4365095 and sha(raw)==JOINT_OVERLAY_SHA,'canonical joint dependency recipe differs')
        current=dict(before);apply_rows(source,current,rows)
        require(len(current)==3239 and tree_id(current)==JOINT_SOURCE_TREE,'complete dependency source tree differs')
        write(output/'JOINT-DEVELOPMENT-SOURCE.json',current)
        packet=read(INPUTS/'evaluation-source.json')
        apply_rows(source,current,packet['files'],packet['before'])
        write(output/'AUTHORED-SOURCE.json',current)
        held=read(INPUTS/'retained-compiler.json')
        compressed=base64.b64decode(held['data'],validate=True)
        require(len(compressed)==held['compressed_bytes'] and sha(compressed)==held['compressed_sha256'],'compiler compressed bytes differ')
        decoder=zlib.decompressobj();raw=decoder.decompress(compressed)+decoder.flush()
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                and len(raw)==669494 and sha(raw)==COMPILER_SHA,'retained actual compiler bytes differ')
        compiler=output/'retained-development-compiler.bin';compiler.write_bytes(raw);compiler.chmod(0o444)
        report.update(status='READY_NOT_QUALIFIED',source_files=len(current),source_tree=tree_id(current),
                      authentic_head=HEAD,authentic_tree=TREE,compiler=dict(path=str(compiler),**identity(raw)))
    except BaseException:
        report['exception']=traceback.format_exc()
    finally:
        write(output/'PREPARE.json',report)
    return report['status']=='READY_NOT_QUALIFIED'

def generate(source,output):
    authored=read(output/'AUTHORED-SOURCE.json');require(snapshot(source)==authored,'authored source changed before generation')
    workflow=(source/'.github/workflows/hia-core.yml').read_text()
    match=re.search(r'for component in ([a-z0-9_ ]+); do',workflow)
    require(match is not None,'original complete generator inventory absent')
    original=match.group(1).split()
    require(original==read(INPUTS/'ORIGINAL-GENERATORS.json'),'exact original 88-generator order differs')
    require(len(original)==len(set(original)) and 'service_verification' in original
            and 'native_build' in original,'original generator inventory differs')
    generators=original+['service_evaluation_foreign','service_evaluation']
    allowed=set(read(INPUTS/'evaluation-source.json')['generated_paths'])
    plan=read(Path(os.environ['P1_JOINT_HARNESS'])/'inputs/MERGE-PLAN.json')
    allowed.update(plan['expected_generated_paths'])
    records=[];ok=True
    for index,name in enumerate(generators):
        row=command(source,output,'gen-'+str(index).zfill(3)+'-'+name,
                    [sys.executable,'-B','-m','tools.generate_hia_'+name])
        records.append(row)
        actual=snapshot(source)
        difference={path for path in set(actual)|set(authored) if actual.get(path)!=authored.get(path)}
        require(difference<=allowed,'generator changed unapproved source paths: '+repr(sorted(difference-allowed)))
        if row['status']!='WORKFLOW_STEP_COMPLETED':
            ok=False;break
    if ok:
        commands=[
            ('language',[sys.executable,'-B','tests/test_hia_selfhost_language_coverage.py','--generate-inventory']),
            ('contract',[sys.executable,'-B','tools/generate_hia_selfhost_contract.py']),
            ('contract-check',[sys.executable,'-B','tools/generate_hia_selfhost_contract.py','--check']),
            ('core-only',[sys.executable,'-B','tools/check_hia_core_only.py']),
        ]
        for label,argv in commands:
            row=command(source,output,'gen-'+label,argv);records.append(row)
            if row['status']!='WORKFLOW_STEP_COMPLETED':ok=False
    final=snapshot(source)
    difference={path for path in set(final)|set(authored) if final.get(path)!=authored.get(path)}
    require(difference<=allowed,'generation left unapproved source delta')
    write(output/'GENERATED-SOURCE.json',final)
    write(output/'GENERATION.json',{'status':'PASS' if ok else 'FAIL','original_generators':original,
          'appended_generators':generators[-2:],'commands':records,'changed_paths':sorted(difference),
          'source_files':len(final),'source_tree':tree_id(final),'authentic_head':HEAD,
          'current_cold':False,'native_compiler_executed':False})
    return ok

def source_controls(source,output):
    current_source(source,output)
    names=[
        'tests.test_hia_service_evaluation_native.ServiceEvaluationSourceTests',
        'tests.test_hia_service_evaluation_builder.ServiceEvaluationAdapterTests',
        'tests.test_hia_service_evaluation_qualifier.ServiceEvaluationQualifierSourceTests',
        'tests.test_hia_service_context_builder.ServiceContextAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope',
        'tests.test_hia_service_emission_builder.ServiceEmissionAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope',
        'tests.test_hia_service_verification_builder.ServiceVerificationAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope',
        'tests.test_hia_selfhost_contract.SelfhostContractTests',
        'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests',
    ]
    receipt=command(source,output,'source-controls',[sys.executable,'-I','-B',str(INPUTS/'run_controls.py'),
        '--source',str(source),'--output',str(output/'source-controls'),*names])
    current_source(source,output)
    return receipt['status']=='WORKFLOW_STEP_COMPLETED'

def build(source,output):
    current_source(source,output)
    compiler=output/'retained-development-compiler.bin'
    require(sha(compiler.read_bytes())==COMPILER_SHA,'development compiler changed')
    receipt=command(source,output,'native-build',[sys.executable,'-I','-B',
        str(source/'tools/build_hia_service_evaluation.py'),'--compiler',str(compiler),
        '--output',str(output/'candidate'),'--development'])
    current_source(source,output);require(sha(compiler.read_bytes())==COMPILER_SHA,'compiler changed after build')
    return receipt['status']=='WORKFLOW_STEP_COMPLETED'

def helper_bindings(source,output):
    current_source(source,output)
    receipt=command(source,output,'helper-binding-observations',
        [sys.executable,'-I','-B',str(INPUTS/'probe_helper_bindings.py'),
         '--source',str(source),'--manifest',str(output/'candidate/development-manifest.json'),
         '--output',str(output/'helper-binding-observations')])
    current_source(source,output)
    return receipt['status']=='WORKFLOW_STEP_COMPLETED'

def component(source,output):
    current_source(source,output)
    environment=env();environment.update(HEPTA_HIA_SERVICE_EVALUATION_DEVELOPMENT_MANIFEST=str(output/'candidate/development-manifest.json'),
                                      HEPTA_HIA_SERVICE_EVALUATION_EVIDENCE=str(output/'component-evidence'))
    receipt=command(source,output,'native-components',[sys.executable,'-I','-B',str(INPUTS/'run_controls.py'),
        '--source',str(source),'--output',str(output/'native-components'),'--expected','8',
        'tests.test_hia_service_evaluation_native.ServiceEvaluationNativeTests'],environment)
    current_source(source,output)
    require(sha((output/'retained-development-compiler.bin').read_bytes())==COMPILER_SHA,'compiler changed after component')
    return receipt['status']=='WORKFLOW_STEP_COMPLETED'

def caller(source,output,group):
    current_source(source,output)
    receipt=command(source,output,'original-'+group,[sys.executable,'-I','-B',
        str(source/'tools/qualify_hia_service_evaluation.py'),'--evidence',str(output/(group+'-callers')),
        '--development-compiler',str(output/'retained-development-compiler.bin'),'--caller-group',group],
        seconds=1800)
    current_source(source,output)
    require(sha((output/'retained-development-compiler.bin').read_bytes())==COMPILER_SHA,'compiler changed after original caller')
    return receipt['status']=='WORKFLOW_STEP_COMPLETED'

def finish(source,output):
    report={'schema':'hia.service-evaluation.actual-development.v1','status':'FAIL','runtime':runtime(),
            'authentic_head':HEAD,'authentic_base_tree':TREE,'current_cold':False,
            'whole_native':False,'default_changed':False,'historical_results_transferred':False}
    try:
        source_after=snapshot(source);write(output/'SOURCE-AFTER.json',source_after)
        expected=read(output/'GENERATED-SOURCE.json') if (output/'GENERATED-SOURCE.json').is_file() else None
        report['source_unchanged']=expected==source_after
        report['source_files']=len(source_after);report['source_tree']=tree_id(source_after)
        reports={}
        for stage in STAGES[:-1]:
            path=output/('STAGE-'+stage+'.json')
            reports[stage]=read(path) if path.is_file() else {'status':'NOT_EXECUTED'}
        report['stages']=reports
        report['status']='PASS' if report['source_unchanged'] and all(row.get('status')=='PASS' for row in reports.values()) else 'FAIL'
        packet=read(INPUTS/'evaluation-source.json')
        original_joint=read(output/'JOINT-DEVELOPMENT-SOURCE.json') if (output/'JOINT-DEVELOPMENT-SOURCE.json').is_file() else {}
        paths={path for path in set(source_after)|set(original_joint)
               if source_after.get(path)!=original_joint.get(path)}
        report['all_actual_source_changes_from_joint']=sorted(paths)
        compiler=output/'retained-development-compiler.bin'
        report['retained_compiler_unchanged']=compiler.is_file() and sha(compiler.read_bytes())==COMPILER_SHA
        report['harness_inputs_unchanged']=check_inputs()==read(output/'HARNESS-INPUTS.json')
        if not report['retained_compiler_unchanged'] or not report['harness_inputs_unchanged']:
            report['status']='FAIL'
        # The dependency recipe is already independently Git-addressed. Retain
        # every actual changed/new candidate file and complete final metadata.
        files=[]
        for path in sorted(paths):
            if path not in source_after:continue
            files.append(dict(path=path,content=(source/path).read_bytes().decode('utf-8','strict'),**source_after[path]))
        write(output/'FINAL-SOURCE-PACKET.json',{'schema':'hia.service-evaluation.generated-source.v1',
             'status':'OBSERVED_NOT_CURRENT_COLD','base':packet['base'],'authentic_head':HEAD,
             'actual_tree':tree_id(source_after),'final_files':source_after,'files':files,
             'deleted_paths':sorted(paths-set(source_after)),
             'dependency_recipe_commit':JOINT,'dependency_overlay_sha256':JOINT_OVERLAY_SHA})
    except BaseException:
        report['exception']=traceback.format_exc()
    write(output/'REPORT.json',report)
    small={}
    for path in sorted(output.rglob('*')):
        if path.is_file() and path.suffix in ('.json','.log','.txt','.py','.md') and path.stat().st_size<=12<<20:
            raw=path.read_bytes()
            try:text=raw.decode('utf-8','strict')
            except UnicodeDecodeError:continue
            small[path.relative_to(output).as_posix()]={'content':text,**identity(raw)}
    raw=(json.dumps({'schema':'hia.lossless-evaluation-text.v1','files':small},sort_keys=True,ensure_ascii=False)+'\n').encode()
    packed=zlib.compress(raw,9);encoded=base64.b64encode(packed).decode()
    size=16000;chunks=[encoded[index:index+size] for index in range(0,len(encoded),size)]
    meta={'raw_bytes':len(raw),'raw_sha256':sha(raw),'compressed_bytes':len(packed),
          'compressed_sha256':sha(packed),'chunks':len(chunks),'encoding':'zlib+base64'}
    print('P1_TEXT_META '+json.dumps(meta,sort_keys=True),flush=True)
    for index,chunk in enumerate(chunks):
        print('P1_TEXT_CHUNK '+json.dumps({'index':index,'bytes':len(chunk),'sha256':sha(chunk.encode()),'data':chunk},sort_keys=True),flush=True)
    manifest={}
    for path in sorted(output.rglob('*')):
        if path.is_file() and path.name not in ('RAW-EVIDENCE.zip','EVIDENCE-MANIFEST.json'):
            manifest[path.relative_to(output).as_posix()]=dict(mode=oct(stat.S_IMODE(path.stat().st_mode)),**identity(path.read_bytes()))
    write(output/'EVIDENCE-MANIFEST.json',manifest)
    with zipfile.ZipFile(output/'RAW-EVIDENCE.zip','x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in sorted(output.rglob('*')):
            if path.is_file() and path.name!='RAW-EVIDENCE.zip':
                archive.write(path,path.relative_to(output).as_posix())
    with zipfile.ZipFile(output/'RAW-EVIDENCE.zip') as archive:
        require(archive.testzip() is None,'raw evidence ZIP CRC differs')
    print(json.dumps({'status':report['status'],'source_files':report.get('source_files'),
                      'whole_native':False,'current_cold':False}),flush=True)
    return report['status']=='PASS'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--joint',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--stage',choices=STAGES,required=True)
    args=parser.parse_args();source=args.source.resolve(strict=True);joint=args.joint.resolve(strict=True);output=args.output.absolute()
    os.environ['P1_JOINT_HARNESS']=str(joint)
    result={'stage':args.stage,'status':'FAIL','current_cold':False,'native_limits_changed':False}
    try:
        check_inputs()
        if args.stage=='prepare':ok=prepare(source,joint,output)
        elif args.stage=='generate':ok=generate(source,output)
        elif args.stage=='source':ok=source_controls(source,output)
        elif args.stage=='build':ok=build(source,output)
        elif args.stage=='helper-binding':ok=helper_bindings(source,output)
        elif args.stage=='component':ok=component(source,output)
        elif args.stage in ('agent','namespace','ledger'):ok=caller(source,output,args.stage)
        else:return 0 if finish(source,output) else 1
        result['status']='PASS' if ok else 'FAIL'
    except BaseException:
        result['exception']=traceback.format_exc();print(result['exception'],flush=True)
    finally:
        if args.stage!='finish' and output.is_dir():
            write(output/('STAGE-'+args.stage+'.json'),result)
    print(json.dumps(result,sort_keys=True),flush=True)
    return int(result['status']!='PASS')

if __name__=='__main__':raise SystemExit(main())
