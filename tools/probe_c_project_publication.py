"""One actual fixed-tool C project -> published Rust cdylib -> scalar smoke.

Separate original/generated processes; no pointer, record or attributed ABI
calls. Not language equivalence or whole-filesystem isolation qualification.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import probe_c_typedef_alignment as owner
from tools.c_project_probe_workspace import run_private, worker_root, evidence_files

OUT=ROOT/'artifacts/c-project-publication'
LIMIT=64*1024*1024
SOURCE='unsigned int identity(unsigned int x) { return x; }\n'
DRIVER='''#include <stdio.h>
#include <limits.h>
_Static_assert(sizeof(unsigned int) == 4, "uint32 ABI required");
_Static_assert(CHAR_BIT == 8 && UINT_MAX == 4294967295U, "exact unsigned32 representation required");
unsigned int identity(unsigned int);
int main(void) { printf("%u %u\\n", identity(7U), identity(123U)); return 0; }
'''


def bundle_oracle(report, manifest, files, *, source_unchanged, outside_unchanged, outputs):
    required={'source.hepta','bridge.rs','generated.rs','libtranslated.so','migration.json'}
    if (report.get('ok') is not True or report.get('status')!='native_built_not_equivalence_proved'
            or report.get('frontend_validation')!='passed' or report.get('native_validation')!='passed'
            or report.get('diagnostics')!=[] or report!=manifest or set(files)!=required
            or set(report.get('artifacts',{}))!=required-{'migration.json'}
            or not source_unchanged or not outside_unchanged
            or outputs!={'original':'7 123\n','generated':'7 123\n'}):
        return False
    return all(files[name]==expected for name,expected in report['artifacts'].items())


def inspect_bundle(bundle):
    identities=[]
    for path in sorted(bundle.iterdir()):
        owner.require(path.is_file() and not path.is_symlink(),'Nonregular/unexpected bundle entry')
        info=path.stat();identities.append((info.st_dev,info.st_ino))
    owner.require(len(set(identities))==len(identities),'Published artifacts share an inode')
    owner.require(not list(bundle.parent.glob('.hepta-*')),'Private migration stage residue remains')
    return evidence_files(bundle,LIMIT)


def scalar_abi_admission(report, bridge, generated):
    """No native call unless reviewed report and exact FFI source shape agree."""
    functions=report.get('functions',[])
    owner.require(len(functions)==1,'Expected exactly one migrated scalar function')
    fn=functions[0]
    configurations=report.get('build',{}).get('configurations',[])
    owner.require(len(configurations)==1 and configurations[0].get('model')=={
                  'char_unsigned':False,'long_bits':64,'pointer_bits':64},
                  'Unexpected fixed x86_64 C data model')
    owner.require(fn.get('name')=='identity' and fn.get('key')=='identity'
                  and fn.get('hepta_name')=='c_identity' and fn.get('external_symbol') is True
                  and fn.get('return')=='u32' and fn.get('params')==[
                      {'name':'x','type':'u32','pointer':False,'mode':'value'}],
                  'Migrated scalar ABI report differs from uint32 identity')
    exports=re.findall(r'#\[export_name\s*=\s*"([^"]+)"\]',bridge)
    signature=r'#\[export_name = "identity"\]\s+pub unsafe extern "C" fn __hepta_c_export_0\(b_x: u32\) -> u32 \{'
    owner.require(exports==['identity'] and len(re.findall(signature,bridge))==1
                  and bridge.count('pub unsafe extern "C" fn ')==1,
                  'Generated scalar bridge does not expose exactly uint32 extern-C identity')
    owner.require(generated.count(bridge)==1 and generated.endswith(bridge),
                  'Compiled source is not bound to the reviewed scalar bridge')
    return {'export':'identity','calling_convention':'C','parameters':['u32'],'return':'u32',
            'bridge_sha256':owner.hashlib.sha256(bridge.encode()).hexdigest(),
            'generated_sha256':owner.hashlib.sha256(generated.encode()).hexdigest()}


def worker():
    from hepta.c_migrate import migrate_c_project
    from hepta import c_project_publish as publisher
    before=owner.source_hashes()
    report={'schema':'hepta.c-project-publication-native.v1','ok':False,
            'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),
            'source_before':before,'tools':{},'cases':[],
            'claims':{'native_project_cases':1,'filesystem_profile_tests_are_native':False,
                      'whole_filesystem_no_write_proved':False,'actual_ai_model_runs':0,
                      'mismatched_abi_calls_executed':False,'whole_language_equivalence_proved':False}}
    try:
        controls=json.loads((ROOT/'tools/c_typedef_port_controls.json').read_text())
        for name,expected in controls['files_sha256'].items():
            owner.require(owner.sha(ROOT/name)==expected,'Wrong source/control: '+name)
        head=owner.run(['git','-c','safe.directory='+str(ROOT),'rev-parse','HEAD'],OUT/'tools','head').strip()
        owner.require(head==report['expected_head'],'Wrong source head');report['actual_head']=head
        for name,version in [('clang','19.1.7'),('gcc','14.2.0'),('rustc','1.90.0')]:
            selected=os.environ.get('RUSTC') if name=='rustc' else shutil.which(name)
            owner.require(bool(selected),'Required compiler absent')
            executable=str(Path(selected).resolve(strict=True))
            actual=owner.run([executable,'--version'],OUT/'tools',name).splitlines()[0]
            owner.require(version in actual,'Unexpected compiler version')
            report['tools'][name]={'path':executable,'version':actual,'sha256':owner.sha(executable)}
        case=OUT/'scalar-identity';case.mkdir(mode=0o700)
        sentinel=OUT/'outside-publication';sentinel.mkdir(mode=0o700)
        (sentinel/'sentinel.txt').write_text('No publication outside its selected bundle\n')
        outside_before={p.name:owner.sha(p) for p in sentinel.iterdir()}
        source=case/'input.c';source.write_text(SOURCE)
        driver=case/'driver.c';driver.write_text(DRIVER)
        owner.write(case/'compile_commands.json',[{'directory':str(case),'file':'input.c',
                    'arguments':['clang','-std=c11','-c','input.c']}])
        original_source={p.name:owner.sha(p) for p in (source,driver,case/'compile_commands.json')}
        calls=[];real_run=subprocess.run
        def observed_run(*args,**kwargs):
            index=len(calls);tag='production-'+str(index)
            record={'argv':list(map(str,args[0] if args else kwargs['args'])),
                    'cwd':str(kwargs.get('cwd',Path.cwd())),'timeout':kwargs.get('timeout'),
                    'started_unix':time.time()};calls.append(record)
            owner.write(case/'production-commands.json',calls)
            def retain(label,data):
                data=data.encode() if isinstance(data,str) else data or b''
                owner.require(len(data)<=32_000_000,'Production output bound exceeded')
                path=case/(tag+'.'+label);path.write_bytes(data);record[label+'_sha256']=owner.sha(path)
            try:
                completed=owner.execution_guard(real_run,*args,**kwargs)
                retain('stdout',completed.stdout);retain('stderr',completed.stderr)
                record['exit_code']=completed.returncode
                return completed
            except BaseException as error:
                retain('stdout',getattr(error,'stdout',None));retain('stderr',getattr(error,'stderr',None))
                record['error']=str(error);record['execution_denied']=isinstance(error.__cause__,PermissionError)
                raise
            finally:
                record['elapsed_seconds']=time.time()-record['started_unix']
                owner.write(case/'production-commands.json',calls)
        bundle=case/'bundle'
        original_publish=publisher.publish_no_replace;publication=[]
        def observed_publish(stage,destination,**kwargs):
            names=set(kwargs['expected'])
            original_ids={name:(os.lstat(Path(stage)/name).st_dev,os.lstat(Path(stage)/name).st_ino) for name in names}
            original_files=evidence_files(stage,LIMIT)
            value=original_publish(stage,destination,**kwargs)
            final_ids={name:(os.lstat(Path(destination)/name).st_dev,os.lstat(Path(destination)/name).st_ino) for name in names}
            final_files=evidence_files(destination,LIMIT)
            owner.require(set(original_files)==names and original_files==final_files==kwargs['expected'],
                          'Publisher source/target bytes differ from caller validation')
            owner.require(len(set(final_ids.values()))==len(names)
                          and not (set(original_ids.values()) & set(final_ids.values())),
                          'Publisher did not create distinct new target regular inodes')
            publication.append({'stage_path':str(stage),'output_path':str(destination),
                                'source_inodes':original_ids,'target_inodes':final_ids,
                                'source_files':original_files,'target_files':final_files})
            owner.write(case/'publisher-inode-and-byte-binding.json',publication)
            return value
        with patch.object(subprocess,'run',observed_run),patch.object(publisher,'publish_no_replace',observed_publish):
            migrated=migrate_c_project(case/'compile_commands.json',bundle,
                clang=report['tools']['clang']['path'],rustc=report['tools']['rustc']['path'],verify_native=True)
        owner.write(case/'migration-report.json',migrated)
        owner.require(migrated.get('ok') is True and migrated.get('native_validation')=='passed'
                      and migrated.get('frontend_validation')=='passed' and migrated.get('diagnostics')==[]
                      and migrated.get('status')=='native_built_not_equivalence_proved'
                      and migrated.get('native_build',{}).get('ok') is True,
                      'Actual native project build did not pass')
        manifest=json.loads((bundle/'migration.json').read_text())
        files=inspect_bundle(bundle)
        owner.require(len(publication)==1,'Actual production publisher was not observed exactly once')
        owner.require(migrated==manifest and set(files)=={'source.hepta','bridge.rs','generated.rs','migration.json','libtranslated.so'}
                      and set(migrated.get('artifacts',{}))==set(files)-{'migration.json'}
                      and all(files.get(n)==v for n,v in migrated.get('artifacts',{}).items()),
                      'Publication manifest/file receipt mismatch before native calls')
        with (bundle/'libtranslated.so').open('rb') as stream:binary=stream.read(20)
        owner.require(binary[:6]==b'\x7fELF\x02\x01' and binary[16:20]==b'\x03\x00\x3e\x00','Published artifact is not x86_64 ELF shared library')
        abi=scalar_abi_admission(migrated,(bundle/'bridge.rs').read_text(),(bundle/'generated.rs').read_text())
        owner.write(case/'scalar-abi-admission.json',abi)
        gcc=report['tools']['gcc']['path'];outputs={}
        original=case/'original-executable';generated=case/'generated-executable'
        owner.run([gcc,'-std=c11','-Werror','-O0',str(driver),str(source),'-o',str(original)],case,'original-build',timeout=30)
        owner.run([gcc,'-std=c11','-Werror','-O0',str(driver),str(bundle/'libtranslated.so'),
                   '-Wl,-rpath,'+str(bundle),'-o',str(generated)],case,'generated-build',timeout=30)
        outputs['original']=owner.run([str(original)],case,'original-execute',timeout=5)
        outputs['generated']=owner.run([str(generated)],case,'generated-execute',timeout=5)
        original_after={p.name:owner.sha(p) for p in (source,driver,case/'compile_commands.json')}
        outside_after={p.name:owner.sha(p) for p in sentinel.iterdir()}
        row={'name':'actual-scalar-native-project','ok':bundle_oracle(migrated,manifest,files,
             source_unchanged=original_source==original_after,outside_unchanged=outside_before==outside_after,outputs=outputs),
             'bundle_files':files,'migration_report_sha256':owner.sha(case/'migration-report.json'),
             'published_manifest_sha256':owner.sha(bundle/'migration.json'),
             'source_before':original_source,'source_after':original_after,
             'outside_sentinel_before':outside_before,'outside_sentinel_after':outside_after,
             'outputs':outputs,'native_executions':2,
             'scalar_abi_admission':abi,
             'publisher_binding':publication[0],
             'write_audit_scope':'Selected private root, tracked source and outside-publication sentinel only; not whole-filesystem isolation'}
        report['cases'].append(row)
        report['source_after']=owner.source_hashes()
        owner.require(before==report['source_after'],'Source changed during native project probe')
        report['ok']=row['ok']
    except Exception as error:
        report['error']=str(error);(OUT/'worker-exception.txt').write_text(traceback.format_exc())
    finally:owner.write(OUT/'report.json',report)
    return 0 if report['ok'] else 1


def _private_main(private):
    global OUT
    OUT=private
    result=owner.supervise([sys.executable,str(Path(__file__).resolve()),'--worker','--work-root',str(private)],
                           timeout=240,max_output=1_000_000)
    (OUT/'worker.stdout').write_bytes(result.pop('stdout'));(OUT/'worker.stderr').write_bytes(result.pop('stderr'))
    owner.write(OUT/'owned-process-receipt.json',result)
    if not result['cleanup']['confirmed']:
        owner.write(OUT/'UNSEALED.json',{'reason':'Owned cleanup unknown','supervisor':result});return 1
    from tools.c_project_probe_workspace import evidence_files
    files=evidence_files(OUT,LIMIT)
    total=sum(item['bytes'] for item in files.values());status=result['exit_code'] if total<=LIMIT else 1
    owner.write(OUT/'manifest.json',{'schema':'hepta.c-project-publication-artifacts.v1','exit_code':status,
        'files':files,'total_bytes':total,'byte_limit':LIMIT,'owned_cleanup_confirmed':True,
        'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),'native_project_cases':1,
        'actual_ai_model_runs':0,'whole_project_qualified':False})
    return status


def main():
    global OUT
    if '--worker' in sys.argv:
        OUT=worker_root(sys.argv);return worker()
    return run_private(OUT,_private_main,limit=LIMIT)


if __name__=='__main__':raise SystemExit(main())
