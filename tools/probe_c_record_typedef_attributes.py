"""Real-Clang typed alias rejection and independent ordinary ABI layout oracle.

No generated negative executable is compiled, linked or called. Ordinary C and
Rust layouts execute in separate processes, never through a mismatched ABI.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import time
import traceback
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import probe_c_typedef_alignment as owner

OUT=ROOT/'artifacts/c-record-typedef-attributes'
EXPECTED={
 'hepta/c_translation.py':'5729dc9d659779ad2d5d425793fb13a9688420826cf0d5c8e5ce17d81e59d0fb',
 'hepta/c_record_views.py':'262be266bebf324250c08366a64c3b85d5c9da09371f38be04a598f4af653629',
}
# Each specimen is real source. system=True means actual -isystem capture,
# not a hand-edited source location or mocked semantic AST.
CASES=[
 {'name':'system-pointer-aligned','negative':True,'system':True,'defs':'typedef int *Ptr __attribute__((aligned(16)));','raw':'Ptr','attribute':'Ptr','desugared_pointer':True},
 {'name':'system-pointee-aligned','negative':True,'system':True,'defs':'typedef int Element __attribute__((aligned(16)));','raw':'Element *','attribute':'Element'},
 {'name':'system-pointer-chain','negative':True,'system':True,'defs':'typedef int Element __attribute__((aligned(16))); typedef Element *Base; typedef Base Ptr;','raw':'Ptr','attribute':'Element','desugared_pointer':True},
 {'name':'system-pointer-redeclared','negative':True,'system':True,'defs':'typedef int *Ptr __attribute__((aligned(16))); typedef int *Ptr;','raw':'Ptr','attribute':'Ptr','desugared_pointer':True},
 {'name':'header-scalar-chain','negative':True,'system':False,'defs':'typedef int Element __attribute__((aligned(16))); typedef Element Wide;','raw':'Wide *','attribute':'Element'},
 {'name':'local-scalar-chain','negative':True,'local':True,'defs':'typedef int Element __attribute__((aligned(16))); typedef Element Wide;','raw':'Wide *','attribute':'Element'},
 {'name':'system-record-parameter-aligned','negative':True,'system':True,'defs':'typedef struct State StateAlias __attribute__((aligned(16)));','raw':'int *','parameter':'StateAlias','attribute':'StateAlias'},
 {'name':'two-unit-used-attribute','negative':True,'system':True,'defs':'typedef int *Ptr __attribute__((aligned(16)));','raw':'Ptr','attribute':'Ptr','collision':True,'desugared_pointer':True},
 {'name':'plain-system-pointer','negative':False,'system':True,'defs':'typedef int *Ptr;','raw':'Ptr','desugared_pointer':True},
 {'name':'plain-header-scalar-chain','negative':False,'system':False,'defs':'typedef int Element; typedef Element Wide;','raw':'Wide *'},
 {'name':'unused-system-attribute','negative':False,'system':True,'defs':'typedef int *Unused __attribute__((aligned(16)));','raw':'int *','attribute':'Unused'},
 {'name':'two-unit-unused-attribute','negative':False,'system':True,'defs':'typedef int *Ptr;','raw':'Ptr','unused_collision':True,'desugared_pointer':True,'ordinary_aliases':{'Ptr':'int *'}},
 {'name':'plain-system-record-parameter','negative':False,'system':True,'defs':'typedef struct State StateAlias;','raw':'int *','parameter':'StateAlias'},
]


def gate(spec, migration, bundle_exists, layouts):
    if spec['negative']:
        return (migration.get('ok') is False and not bundle_exists and not layouts and
                'E_C_ATTRIBUTE' in [d.get('code') for d in migration.get('diagnostics',[])])
    return (migration.get('ok') is True and bundle_exists and migration.get('diagnostics')==[] and
            len(layouts)==4 and {(v.get('compiler'),v.get('optimization')) for v in layouts}=={(c,o) for c in ('clang','gcc') for o in ('0','2')} and
            all(v['original']==v['generated'] and all(isinstance(v.get(k),list) and len(v[k])==4 and
                all(type(n) is int and 0<=n<=4096 for n in v[k]) and v[k][0]>0 and v[k][1]>0 for k in ('original','generated')) for v in layouts))


def contract(names):
    return {'schema':'hepta.c-record-views.v1','records':{'State':{'buffers':{'data':{'length_field':'n','add':0}}}},
            'functions':{n:{'records':{'ctx':{'access':'read'}},'slices':{}} for n in names}}


def fixture(directory, spec):
    """Return actual compilation database and exact user contract."""
    entries=[]; names=[]; units=[]
    variants=[]
    if spec.get('collision'):
        variants.append(dict(spec,defs='typedef int *Ptr;',attribute=None))
    if spec.get('unused_collision'):
        variants.append(dict(spec,defs='typedef int *Ptr __attribute__((aligned(16)));',empty=True,attribute='Ptr',ordinary_aliases={}))
    variants.append(spec)
    for i,variant in enumerate(variants):
        unit=directory/('unit'+str(i));unit.mkdir()
        defs=variant['defs']+'\n';flags=['-std=c11']; source=''
        if variant.get('local'):source+=defs
        else:
            header=unit/'headers';header.mkdir();(header/'types.h').write_text(defs)
            flags+=['-isystem' if variant.get('system') else '-I',str(header)]
            source+='#include <types.h>\n'
        if not variant.get('empty'):
            name='inspect'+str(i);names.append(name)
            source+='/** ordinary buffer view */\nstruct State;\nstruct State { '+variant['raw']+' data; unsigned int n; };\n'
            source+='unsigned int '+name+'('+variant.get('parameter','struct State')+' *ctx) { return ctx->n; }\n'
        path=unit/'input.c';path.write_text(source)
        entries.append({'directory':str(unit),'file':'input.c','arguments':['clang',*flags,'-c','input.c']})
        units.append({'source':path,'flags':flags,'variant':variant,'directory':unit})
    owner.write(directory/'compile_commands.json',entries)
    owner.write(directory/'contracts.json',contract(names))
    return units,contract(names)


def observe_ast(ast, variant):
    owner.require(ast.get('kind')=='TranslationUnitDecl','Not a real Clang translation unit')
    aliases=[n for n in ast.get('inner',[]) if n.get('kind')=='TypedefDecl']
    attributed=[n.get('name') for n in aliases if any(c.get('kind','').endswith('Attr') for c in n.get('inner',[]))]
    expected=variant.get('attribute')
    if expected:
        owner.require(any(n.get('name')==expected and any(c.get('kind')=='AlignedAttr' for c in n.get('inner',[])) for n in aliases),
                      'Required AlignedAttr absent from actual typedef AST')
    for name,qual in variant.get('ordinary_aliases',{}).items():
        declarations=[n for n in aliases if n.get('name')==name]
        owner.require(bool(declarations) and all(n.get('type',{}).get('qualType')==qual and
                      not any(c.get('kind','').endswith('Attr') for c in n.get('inner',[])) for n in declarations),
                      'Required ordinary typedef absent or attributed: '+name)
    fields=[f for n in ast.get('inner',[]) if n.get('kind')=='RecordDecl' and n.get('name')=='State'
            for f in n.get('inner',[]) if f.get('kind')=='FieldDecl' and f.get('name')=='data']
    if variant.get('desugared_pointer') and not variant.get('empty'):
        owner.require(len(fields)==1,'Expected one actual pointer field')
        data=fields[0]['type']
        owner.require(data.get('qualType')==variant['raw'] and data.get('desugaredQualType','').endswith('*'),
                      'Real pointer alias AST does not match the modeled regression')
    return {'attributed_typedefs':attributed,'data_field_types':[f['type'] for f in fields],
            'typedef_types':[{'name':n.get('name'),'type':n.get('type'),'attributes':[c.get('kind') for c in n.get('inner',[]) if c.get('kind','').endswith('Attr')]} for n in aliases]}


def ordinary_layout(case, units, bundle, tools):
    # The typed translator deliberately removes the pointer from safe core state.
    # Compare the actual emitted Rust FFI record, not the safe-state struct.
    source=units[-1]['source'];flags=units[-1]['flags']
    original='#include <stddef.h>\n#include <stdio.h>\n#include '+json.dumps(str(source))+'\n'
    original+='int main(void) { printf("%zu %zu %zu %zu\\n", sizeof(struct State), _Alignof(struct State), offsetof(struct State,data), offsetof(struct State,n)); return 0; }\n'
    (case/'original-layout.c').write_text(original)
    generated=(bundle/'generated.rs').read_text()
    owner.require('pub struct __HeptaAbi_C_State' in generated,'Actual typed ABI record not emitted')
    generated+='\nfn main() { println!("{} {} {} {}", std::mem::size_of::<__HeptaAbi_C_State>(), std::mem::align_of::<__HeptaAbi_C_State>(), std::mem::offset_of!(__HeptaAbi_C_State,f_data), std::mem::offset_of!(__HeptaAbi_C_State,f_n)); }\n'
    (case/'generated-layout.rs').write_text(generated)
    rust={};rows=[]
    for opt in ('0','2'):
        binary=case/('rust-O'+opt)
        owner.run([tools['rustc']['path'],'--edition=2021','--crate-name','typed_layout','-C','opt-level='+opt,str(case/'generated-layout.rs'),'-o',str(binary)],case,'rust-O'+opt+'-compile')
        rust[opt]=owner.layout(owner.run([str(binary)],case,'rust-O'+opt+'-run',timeout=5))
        for name in ('clang','gcc'):
            binary=case/(name+'-O'+opt)
            owner.run([tools[name]['path'],*flags,'-O'+opt,str(case/'original-layout.c'),'-o',str(binary)],case,name+'-O'+opt+'-compile')
            original_values=owner.layout(owner.run([str(binary)],case,name+'-O'+opt+'-run',timeout=5))
            rows.append({'compiler':name,'optimization':opt,'original':original_values,'generated':rust[opt]})
    return rows


def worker():
    from hepta.c_migrate import migrate_c_project
    import hepta.c_project as project
    import hepta.c_translation as translation
    before=owner.source_hashes()
    report={'schema':'hepta.c-record-typedef-attributes.v1','ok':False,'source_before':before,
            'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),'cases':[],'tools':{},
            'scope':'actual Clang AST; separate ordinary C/Rust layout executables; no ABI calls or equivalence proof'}
    try:
        owner.require(all(before.get(p)==sha for p,sha in EXPECTED.items()),'Wrong reviewed production source')
        actual=owner.run(['git','-c','safe.directory='+str(ROOT),'rev-parse','HEAD'],OUT/'tools','head').strip()
        owner.require(actual==report['expected_head'],'Wrong candidate head');report['actual_head']=actual
        for name,arg,version in [('clang','--version','19.1.7'),('gcc','--version','14.2.0'),('rustc','--version','1.90.0')]:
            selected=os.environ.get('RUSTC') if name=='rustc' else shutil.which(name)
            owner.require(bool(selected),'Missing required '+name)
            executable=str(Path(selected).resolve(strict=True))
            observed=owner.run([executable,arg],OUT/'tools',name).splitlines()[0]
            owner.require(version in observed,'Wrong '+name+' version')
            report['tools'][name]={'path':executable,'version':observed,'sha256':owner.sha(executable)}
        for spec in CASES:
            case=OUT/spec['name'];case.mkdir();row={'name':spec['name'],'negative':spec['negative'],'ok':False,'layouts':[],'asts':[]};report['cases'].append(row)
            try:
                units,contracts=fixture(case,spec)
                for i,unit in enumerate(units):
                    text=owner.run([report['tools']['clang']['path'],*unit['flags'],'-Werror','-fsyntax-only','-Xclang','-ast-dump=json',str(unit['source'])],case,'actual-ast-'+str(i))
                    row['asts'].append(observe_ast(json.loads(text),unit['variant']))
                original=project.invoke;calls=[]
                def observed(args,directory,*,stdin=None):
                    index=len(calls);rec={'argv':list(args),'cwd':str(directory),'stdin':stdin};calls.append(rec)
                    owner.write(case/'migration-invocations.json',calls)
                    try:
                        result=original(args,directory,stdin=stdin)
                        owner.require(len(result.encode())<=32_000_000,'Migration output bound exceeded')
                        dest=case/('migration-'+str(index)+'.stdout');dest.write_text(result)
                        rec.update(returned=True,stdout_sha256=owner.sha(dest));return result
                    except BaseException as exc:
                        rec['error']=str(exc);raise
                    finally:owner.write(case/'migration-invocations.json',calls)
                # Observe complete raw subprocess output while delegating the
                # unchanged production call/flags/environment to original run.
                real_run=subprocess.run;native_calls=[]
                def recorded_run(*args,**kwargs):
                    index=len(native_calls);tag='migration-native-'+str(index)
                    rec={'argv':list(map(str,args[0] if args else kwargs['args'])),
                         'cwd':str(kwargs.get('cwd',Path.cwd())), 'timeout':kwargs.get('timeout'),
                         'started_unix':time.time()};native_calls.append(rec)
                    owner.write(case/'migration-native-commands.json',native_calls)
                    def retain(out,err):
                        for label,data in [('stdout',out),('stderr',err)]:
                            data=data.encode() if isinstance(data,str) else data or b''
                            dest=case/(tag+'.'+label);dest.write_bytes(data)
                            rec[label+'_sha256']=owner.sha(dest)
                    try:
                        completed=owner.execution_guard(real_run,*args,**kwargs)
                        retain(completed.stdout,completed.stderr);rec['exit_code']=completed.returncode
                        return completed
                    except BaseException as exc:
                        retain(getattr(exc,'stdout',None),getattr(exc,'stderr',None));rec['error']=str(exc)
                        rec['execution_denied']=isinstance(exc.__cause__,PermissionError);raise
                    finally:
                        rec['elapsed_seconds']=time.time()-rec['started_unix']
                        owner.write(case/'migration-native-commands.json',native_calls)
                with patch.object(project,'invoke',observed),patch.object(translation,'invoke',observed),patch.object(subprocess,'run',recorded_run):
                    migrated=migrate_c_project(case/'compile_commands.json',case/'bundle',contracts=contracts,clang=report['tools']['clang']['path'])
                owner.write(case/'migration-report.json',migrated)
                row.update(migration_ok=migrated['ok'],diagnostics=migrated['diagnostics'])
                # A mistakenly accepted negative is a rejection-policy failure,
                # never an invitation to compile/execute that generated output.
                if not spec['negative'] and migrated['ok']:
                    row['layouts']=ordinary_layout(case,units,case/'bundle',report['tools'])
                row['ok']=gate(spec,migrated,(case/'bundle').exists(),row['layouts'])
            except Exception as exc:
                row['error']=str(exc);(case/'exception.txt').write_text(traceback.format_exc())
            finally:owner.write(OUT/'report.json',report)
        report['source_after']=owner.source_hashes()
        owner.require(before==report['source_after'],'Source changed during probe')
        report['ok']=len(report['cases'])==len(CASES) and all(r['ok'] for r in report['cases'])
    except Exception as exc:
        report['error']=str(exc);(OUT/'worker-exception.txt').write_text(traceback.format_exc())
    finally:owner.write(OUT/'report.json',report)
    return 0 if report['ok'] else 1


def main():
    if '--worker' in sys.argv:return worker()
    owner.require(not OUT.exists(),'Stale typed probe evidence')
    OUT.mkdir(parents=True)
    result=owner.supervise([sys.executable,str(Path(__file__).resolve()),'--worker'],timeout=600,max_output=1_000_000)
    (OUT/'worker.stdout').write_bytes(result.pop('stdout'));(OUT/'worker.stderr').write_bytes(result.pop('stderr'))
    owner.write(OUT/'owned-process-receipt.json',result)
    if not result['cleanup']['confirmed']:
        owner.write(OUT/'UNSEALED.json',{'reason':'Owned cleanup unconfirmed','supervisor':result});return 1
    files={str(p.relative_to(OUT)):{'bytes':p.stat().st_size,'sha256':owner.sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file()}
    total=sum(r['bytes'] for r in files.values());status=result['exit_code'] if total<=owner.LIMIT else 1
    owner.write(OUT/'manifest.json',{'schema':'hepta.typed-typedef-artifacts.v1','exit_code':status,'files':files,'total_bytes':total,'byte_limit':owner.LIMIT,
                'owned_cleanup_confirmed':True,'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),
                'claims':{'mismatched_abi_calls_executed':False,'whole_project_blockers_closed':False,'actual_ai_model_runs':0}})
    return status


if __name__=='__main__':raise SystemExit(main())
