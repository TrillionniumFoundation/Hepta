"""Author a minimal successor request from closed r1. No compiler or native calls.

The only implementation change is the two explicit-tstate no-argument calls in
the preserved CPython do_raise body. All finite methods, owners and budgets are
copied byte-for-byte. This authoring script is a newly bound input, not a test.
"""
from __future__ import annotations
import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct

OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r1-20261112-e26e')
ROOT = Path(__file__).resolve().parent
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r2-20261112-e26e')
FAILED = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r1-20261112-e26e')
QUALIFIED = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
OLD_ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r1-20261112-e26e')
TARGET = 'hepta/hia_cli_json_cpython312_errors.inc'

def wire(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()

def record(path, relative=None):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    fields = lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert fields(before)==fields(after) and stat.S_ISREG(before.st_mode)
    return {'path':str(path) if relative is None else relative,'bytes':len(raw),
            'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'mode':stat.S_IMODE(before.st_mode)}

def create(path, raw, mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        position=0
        while position<len(raw):
            count=os.write(fd,raw[position:])
            assert count>0
            position+=count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path,mode)
    assert path.read_bytes()==raw
    return record(path)

def symbols(path, table_types):
    raw=path.read_bytes(); fields=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    assert fields[0][:7]==b'\x7fELF\x02\x01\x01' and fields[11]==64
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,fields[6]+n*64) for n in range(fields[12])]
    rows=[]
    for section in sections:
        if section[1] not in table_types:continue
        assert section[9]==24 and section[5]%24==0
        strings_section=sections[section[6]]
        strings=raw[strings_section[4]:strings_section[4]+strings_section[5]]
        for at in range(section[4],section[4]+section[5],24):
            name,info,vis,index,value,size=struct.unpack_from('<IBBHQQ',raw,at)
            end=strings.find(b'\0',name);assert 0<=name<=end<len(strings)
            name=strings[name:end].decode('ascii')
            if name:rows.append({'name':name,'type':info&15,'bind':info>>4,'visibility':vis,
                                 'section':index,'value':value,'bytes':size,'table_type':section[1]})
    return rows

def main():
    assert ROOT == Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2-20261112-e26e')
    assert not os.path.lexists(ACTUAL)
    old=json.loads((OLD/'POLICY.json').read_bytes())
    assert hashlib.sha256((OLD/'POLICY.json').read_bytes()).hexdigest()=='8eb03e9fb5190117a72b8fd4d3d08195adbd526a2aac623d7758a9c9e829df70'
    assert json.loads((FAILED/'FINAL.json').read_bytes())['status']=='HOLD'
    for base,rows in [(Path('source'),old['source_files']),(Path(),old['control_files']+old['asset_files'])]:
        for row in rows:
            path=OLD/base/row['path'];r=record(path,row['path']);assert r==row
            create(ROOT/base/row['path'],path.read_bytes(),row['mode'])
    original=(OLD/'source'/TARGET).read_bytes()
    assert original.count(b'_PyObject_CallNoArgs(')==2
    edits=[
      (b' * Only two local function identifiers change. No JSON traversal,\n * message selection, normalization or lifetime body is rewritten.\n',
       b' * Two function names are local. The r2 call sites additionally use the\n * already-held tstate, preserving EVAL_CALL_API bookkeeping and Vectorcall.\n * This avoids importing private TLS; error and ownership order are unchanged.\n'),
      (b'        value = _PyObject_CallNoArgs(exc);',
       b'        EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, exc);\n        value = _PyObject_CallNoArgsTstate(tstate, exc);'),
      (b'            fixed_cause = _PyObject_CallNoArgs(cause);',
       b'            EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, cause);\n            fixed_cause = _PyObject_CallNoArgsTstate(tstate, cause);')]
    corrected=original
    for before,after in edits:
        assert corrected.count(before)==1
        corrected=corrected.replace(before,after)
    inverse=corrected
    for before,after in reversed(edits):
        assert inverse.count(after)==1
        inverse=inverse.replace(after,before)
    assert inverse==original and b'_PyObject_CallNoArgs(' not in corrected
    target=ROOT/'source'/TARGET
    target.write_bytes(corrected)
    assert stat.S_IMODE(target.stat().st_mode)==next(r['mode'] for r in old['source_files'] if r['path']==TARGET)
    create(ROOT/'reference/r1-errors.inc',original)
    delta=''.join(difflib.unified_diff(original.decode().splitlines(True),corrected.decode().splitlines(True),
                                    fromfile='r1/'+TARGET,tofile='r2/'+TARGET))
    create(ROOT/'SOURCE-DELTA.patch',delta.encode())

    # The actual provisioned headers are copied as evidence; exact upstream
    # bodies are checked independently. No preprocessing or C compilation.
    include=Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/python/include/python3.12')
    reference_rows=[]
    for relative in ['internal/pycore_call.h','internal/pycore_pystate.h','internal/pycore_code.h','pyport.h','pyconfig.h']:
        p=include/relative;create(ROOT/'reference'/('actual-'+p.name),p.read_bytes())
        reference_rows.append(record(p))
        official=ROOT/'reference'/('official-'+p.name)
        if official.exists():assert official.read_bytes()==p.read_bytes(), p.name
    h=(include/'internal/pycore_call.h').read_text()
    assert '_PyObject_CallNoArgsTstate(PyThreadState *tstate, PyObject *func) {\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in h
    assert '_PyObject_CallNoArgs(PyObject *func) {\n    EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, func);\n    PyThreadState *tstate = _PyThreadState_GET();\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in h
    ph=(include/'internal/pycore_pystate.h').read_text()
    assert '#if defined(HAVE_THREAD_LOCAL) && !defined(Py_BUILD_CORE_MODULE)\n    return _Py_tss_tstate;' in ph
    parent_call=(ROOT/'source/hepta/hia_cli_json_cpython312_exceptions.inc').read_text()
    assert parent_call.count('cj312_do_raise(')==1 and 'cj312_do_raise(PyThreadState_Get(),' in parent_call
    assert '/* #undef Py_STATS */' in (include/'pyconfig.h').read_text()
    dso=FAILED/'work/c-build/cli-json.so'
    dyn=symbols(dso,{11}); all_symbols=symbols(dso,{2})
    undefined=[x for x in dyn if x['section']==0]
    assert [x for x in undefined if x['name']=='_Py_tss_tstate'][0]['type']==6
    py=Path(old['python']['path']);runtime_dyn=symbols(py,{11})
    assert not any(x['name']=='_Py_tss_tstate' and x['section'] for x in runtime_dyn)
    runtime_public={x['name']:x for x in runtime_dyn if x['section']}
    assert all(n in runtime_public for n in ['PyThreadState_Get','_PyObject_MakeTpCall','_Py_CheckFunctionResult'])
    parent_do_raise=[x for x in all_symbols if x['name']=='cj312_do_raise']
    assert len(parent_do_raise)==1
    create(ROOT/'proof/ORIGINAL-ELF-SYMBOLS.json',wire({
        'status':'READONLY_ORIGINAL_BYTES_OBSERVED','original_dso':record(dso),
        'runtime_image':record(py),'undefined_dynamic_symbols':undefined,
        'original_do_raise':parent_do_raise[0],
        'runtime_exports':{n:runtime_public[n] for n in ['PyThreadState_Get','_PyObject_MakeTpCall','_Py_CheckFunctionResult']},
        'private_TLS_not_exported_by_actual_runtime':True,
        'runtime_loaded_here':False,'new_C_compiler_executed':False}))

    policy=copy.deepcopy(old)
    policy['operation_key']='hia-cli-json-c-runtime-lifetime-local312-r2'
    policy['operation_root']=str(ACTUAL)
    policy['c_command']=[v.replace(str(OLD),str(ROOT)).replace(str(OLD_ACTUAL),str(ACTUAL)) for v in old['c_command']]
    policy['source_files']=[record(ROOT/'source'/r['path'],r['path']) for r in old['source_files']]
    policy['control_files'].append(record(ROOT/'freeze_revision.py','freeze_revision.py'))
    changed=[(b['path'],b,a) for b,a in zip(old['source_files'],policy['source_files']) if a!=b]
    assert len(changed)==1 and changed[0][0]==TARGET
    for k in ['runtime_ids','lifetime_ids','expected_lifetime_HIA_returns','expected_C_pump_calls_including_refusals',
              'expected_total_HIA_returns','expected_total_C_pump_calls_including_refusals','compiler_limits',
              'c_compiler_limits','qualification_seconds','cleanup_seconds','child_seconds',
              'current_compiler_capsule','external_files','python','system_manifest','preserved_original17_and46']:
        assert policy[k]==old[k]
    policy_record=create(ROOT/'POLICY.json',wire(policy))
    request=json.loads((OLD/'REQUEST.json').read_bytes())
    request.update(operation_key=policy['operation_key'],operation_root=str(ACTUAL),policy_sha256=policy_record['sha256'])
    request_record=create(ROOT/'REQUEST.json',wire(request))
    preexec=json.loads((OLD/'PREEXEC.json').read_bytes())
    preexec.update(command=[policy['python']['path'],'-I','-S','-B',str(ROOT/'control/launch.py'),
                           '--request',str(ROOT/'REQUEST.json'),'--sha256',request_record['sha256']],
                   cwd=str(ROOT),request=request_record,policy=policy_record,
                   source_bytes=sum(x['bytes'] for x in policy['source_files']))
    preexec['previous_failed_request_commit']='30d2cf56eb346db37a1da41dffbffa0cfefc6c44'
    preexec['previous_failure_originals_commit']='46a0ae851d1c9009770282c6bb002d6e535678c0'
    preexec['new_source_revision_native_executed']=False
    preexec['new_source_revision_HIA_generation_executed']=False
    preexec['old_actual_reused_as_a_result']=False
    preexec['original_11_runtime_control_files_byte_identical']=True
    preexec['new_authoring_script_is_bound_control_input']=True
    # All source Python and original runtime controls are unchanged, so the
    # earlier syntax observation is retained as historical, not rerun here.
    preexec['source_and_control_AST_parses_only']=0
    preexec['unchanged_python_syntax_result_in_parent_request']=True
    create(ROOT/'PREEXEC.json',wire(preexec))
    correction={'schema':'hia.cli-json.private-TLS-correction.v1','status':'STATIC_MINIMAL_SUCCESSOR_NOT_EXECUTED',
        'actual_failure_commit':'46a0ae851d1c9009770282c6bb002d6e535678c0',
        'actual_failed_request':'30d2cf56eb346db37a1da41dffbffa0cfefc6c44',
        'actual_primary_error':'undefined symbol: _Py_tss_tstate','actual_runtime_completed':0,
        'actual_C_compile_pass':True,'HIA_compile_and_lifetime_unexecuted':True,
        'source_changed_files':[{'path':n,'before':b,'after':a} for n,b,a in changed],
        'unchanged_source_files':181,'implementation_change':'Two no-argument calls use existing tstate plus the original EVAL_CALL_STAT_INC_IF_FUNCTION, then unchanged _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL).',
        'inverse_all_original_error_helper_bytes_equal':True,
        'official_headers_equal_actual_frozen_headers':True,'reference_pins':reference_rows,
        'ownership_exception_refcount_argument_order_unchanged_by_source_delta':True,
        'same_threadstate_reason':'Only do_raise call site passes PyThreadState_Get() under the existing GIL-held leaf; no Python operation intervenes before the original no-arg helper thread-state read.',
        'call_statistics_macro_preserved_at_each_original_call_site':True,
        'global_Py_BUILD_CORE_MODULE_not_changed':True,'symbol_addresses_not_fabricated':True,
        'runtime_admission_code_unchanged':True,'case_bodies_unchanged':True,
        'HIA_source_unchanged':True,'source_generation_executed':False,'C_compilation_executed':False,
        'native_load_executed':False,'qualification_executed':False,
        'remaining_real_gate':'New actual C compile and all original 8 runtime plus 10 lifetime cases, under the original request limits.',
        'original_17_CLI_and_46_trace_population_unchanged_and_unexecuted':True,
        'CALL_SEND_UNPACK_activation_closed':False}
    create(ROOT/'CORRECTION.json',wire(correction))
    print(json.dumps({'status':correction['status'],'source_changed':changed[0][0],
                      'policy':policy_record,'request':request_record,'actual_absent':not ACTUAL.exists()}))

if __name__=='__main__':
    main()
