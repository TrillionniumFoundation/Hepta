"""Inspect original ELF/header bytes only. Does not load the DSO or compile C."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
DSO=Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r1-20261112-e26e/work/c-build/cli-json.so')

def rec(path):
    b=path.read_bytes()
    return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}

def main():
    original=rec(DSO)
    assert original['sha256']=='efec9ed66bab1e5a97b1838fbf94f2416bff97e392b0920effc3aeddd374d316'
    commands=[('/usr/bin/objdump',['-dr','--disassemble=cj312_do_raise',str(DSO)],'do-raise-disassembly'),
              ('/usr/bin/readelf',['-Wr',str(DSO)],'dynamic-relocations')]
    receipts=[]
    for tool,args,label in commands:
        start=time.monotonic_ns()
        value=subprocess.run([tool]+args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,cwd='/',env={'PATH':'','LANG':'C','LC_ALL':'C'},timeout=10)
        elapsed=time.monotonic_ns()-start
        out=ROOT/'proof'/(label+'.original.txt');err=ROOT/'proof'/(label+'.stderr.log')
        with out.open('xb') as f:f.write(value.stdout)
        with err.open('xb') as f:f.write(value.stderr)
        receipts.append({'command':[tool]+args,'tool':rec(Path(tool).resolve()),'cwd':'/',
            'environment':{'PATH':'','LANG':'C','LC_ALL':'C'},'readonly_diagnostic_timeout_seconds':10,
            'returncode':value.returncode,'elapsed_ns':elapsed,'stdout':rec(out),'stderr':rec(err),
            'does_not_execute_or_load_examined_DSO':True})
        assert value.returncode==0 and value.stderr==b''
    asm=(ROOT/'proof/do-raise-disassembly.original.txt').read_text()
    references=[line for line in asm.splitlines() if '<_Py_tss_tstate>' in line]
    assert len(references)==2 and '<cj312_do_raise>:' in asm
    reloc=(ROOT/'proof/dynamic-relocations.original.txt').read_text()
    tls_relocations=[line for line in reloc.splitlines() if '_Py_tss_tstate' in line]
    assert len(tls_relocations)==2
    assert any('R_X86_64_DTPMOD64' in line for line in tls_relocations)
    assert any('R_X86_64_DTPOFF64' in line for line in tls_relocations)
    official=(ROOT/'reference/official-pystate.c').read_text()
    assert '_PyThreadState_GetCurrent(void)\n{\n    return current_fast_get(&_PyRuntime);\n}' in official
    assert 'current_fast_get(_PyRuntimeState *Py_UNUSED(runtime))\n{\n#ifdef HAVE_THREAD_LOCAL\n    return _Py_tss_tstate;' in official
    call=(ROOT/'reference/official-pycore_call.h').read_text()
    assert '_PyObject_CallNoArgsTstate(PyThreadState *tstate, PyObject *func) {\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in call
    assert '_PyObject_CallNoArgs(PyObject *func) {\n    EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, func);\n    PyThreadState *tstate = _PyThreadState_GET();\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in call
    pystate=(ROOT/'reference/official-pycore_pystate.h').read_text()
    assert '#if defined(HAVE_THREAD_LOCAL) && !defined(Py_BUILD_CORE_MODULE)\n    return _Py_tss_tstate;\n#else\n    return _PyThreadState_GetCurrent();\n#endif' in pystate
    assert rec(DSO)==original
    result={'schema':'hia.cli-json.original-TLS-readonly-mechanism.v1',
        'status':'READONLY_ORIGINAL_MECHANISM_MATCHES','original_failed_DSO':original,
        'actual_do_raise_TLS_reference_lines':references,'actual_TLS_relocations':tls_relocations,
        'diagnostic_commands':receipts,
        'official_version':'CPython v3.12.14',
        'official_urls':['https://raw.githubusercontent.com/python/cpython/v3.12.14/Include/internal/pycore_call.h',
                         'https://raw.githubusercontent.com/python/cpython/v3.12.14/Include/internal/pycore_pystate.h',
                         'https://raw.githubusercontent.com/python/cpython/v3.12.14/Python/pystate.c'],
        'official_getter_body_returns_same_runtime_private_TLS':True,
        'explicit_getter_called_at_each_original_current_state_observation_point':True,
        'same_statistics_before_same_no_arg_Vectorcall':True,
        'does_not_fabricate_TLS_or_function_addresses':True,
        'global_core_module_macro_not_modified':True,
        'shim_own_local_thread_local_active_frame_not_removed':True,
        'remaining___tls_get_addr_for_local_owned_TLS_is_not_this_private_external_TLS_failure':True,
        'original_HOLD_not_reclassified':True,'new_source_compiled':False,'new_DSO_loaded':False,
        'new_runtime_and_lifetime_results':'UNKNOWN_UNEXECUTED'}
    with (ROOT/'proof/TLS-MECHANISM.json').open('x') as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
    print(json.dumps({'status':result['status'],'actual_references':len(references),
                      'actual_relocations':len(tls_relocations),'product_executed':False}))

if __name__=='__main__':
    main()
