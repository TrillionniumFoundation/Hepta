"""Independent r1-to-r2 inverse and actual complete input reads; no products."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
OLD=Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r1-20261112-e26e')
sys.path.insert(0,str(ROOT/'control'))
from common import require,read_file,save,pin
from support import frozen,read_policy
from original_current_compiler import current_compiler

def main():
    started=time.monotonic_ns()
    pre=json.loads((ROOT/'PREEXEC.json').read_bytes())
    req=json.loads((ROOT/'REQUEST.json').read_bytes())
    policy,policy_pin=read_policy(ROOT/'POLICY.json',req['policy_sha256'])
    prior=json.loads((OLD/'POLICY.json').read_bytes())
    checks=[]
    def check(name,value):
        checks.append({'name':name,'ok':bool(value)})
        require(value,name)
    check('actual operation root absent',not os.path.lexists(policy['operation_root']))
    check('new absolute request/cwd with exact seal',pre['command']==[policy['python']['path'],'-I','-S','-B',
        str(ROOT/'control/launch.py'),'--request',str(ROOT/'REQUEST.json'),'--sha256',
        hashlib.sha256((ROOT/'REQUEST.json').read_bytes()).hexdigest()] and pre['cwd']==str(ROOT))
    for row in prior['control_files']:
        check('original control bytes:'+row['path'],(ROOT/row['path']).read_bytes()==(OLD/row['path']).read_bytes())
    check('only one new authoring input',policy['control_files'][:-1]==prior['control_files']
          and policy['control_files'][-1]['path']=='freeze_revision.py')
    changed=[]
    for row in prior['source_files']:
        name=row['path'];a=(OLD/'source'/name).read_bytes();b=(ROOT/'source'/name).read_bytes()
        if a!=b:changed.append(name)
    check('one source delta and 181 byte-identical sources',changed==['hepta/hia_cli_json_cpython312_errors.inc']
          and len(policy['source_files'])==len(prior['source_files'])==182)
    old=(OLD/'source'/changed[0]).read_bytes();new=(ROOT/'source'/changed[0]).read_bytes()
    inverse=new.replace(
      b' * Two function names are local. The r2 call sites additionally use the\n * already-held tstate, preserving EVAL_CALL_API bookkeeping and Vectorcall.\n * This avoids importing private TLS; error and ownership order are unchanged.\n',
      b' * Only two local function identifiers change. No JSON traversal,\n * message selection, normalization or lifetime body is rewritten.\n').replace(
      b'        EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, exc);\n        value = _PyObject_CallNoArgsTstate(tstate, exc);',
      b'        value = _PyObject_CallNoArgs(exc);').replace(
      b'            EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, cause);\n            fixed_cause = _PyObject_CallNoArgsTstate(tstate, cause);',
      b'            fixed_cause = _PyObject_CallNoArgs(cause);')
    check('exact complete error helper inverse',inverse==old)
    check('only two tstate no-arg calls and preserved statistics',new.count(b'_PyObject_CallNoArgsTstate(tstate,')==2
          and new.count(b'EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API,')==2
          and b'_PyObject_CallNoArgs(' not in new)
    restored=json.loads(json.dumps(policy));restored['source_files']=prior['source_files']
    restored['control_files']=restored['control_files'][:-1]
    restored['operation_key']=prior['operation_key'];restored['operation_root']=prior['operation_root']
    restored['c_command']=[v.replace(str(ROOT),str(OLD)).replace(policy['operation_root'],prior['operation_root'])
                           for v in policy['c_command']]
    check('complete policy inverse outside exact source and authoring/identity',restored==prior)
    oldreq=json.loads((OLD/'REQUEST.json').read_bytes());backreq=dict(req)
    for key in ['operation_key','operation_root','policy_sha256']:backreq[key]=oldreq[key]
    check('complete request inverse',backreq==oldreq)
    check('same 8+10 exact IDs and expected 48+11 populations',policy['runtime_ids']==prior['runtime_ids']
          and policy['lifetime_ids']==prior['lifetime_ids'] and len(policy['runtime_ids'])==8
          and len(policy['lifetime_ids'])==10 and policy['expected_total_HIA_returns']==48
          and policy['expected_total_C_pump_calls_including_refusals']==11)
    check('same original 17 CLI and 46 trace IDs retained',policy['preserved_original17_and46']==prior['preserved_original17_and46'])
    check('same original owner, compiler and child limits',policy['qualification_seconds']==180
          and policy['cleanup_seconds']==3 and policy['child_seconds']==5
          and policy['compiler_limits']=={'wall_seconds':20,'cpu_seconds':10,'output_capacity':1<<20}
          and policy['c_compiler_limits']==prior['c_compiler_limits'])
    check('same actual qualified HIA bytes',all((ROOT/row['path']).read_bytes()==(OLD/row['path']).read_bytes()
          for row in prior['asset_files']))
    observation=frozen(policy)
    observation_pin=save(ROOT/'proof/FROZEN-INPUTS.READBACK.json',observation)
    check('complete current physical frozen inputs read',observation['source_files']==182
          and len(observation['system']['files'])==4555)
    old_read=json.loads((OLD/'proof/FROZEN-INPUTS.READBACK.json').read_bytes())
    check('complete physical system observations unchanged from r1',observation['system']==old_read['system'])
    base=Path(policy['compiler_origin_root'])
    compiler=current_compiler(base,policy,read_file)
    compiler_pin=save(ROOT/'proof/CURRENT-COMPILER.READBACK.json',compiler)
    check('all current-v89 62 original compiler files reread',len(compiler['originals'])==62
          and compiler['compiler_from_current_v89_cold'] is True)
    check('no qualification inherited into this source',policy['fresh_cold'] is False
          and policy['current_v92_matching_claimed'] is False
          and policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False)
    check('unchanged policy physical identity',read_file(ROOT/'POLICY.json',2<<20)[1]==policy_pin)
    check('no actual operation after readonly audit',not os.path.lexists(policy['operation_root']))
    result={'schema':'hia.cli-json.private-TLS-request-readonly-audit.v1',
        'status':'READONLY_REQUEST_AND_INPUTS_PASS','checks':checks,'check_count':len(checks),
        'input_observation':observation_pin,'compiler_original_provenance':compiler_pin,
        'elapsed_ns':time.monotonic_ns()-started,'source_generation':False,'C_frontend_executed':False,
        'HIA_compiler_executed':False,'runtime_load_or_symbol_binding_executed':False,
        'finite_case_bodies_executed':False,'original17_executed':False,'original46_executed':False,
        'old_HOLD_preserved':True,'new_actual_absent':True}
    save(ROOT/'proof/READONLY-REQUEST-AUDIT.json',result)
    print(json.dumps({'status':result['status'],'checks':len(checks),'elapsed_ns':result['elapsed_ns'],
                      'source_files':182,'system_files':4555,'compiler_originals':62,'product_executed':False}))

if __name__=='__main__':
    main()
