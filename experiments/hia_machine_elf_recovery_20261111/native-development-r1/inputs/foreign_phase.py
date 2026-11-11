"""Actual four foreign dictionary-order controls before and after the HIA fix.

The before image is deliberately a low-level development image bound to its
own source and compile receipt. The fixed image uses the ordinary installed
selector and its actual current source. No selector source is reassigned.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from common import (SOURCE, COMPILER_SHA, ORACLE_SHA, create, load_exact,
                    read_json, require, stable_file, wire)

def inputs(flags):
    trace=[]
    class Key:
        def __init__(self,row,field):
            self.row,self.field=row,field
        def __hash__(self):
            trace.append(['hash',self.row,self.field])
            return hash(self.field)
        def __eq__(self,other):
            if type(other) is str:
                trace.append(['eq',self.row,self.field,other])
                return self.field == other
            if type(other) is Key:
                trace.append(['eq_key',self.row,self.field,other.row,other.field])
                return self.field == other.field
            trace.append(['eq_other',self.row,self.field,type(other).__name__])
            return NotImplemented
    rows=[]
    for index,flag in enumerate(flags):
        values=(('name','left' if index==0 else 'right'),('offset',index),
                ('size',1),('global',flag))
        rows.append({Key(index,field):value for field,value in values})
    trace.clear()
    return (b'\xc3\xc3',rows,[]),trace

def observe(fn,flags):
    args,trace=inputs(flags)
    try:
        raw=fn(*args)
        result={'kind':'bytes','size':len(raw),'sha256':sha256(raw).hexdigest(),
                'hex':raw.hex()}
    except BaseException as exc:
        result={'kind':'exception','type':type(exc).__qualname__,
                'args_repr':repr(exc.args)}
    return {'result':result,'trace':trace}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--baseline-build',type=Path,required=True)
    parser.add_argument('--oracle',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    sys.path.insert(0,str(SOURCE))
    from hepta.hia_machine_elf_native import NativeMachineElf, installed_machine_elf
    baseline,pin=read_json(args.baseline_build/'build.json')
    require(baseline['status']=='NATIVE_DEVELOPMENT_IMAGE_BUILT'
            and baseline['variant']=='before_filter_key_fix'
            and baseline['compiler_sha256']==COMPILER_SHA
            and baseline['host_successor_compiler_calls']==[],
            'baseline actual build receipt differs')
    source=Path(baseline['actual_source']['path'])
    source_info,_=stable_file(source,baseline['actual_source']['sha256'])
    image_info,image_bytes=stable_file(args.baseline_build/'machine-elf.image.bin',
                                      baseline['image']['sha256'],collect=True)
    receipt=baseline['native_compile_receipt']
    require(receipt['status']=='returned' and receipt['abi_status']==0
            and receipt['artifact_sha256']==COMPILER_SHA
            and receipt['input_sha256']==source_info['sha256']
            and receipt['produced_sha256']==image_info['sha256']
            and baseline['manifest']['source_sha256']==source_info['sha256']
            and baseline['manifest']['image_sha256']==image_info['sha256'],
            'baseline source/image/real B3 compile binding failed')
    old=NativeMachineElf(image_bytes,image_info['sha256'])
    fixed=installed_machine_elf(str(args.manifest))
    oracle=load_exact('complete_608_filter_order_oracle',args.oracle,ORACLE_SHA)
    before={str(p):stable_file(p)[0] for p in (
        args.baseline_build/'build.json',source,args.baseline_build/'machine-elf.image.bin',
        args.manifest,args.oracle,SOURCE/'examples/hia_bootstrap/machine_elf.hiaasm')}
    rows=[]
    error=None
    try:
        for flags in ((False,False),(True,True),(False,True),(True,False)):
            reference=observe(oracle.write_elf_object,flags)
            first=observe(old.write,flags)
            second=observe(fixed.write,flags)
            ordinary_bytes=(reference['result']['kind']=='bytes'
                            and first['result']==reference['result']
                            and second['result']==reference['result'])
            mismatch=first['trace']!=reference['trace']
            fixed_equal=second['trace']==reference['trace']
            rows.append({'id':'global_filter_then_name_keys_'+''.join('1' if f else '0' for f in flags),
                         'flags':list(flags),'original':reference,
                         'before_filter_key_fix':first,'after_filter_key_fix':second,
                         'bytes_equal':ordinary_bytes,'original_counterexample_reproduced':mismatch,
                         'fixed_trace_equal':fixed_equal,
                         'pass':ordinary_bytes and mismatch and fixed_equal})
    except BaseException as exc:
        error=exc
    finally:
        old_counts=dict(old.calls)
        fixed_counts=dict(fixed.calls)
        old._entry=None
        fixed._entry=None
        old._mapping.close()
        fixed._mapping.close()
    after={path:stable_file(path)[0] for path in before}
    passed=(error is None and len(rows)==4 and all(row['pass'] for row in rows)
            and before==after and pin==stable_file(args.baseline_build/'build.json')[0])
    result={'schema':'hepta.hia.machine-elf.filter-key-two-native-variants.v1',
            'status':'PASS' if passed else 'HOLD',
            'scope':'FOUR_ACTUAL_PHASE_ORDER_CONTROLS_ONLY',
            'loaded_case_ids':['global_filter_then_name_keys_'+v for v in ('00','11','01','10')],
            'executed_case_ids':[row['id'] for row in rows],
            'loaded':4,'executed':len(rows),'cases':rows,
            'baseline_selection':'LOW_LEVEL_WITH_ACTUAL_SOURCE_IMAGE_B3_RECEIPT',
            'fixed_selection':'ORDINARY_INSTALLED_SOURCE_BOUND_MANIFEST',
            'baseline_build':pin,'baseline_source':source_info,'baseline_image':image_info,
            'source_before':before,'source_after':after,'source_stable':before==after,
            'baseline_native_operation_counts':old_counts,
            'fixed_native_operation_counts':fixed_counts,
            'foreign_sort_schedule_closed':False,'whole_writer_qualified':False}
    if error is not None:
        result['failure']={'type':type(error).__name__,'text':str(error)}
    create(args.report,wire(result))
    print(json.dumps({'stage':'filter_key_actual_dual_image','status':result['status'],
                      'loaded':4,'executed':len(rows)}),flush=True)
    return 0 if passed else 1

if __name__=='__main__':
    raise SystemExit(main())
