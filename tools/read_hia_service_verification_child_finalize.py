"""Pure-data readback of the independent child FINALIZE resource control.

This validates the new control's raw identity and observations. It does not
replace the original Native8, complete finite/packet or whole cold gates.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import struct
ROOT=Path(__file__).resolve().parents[1]

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}

def require(value,message):
    if not value:raise ValueError(message)

def read(report_path,authority_path,*,expected_report,expected_authority):
    captured={}
    def raw(path,expected=None):
        path=Path(path);value=path.read_bytes()
        if expected is not None:
            require(canonical(pin(value))==canonical(expected),'consumed raw identity differs: '+str(path))
        if path in captured:require(captured[path]==value,'second read changed: '+str(path))
        captured[path]=value
        return value
    def js(path,expected=None):return json.loads(raw(path,expected))
    authority=js(authority_path,expected_authority)
    report=js(report_path,expected_report)
    require(authority['schema']=='hepta.hia.service-verification-finalize-authority.v1','authority schema')
    require(report['schema']=='hepta.hia.service-verification-child-finalize-control.v1','control schema')
    require(report['status']=='PASS_INDEPENDENT_CHILD_CONTROL_ONLY','control did not complete')
    require(canonical(report['authority'])==canonical(expected_authority),'inner authority pin')
    require(report['case_id']=='nested-SUBJECT-FINALIZE-before-SQL','complete independent case')
    require(report['original_event_only_predicate_preserved'] is True,'original predicate scope')
    require(report['whole_native_stack_qualified'] is False,'overbroad qualification')
    for name in ('pid','ppid','pgid'):
        require(type(report[name]) is int and report[name]>0,'process identity '+name)
    require(report['pid']==report['pgid'],'child does not own reported group')
    require(report['scope']==authority['scope'] and authority['scope'] in (
        'DEVELOPMENT_COMPONENT','MATCHING_SOURCE_COLD_COMPONENT'),'construction scope')
    tree=ast.parse(raw(ROOT/'tools/build_hia_service_verification.py'))
    inputs=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='INPUTS' for t in n.targets)))
    require(set(authority['source_inputs'])==set(inputs),'complete source membership')
    sources={name:sha256(raw(ROOT/name)).hexdigest() for name in inputs}
    require(canonical(sources)==canonical(authority['source_inputs']),'actual source inputs')
    require(canonical(report['source_before'])==canonical(sources)
            and canonical(report['source_after'])==canonical(sources),'source drift')
    for name in ('verification','store','context'):
        item=authority['manifests'][name]
        manifest=js(item['path'],item['pin'])
        image=raw(Path(item['path']).parent/manifest['image_path'])
        require(sha256(image).hexdigest()==manifest['image_sha256'],'compiled image changed')
        require(manifest['compiler_sha256']==authority['compiler']['sha256'],'compiler identities differ')
        build=js(item['build_path'],item['build_pin'])
        require(build['scope']==authority['scope'],'build scope differs')
        require(canonical(build['manifest'])==canonical(manifest),'build/manifest differ')
        if name=='verification':
            require(canonical(build['component_inputs'])==canonical(sources),'verification build inputs')
            require(report['actual_image_sha256']==manifest['image_sha256'],'executed image differs')
    require(canonical(pin(raw(authority['compiler_path'])))==canonical(authority['compiler']),
            'actual compiler changed')
    if authority['scope']=='MATCHING_SOURCE_COLD_COMPONENT':
        cold=raw(authority['cold_report_path'],authority['cold_report'])
        require(all(js(authority['manifests'][n]['build_path'])['cold_report_sha256']==sha256(cold).hexdigest()
                    for n in ('verification','store','context')),'three build cold identities differ')
    else:
        require(authority['cold_report_path'] is None and authority['cold_report'] is None,'DEV has cold claim')
    basis=raw(ROOT/'tests/fixtures/hia_service_verification_original_r12/cases.json')
    require(canonical(pin(basis))==canonical({'bytes':47104,
        'sha256':'270dca9e230051d50359281c5ba73be82329cdfa997d4058a72554ac637b065e'}),'immutable original basis')
    require(canonical(report['original_basis'])==canonical(pin(basis)),'basis pin differs')
    original_case=next(row for row in json.loads(basis)['base_cases'] if row['id']=='verify.core.outer0')
    require(canonical(report['original_basis_case'])==canonical(original_case),'original case changed')
    entries=report['entries'];fired=report['fired'];facts=report['facts']
    require(type(entries) is list and entries and type(fired) is list and len(fired)==1,'actual entries/fault count')
    finals=[]
    for index,row in enumerate(entries):
        buffers=[]
        for key,size in (('request',128),('output',96),('state',192)):
            text=row[key]
            require(type(text) is str,'buffer type')
            value=bytes.fromhex(text)
            require(len(value)==size and value.hex()==text,'buffer extent/canonical hex')
            buffers.append(value)
        q=struct.unpack('<16Q',buffers[0]);a=struct.unpack('<12Q',buffers[1])
        for key,value in (('event',q[1]),('port',q[3]),('mode',q[5]),('sequence',q[2]),('phase',a[4])):
            require(type(row[key]) is int and row[key]==value,'decoded transport field '+key)
        require(type(row['code']) is int and row['code']==96,'actual entry return extent')
        if q[1]==4:finals.append((index,q,a))
    require(len(finals)==1,'original event-only predicate must hit once')
    index,q,a=finals[0]
    require(index==len(entries)-1 and q[5]==2 and a[4]==4,'actual early SUBJECT FINALIZE')
    require(canonical(fired[0])==canonical({'entry_index':index,'mode':2,'event':4,'phase':4,'code':96}),
            'fault occurrence does not match actual native return')
    true_fields=('result_is_none','error_is_owner_unknown','fault_is_direct_cause',
        'selected_owner_is_distinct','selected_record_is_child_record','selected_child_fenced',
        'parent_fenced','parent_loss_is_child_loss','loss_owner_is_child',
        'loss_error_is_injected_fault','untouched_store_has_no_recorded_loss',
        'parent_retry_is_unknown','child_retry_is_unknown','public_close_exact_receiver',
        'public_close_returned_none','actual_connection_closed','retained_loss_unchanged_after_healthy_close')
    for name in true_fields:require(facts[name] is True,'actual control failed: '+name)
    require(facts['selected_child_finished'] is False and facts['parent_finished'] is False,'false completed outcome')
    require(type(facts['selected_owner_mode']) is int and facts['selected_owner_mode']==2,'child owner identity')
    for name in ('retry_added_entries','retry_added_faults','close_added_verification_entries'):
        require(type(facts[name]) is int and facts[name]==0,'unexpected retry/entry: '+name)
    require(type(facts['public_close_calls']) is int and facts['public_close_calls']==1,'one actual original close')
    require(facts['public_close_error'] is None,'healthy unused Store close failed')
    for value in (facts['SQL_before_close'],facts['SQL_after_retry'],facts['SQL_after_close'],report['SQL']):
        require(type(value) is list and value==[],'pre-publication control had SQL')
    require(report['SQL_trace_scope']=='after original Store construction through close probe','SQL trace scope')
    for path,value in captured.items():require(path.read_bytes()==value,'input changed at terminal: '+str(path))
    return {'schema':'hepta.hia.service-verification-child-finalize-readback.v1',
        'status':'PASS_READBACK_ONLY','report':expected_report,'authority':expected_authority,
        'actual_entry_count':len(entries),'actual_fault_count':1,
        'actual_fault_event':4,'actual_fault_mode':2,'parent_mode':3,
        'SQL_count_after_constructor':0,'public_close_count':1,
        'actual_SQLite_connection_closed':True,'sticky_child_and_parent_loss_retained':True,
        'scope':authority['scope'],'original_Native8_qualified':False,
        'parent_VERIFY_FINALIZE_qualified':False,'whole_native_stack_qualified':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--report-bytes',type=int,required=True)
    parser.add_argument('--report-sha256',required=True)
    parser.add_argument('--authority',type=Path,required=True)
    parser.add_argument('--authority-bytes',type=int,required=True)
    parser.add_argument('--authority-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=read(args.report,args.authority,
        expected_report={'bytes':args.report_bytes,'sha256':args.report_sha256},
        expected_authority={'bytes':args.authority_bytes,'sha256':args.authority_sha256})
    with args.output.open('xb') as stream:stream.write(canonical(result)+b'\n')
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
