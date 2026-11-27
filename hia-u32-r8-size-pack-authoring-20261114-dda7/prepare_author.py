"""Capture bounded fixed inputs and write an author-only plan; no product import."""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat

ROOT = Path(__file__).resolve().parent
ENTRY = Path('/tmp/hia-u32-entry-layout-r1-dda7')
BASE = Path('/workspace/scratch/dda74a4fae35')
OLD = BASE / 'v99-canonical-roundtrip-process-r1/successor-r2/evidence/build-r2/built'
R8 = BASE / 'v117-dense-token-r8-r1'
BUILDER = BASE / 'v120-union-r20/source/tools/build_hia_linux_file_roundtrip_program.py'
STAT_KEYS = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
COMMON = ('require','pin','state','read_regular','identity','write','dump',
          'source_snapshot','same_source','controls','runtime','function_text',
          'owner_return','complete_owner')
PACK = ('_digest','_frame','_elf_structure')

def require(value, message):
    if not value:
        raise AssertionError(message)

def stamp(value):
    return {k:getattr(value,k) for k in STAT_KEYS}

def captured(path):
    p=Path(path); before=p.lstat()
    require(stat.S_ISREG(before.st_mode),'fixed ordinary file required: '+str(p))
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        require(stamp(os.fstat(fd))==stamp(before),'opened input differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
        require(len(raw)==before.st_size and stamp(os.fstat(fd))==stamp(before)
                and stamp(p.lstat())==stamp(before),'input drift during full read')
    finally:os.close(fd)
    return raw,stat.S_IMODE(before.st_mode),stamp(before)

def pin(raw,mode=None):
    row={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
         'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:row.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return row

def write(path,raw,mode=0o644):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    os.chmod(path,mode)
    actual,m,_=captured(path)
    require(actual==raw and m==mode,'new author file readback differs')

def dump(path,value):
    write(path,(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode())

def function_text(path,name):
    text=captured(path)[0].decode()
    nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name]
    require(len(nodes)==1,'unique retained function required')
    n=nodes[0]
    return ''.join(text.splitlines(keepends=True)[n.lineno-1:n.end_lineno])

def fixed_row(path):
    raw,mode,_=captured(path)
    return {'path':str(path),'identity':pin(raw,mode)}

def main():
    require(not (ROOT/'EXECUTION-PLAN.json').exists() and not (ROOT/'inputs').exists(),
            'unique author capture already exists; do not overwrite')
    entry_plan=json.loads(captured(ENTRY/'EXECUTION-PLAN.json')[0])
    source=Path(entry_plan['source']['path'])
    rows=[]
    def take(origin,name):
        raw,mode,before=captured(origin)
        destination=ROOT/'inputs'/name
        write(destination,raw,mode)
        require(captured(origin)==(raw,mode,before),'input changed after independent copy')
        rows.append({'origin':str(origin),'origin_stat':before,'origin_identity':pin(raw,mode),
                     'captured':destination.relative_to(ROOT).as_posix(),
                     'captured_identity':pin(raw,mode)})
        return raw
    for suffix in ('image.bin','input.bin','output.bin','request.json','receipt.json','stdout.log','stderr.log'):
        take(ENTRY/'actual-inputs'/('B3.'+suffix),'u32/B3.'+suffix)
    for label in ('controller','representation','packer'):
        for suffix in ('hepta','image.bin','input.bin','output.bin','request.json','receipt.json','stdout.log','stderr.log'):
            take(OLD/(label+'.'+suffix),'retained/'+label+'.'+suffix)
    take(OLD/'captured-compiler.image.bin','retained/captured-compiler.image.bin')
    take(OLD/'REPORT.json','retained/REPORT.json')
    take(R8/'source/examples/hia_bootstrap/file_render_checker_v4.hepta','R8.hepta')
    exact={
      'u32/B3.image.bin':(658860,'56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764'),
      'retained/controller.image.bin':(59889,'5f23e0aefb1cb4749c7ce4a8c50c694367357051144f34cec8867e32d5eba6e2'),
      'retained/representation.image.bin':(430261,'0ba4d693b9533b13aa059b7e4bb68ba482119f2109f1ae87c44c0d6a72cddba7'),
      'retained/packer.image.bin':(31031,'7a5556523bfcc294c125106d837323a2cc5c5181b502a5ff99841e432aa0d839'),
      'retained/captured-compiler.image.bin':(616621,'6e8d31b694721b79c693417f0687338bc15277971496f6deaa7ff6e1ed357338'),
      'R8.hepta':(395910,'83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de')}
    for name,wanted in exact.items():
        raw=captured(ROOT/'inputs'/name)[0]
        require((len(raw),pin(raw)['sha256'])==wanted,'fixed actual input differs: '+name)
    dump(ROOT/'INPUTS.json',{'schema':'hia.u32-r8-fixed-actual-inputs.v1','files':rows,
         'all_copies_independent_inodes':all((ROOT/r['captured']).stat().st_ino!=r['origin_stat']['st_ino']
                                          or (ROOT/r['captured']).stat().st_dev!=r['origin_stat']['st_dev'] for r in rows),
         'product_executions':0})
    for name in ('FROZEN-3180-SOURCE.json','ACTUAL-INPUT-MANIFEST.json','EXTRACTION-RESULT.json'):
        raw,mode,_=captured(ENTRY/name);write(ROOT/name,raw,mode)
    loaders={}
    for name in ('retained_buffer_observer.py','retained_buffer_child.py'):
        origin=R8/'authoring'/name
        raw,mode,_=captured(origin);write(ROOT/name,raw,mode)
        loaders[name]={'origin':str(origin),'captured_identity':pin(raw,mode),
                       'original_whole_file_bytes_equal':True}
    functions={name:{'text':function_text(BUILDER,name)} for name in PACK}
    prefix='''"""Three unchanged retained inspection/frame functions; no product imports."""
from hashlib import sha256
import struct
CAPACITY = 1 << 20
PACK_MAGIC = int.from_bytes(b'HFRTPAK1', 'little')
LABELS = ('controller', 'representation', 'semantic')

'''
    write(ROOT/'retained_pack_contract.py',(prefix+'\n\n'.join(functions[n]['text'] for n in PACK)+'\n').encode())
    dump(ROOT/'PROJECTION.json',{'original_builder':str(BUILDER),'original_builder_identity':fixed_row(BUILDER)['identity'],
         'functions':functions,'unchanged_loader_files':loaders,
         'production_checked_components_not_called_or_modified':True,
         'replacement_is_private_packing_only':True})
    original_support=ENTRY/'entry_support.py'
    common={name:function_text(original_support,name) for name in COMMON}
    support_prefix='''"""Private R8 size/pack support; importing performs no product call."""
from pathlib import Path
import ast
import hashlib
import json
import os
import platform
import stat
import sys
import time
import traceback
ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / 'EXECUTION-PLAN.json'
PLAN_RAW = PLAN_PATH.read_bytes()
PLAN = json.loads(PLAN_RAW)
SOURCE = Path(PLAN['source']['path'])
OUT = Path(PLAN['output'])
CAPACITY = 1 << 20
STAT_KEYS = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

'''
    extension=captured(ROOT/'support_extension.py.txt')[0].decode()
    write(ROOT/'size_support.py',(support_prefix+'\n\n'.join(common.values())+'\n\n'+extension).encode())
    dump(ROOT/'RETAINED-SUPPORT.json',{'original_path':str(original_support),
         'original_identity':fixed_row(original_support)['identity'],'functions':common,
         'all_fourteen_whole_functions_exact':True})
    controls={}
    local=('run_size_pack.py','size_support.py','retained_pack_contract.py','retained_buffer_observer.py',
           'retained_buffer_child.py','INPUTS.json','FROZEN-3180-SOURCE.json','ACTUAL-INPUT-MANIFEST.json',
           'EXTRACTION-RESULT.json','PROJECTION.json','RETAINED-SUPPORT.json')
    for name in local:controls['author:'+name]=fixed_row(ROOT/name)
    controls['retained_builder']=fixed_row(BUILDER)
    controls['retained_R8_driver']=fixed_row(R8/'authoring/run_compact_build_r1.py')
    controls['retained_entry_support']=fixed_row(original_support)
    controls['owner_source']=entry_plan['owner_source']
    environment=dict(entry_plan['environment']);environment['HOME']=str(ROOT)
    plan={
      'schema':'hia.u32-r8.size-conditional-pack.execution-plan.v1',
      'status':'FROZEN_AUTHORING_ONLY_NOT_EXECUTED','root':str(ROOT),'output':str(ROOT/'evidence/attempt-r1'),
      'source':entry_plan['source'],'new_source_relative':entry_plan['new_source_relative'],
      'ordinary_SOURCE_path':entry_plan['ordinary_SOURCE_path'],'ordinary_SOURCE_rebound':False,
      'runtime':entry_plan['runtime'],'environment':environment,'controls':controls,
      'source_guard':'Complete 3180 paths/bytes/modes/seven inode fields before/after each parent/child',
      'input_authority':{'u32_run':43579403463,'u32_artifact':14108215158,
          'actual_B3_image':exact['u32/B3.image.bin'],'actual_input_member_manifest':'ACTUAL-INPUT-MANIFEST.json',
          'actual_input_extraction':'EXTRACTION-RESULT.json','retained_aggregate_build':str(OLD),
          'retained_profile_compiler_and_three_images_not_recompiled':True},
      'predecessor_entry20':{'actual_checks':20,'independent_full_readback':'2d9f44985e60f221919d12b9b6991128cd3f0694',
          'reader_r2':'f0bd61949ec71cd45a8df06fb539894d69338e5b','originals':830,'logical_bytes':173880184,
          'scope':'Finite explicit entry-layout gate; no ordinary SOURCE/current-cold/all-input transfer'},
      'original_R8_history':{'image_bytes':562746,'image_sha256':'2138fd3f57a76e3ac5ad00fee9d2b1a3e36c0af24395b7c491a772d788a3ab21',
          'compiler':'ordinary B3 673413B/bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0',
          'conservative_shortfall_bytes':6600,'original_execution_not_repeated':True,
          'semantic_or_aggregate_qualification':False},
      'execution':{'compile_calls':1,'pack_calls_if_both_capacity_gates_pass':1,'automatic_retry':False,
          'owner_qualification_seconds':180,'owner_cleanup_seconds':3,'compile_pack_share_one_owner':True,
          'native_per_call_seconds':20,'native_per_call_cleanup_seconds':3,'native_cpu_seconds':10,
          'source_output_workspace_max_bytes':1<<20,'address_bytes':256<<20,'stack_bytes':8<<20,
          'file_size_bytes':16<<20,'open_files':32,'core_dumpable':False,'source_tree_copy':False,
          'compiler_imports_in_machine_child':False,'ELF_exec_calls':0,'VM_calls':0,
          'semantic_native_cases':0,'aggregate_cases':0,
          'owner_covers':'Child runtime/controls/input/source checks, compile, conditional pack, after guards, child result and six-buffer inventory',
          'outside_owner':'Parent preflight, parent source/input/runtime/control finalization and complete raw inventory are separately timed; not claimed within 183 seconds'},
      'capacity':{'bytes':1<<20,'fixed_controller_bytes':59889,'fixed_representation_bytes':430261,
          'frame_header_bytes':48,'image_offsets':[1024,60928,491200],
          'maximum_new_image_by_frame':558378,'maximum_new_image_by_ELF':557376,
          'exact_reduction_required_from_old_R8':5370,'page_size':4096},
      'raw_capture':{'each_attempt':'before/after full source/output/workspace plus physical canaries, child stdout/stderr/request/report and observed hex',
          'compile_six_buffers':True,'pack_six_buffers_only_if_attempted':True,
          'timeout_partial_files_preserved':True,'missing_child_terminal_never_implies_zero_attempts':True,
          'ELF_file_mode':'0644, no exec, no promotion'},
      'storage':{'conservative_raw_allowance_bytes':96<<20,'post_raw_reserve_bytes':128<<20,
          'required_free_bytes':224<<20,'no_raw_cleanup_or_truncation':True},
      'nonclaims':['matching-current-source u32 cold','ordinary encoding gate','R8 semantic 162 or six VM gates',
          'aggregate 130 kernel / seven pipeline VM / six fullframes / two last-byte controls',
          'production R5 source-pin replacement','all-input refinement','whole language','whole native'],
      'new_CI':False,'product_executions_before_root_authorization':0}
    dump(ROOT/'EXECUTION-PLAN.json',plan)
    plan_raw=captured(ROOT/'EXECUTION-PLAN.json')[0]
    dump(ROOT/'COMMAND-INTENT.json',{'state':'PREPARED_NOT_EXECUTED_REQUIRES_ROOT_AUTHORIZATION',
         'argv':[plan['runtime']['executable']['path'],'-I','-S','-B',str(ROOT/'run_size_pack.py'),
                 '--plan-sha256',pin(plan_raw)['sha256']], 'environment':environment,'cwd':str(ROOT),
         'unique_output':plan['output'],'plan':pin(plan_raw),'product_executions':0})
    for name in ('run_size_pack.py','size_support.py','retained_pack_contract.py',
                 'retained_buffer_observer.py','retained_buffer_child.py','prepare_author.py'):
        ast.parse(captured(ROOT/name)[0])
    for name in PACK:require(function_text(ROOT/'retained_pack_contract.py',name)==functions[name]['text'],'pack whole function changed')
    for name in COMMON:require(function_text(ROOT/'size_support.py',name)==common[name],'support whole function changed')
    for row in rows:
        raw,mode,before=captured(row['origin'])
        require(pin(raw,mode)==row['origin_identity'] and before==row['origin_stat'],'author changed original input')
    result={'status':'AUTHOR_ONLY_CAPTURE_AND_STATIC_READBACK_PASS','captured_input_files':len(rows),
         'captured_input_bytes':sum(r['captured_identity']['bytes'] for r in rows),
         'plan':pin(plan_raw),'controls':len(controls),'pack_functions_exact':len(PACK),
         'retained_support_functions_exact':len(COMMON),'retained_loader_files_exact':2,
         'product_executions':0,'native_calls':0,'VM_calls':0,'new_CI':0}
    dump(ROOT/'AUTHOR-READBACK.json',result)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
