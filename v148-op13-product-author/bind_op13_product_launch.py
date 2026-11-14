"""Bind the already verified actual op13 preparation to one original product attempt."""
from pathlib import Path
import hashlib,json,os,stat
ROOT=Path('/tmp/hia-progress-v148-20261114-dda7')
AUTHOR=Path('/tmp/hia-op13-execution-author-r1-dda7')
READBACK=Path('/tmp/hia-op13-binding-readback-actual-r2-dda7/RESULT.json')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b,mode='100644'):return {'bytes':len(b),'mode':mode,'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def read(p):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 stamp={k:getattr(s,k) for k in FIELDS};b=p.read_bytes();assert {k:getattr(p.lstat(),k) for k in FIELDS}==stamp
 return b,{'path':str(p),'pin':pin(b,'100755' if s.st_mode&0o111 else '100644'),'stat':stamp}
def fixed(row):
 b,d=read(row['path']);assert d==row;return b
def dump(p,v):
 b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 with p.open('xb')as f:f.write(b)
 assert p.read_bytes()==b
 return read(p)[1]
review_raw,review_desc=read(READBACK)
assert review_desc['pin']['git_blob']=='4456ff45a7bf01c194f2f5b5ef606d09420b91d1'
review=json.loads(review_raw)
assert review['status']=='PASS_INDEPENDENT_BOUND_SOURCE_ONLY' and review['products']==0 and review['attempt_absent'] is True
assert review['source_origin_full_reads']==review['source_copy_full_reads']==3210 and review['protected_R8_files_full_read']==3180 and review['runtime_files_full_read']==2496
hraw,_=read(AUTHOR/'HANDOFF.json');assert pin(hraw)['git_blob']=='0d0bf592de67db0d79340ff8ab39a8e170dba7d5'
h=json.loads(hraw)
template_raw=fixed(h['files']['PRODUCT-LAUNCH-TEMPLATE-FINAL.json']);template=json.loads(template_raw)
base_raw=fixed(h['files']['PREPARATION-LAUNCH.json']);launch=json.loads(base_raw)
bound_desc=review['actual_bound_plan'];binding_desc=review['actual_binding']
bound=json.loads(fixed(bound_desc));binding=json.loads(fixed(binding_desc))
assert binding['status']=='BOUND_NOT_EXECUTED' and binding['plan']==bound_desc and bound['state']=='BOUND_AWAITING_ROOT_AUTHORIZATION'
assert bound['source_tree']==h['source_tree']=='821bb0ac9c4ce7a7648c1c34ef91406e3a45fbcb'
assert bound['limits']==template['original_limits'] and template['source8']==8 and template['actual_compiles']==8 and template['native_methods']==12
fixed(template['entry'])
argv=template['expected_argv_pattern'][:]
assert argv.count('ACTUAL_BOUND_PLAN_SHA256')==argv.count('ACTUAL_BINDING_RESULT_SHA256')==1
argv[argv.index('ACTUAL_BOUND_PLAN_SHA256')]=bound_desc['pin']['sha256']
argv[argv.index('ACTUAL_BINDING_RESULT_SHA256')]=binding_desc['pin']['sha256']
assert argv[3]==template['entry']['path'] and argv[5]==bound_desc['path'] and argv[9]==binding_desc['path']
launch['argv']=argv;launch['mode']='product';launch['outer']='/tmp/hia-op13-product-outer-r1-dda7'
launch['fixed_inputs']={'entry':template['entry'],'plan':bound_desc,'binding':binding_desc,'root_readback':review_desc,'runtime_exe':h['runtime_byte_authorities']['executable'],'runtime_lib':h['runtime_byte_authorities']['library']}
launch.pop('binding_output_must_be_reviewed_before_product')
launch.pop('missing_exact_source_count')
launch.update(maximum_attempts=1,automatic_retry=False,exact_stage_order=template['exact_stage_order'],root_independent_readback=review_desc['pin'],whole=False,current_cold=False,default=False)
for row in launch['fixed_inputs'].values():fixed(row)
assert not os.path.lexists(launch['outer']) and not os.path.lexists(bound['attempt'])
v=os.statvfs('/dev/shm');assert v.f_bavail*v.f_frsize>=launch['storage_floor']==1073741824
launch_desc=dump(ROOT/'OP13-PRODUCT-LAUNCH-R1.json',launch)
invocation=json.loads(fixed(h['files']['OUTER-INVOCATION.json']))
assert invocation['argv'][1:4]==['-I','-S','-B']
invocation['argv'][-3:]=[str(ROOT/'OP13-PRODUCT-LAUNCH-R1.json'),'--launch-sha256',launch_desc['pin']['sha256']]
invocation['outer_descriptor']=launch_desc
invocation['preparation_only']=False;invocation['product_phase_not_authorized']=False
invocation['status']='ROOT_AUTHORIZED_ONE_EXPLICIT_OP13_PRODUCT_CHAIN'
invocation_desc=dump(ROOT/'OP13-PRODUCT-INVOCATION-R1.json',invocation)
auth={'schema':'hia.root.op13-original-product-authorization.v1','authorized':True,'maximum_attempts':1,'scope':'Source8 then eight real component compiles then twelve separate original Native methods','launch':launch_desc,'invocation':invocation_desc,'root_readback':review_desc,'old_R5_witness10':'FAIL_UNCHANGED_NOT_REQUALIFIED','VM12_authorized':False,'original_limits':template['original_limits'],'storage_floor':1073741824,'automatic_retry':False,'current_cold':False,'whole':False,'production_legacy_retirement':False}
auth_desc=dump(ROOT/'OP13-PRODUCT-AUTHORIZATION-R1.json',auth)
print(json.dumps({'launch':launch_desc['pin'],'invocation':invocation_desc['pin'],'authorization':auth_desc['pin'],'products_started':0},sort_keys=True))
