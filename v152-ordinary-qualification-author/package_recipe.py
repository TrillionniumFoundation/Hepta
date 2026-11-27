"""Small immutable recipe author; seven fields deliberately exclude read atime."""
from pathlib import Path
import hashlib,json,stat
ROOT=Path('/home/agent/hia-ordinary-qualification-author-custody-r1-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def cap(p):
 s=p.lstat();b=p.read_bytes();a=p.lstat()
 assert all(getattr(a,k)==getattr(s,k)for k in FIELDS)and stat.S_ISREG(s.st_mode)and s.st_nlink==1
 return{'path':str(p),'pin':{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()},'stat':{k:getattr(s,k)for k in FIELDS}}
note={'status':'METADATA_RECIPE_AUTHOR_FIRST_INLINE_FAILURE_RETAINED',
 'retained_surface':'functions.exec: Script error: Error: recipe author failed',
 'first_inline_helper_used_full_stat_result_equality_including_atime':True,
 'first_recipe_exists_after_failure':False,
 'full_original_nested_tool_output_not_saved':True,
 'diagnostic_read_after_failure_seven_fields_unchanged':True,
 'cause_not_asserted_from_missing_nested_trace':True,
 'successor_change':'Use the established seven-field comparison, excluding access time.',
 'source_and_qualification_author_files_changed':False,'binders_executed':0,'products_executed':0}
with(ROOT/'METADATA-AUTHOR-NOTE.json').open('xb')as f:f.write(enc(note))
pub=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes())
extra=[{'logical':name,**cap(ROOT/name)}for name in('ACTUAL-GIT-READBACK.json','PUBLICATION-INPUTS.json','package_recipe.py','METADATA-AUTHOR-NOTE.json')]
leaves=[{'path':row['logical'],'mode':'100644',**row['pin']}for row in pub['leaves']+extra]
recipe={'schema':'hepta.hia.ordinary-qualification-author.mount.v1','leaves':leaves,
 'author_files':82,'author_bytes':1904030,'qualification_R1_files':44,'qualification_R2_files':29,
 'generation_terminal_reader_author_files':9,'complete_capsule':'AUTHORING-CAPSULE.json',
 'full_actual_GET_restore':'ACTUAL-GIT-READBACK.json','R1_frozen_unchanged':True,
 'R2_only_output_paths_and_bound_descriptors':True,'all_110_control_function_class_bodies_unchanged':True,
 'source_files':3225,'source_tree':'6c506654638513dbe10623da9458d3904a208cc8',
 'future_owners':18,'future_method_invocations':85,'future_actual_compiles':9,
 'qualification_binders_executed':0,'qualification_products_executed':0,'no_source_copy':True,
 'generation_terminal_reader_already_executed_by_Root_separately':True,
 'all_old_failures_and_qualifications_not_transferred':True,'current_cold':False,
 'whole_native':False,'default_activated':False}
with(ROOT/'MOUNT-RECIPE.json').open('xb')as f:f.write(enc(recipe))
extra.append({'logical':'MOUNT-RECIPE.json',**cap(ROOT/'MOUNT-RECIPE.json')})
print(json.dumps(extra,sort_keys=True))
