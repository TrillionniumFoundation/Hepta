"""Project the proven R4 sealer onto the complete terminal R9 data scope."""
from pathlib import Path
import base64,difflib,hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-r8-r4-complete-custody-r1-dda7/build_custody.py')
roots={'r9_actual':Path('/hia-r8-r9-controls-20261114-dda7'),
       'r9_outer':Path('/tmp/hia-r9-controls-outer-r1-dda7'),
       'fresh_admission':Path('/tmp/hia-r9-controls-fresh-admission-r1-dda7'),
       'r9_author':Path('/tmp/hia-r8-r9-controls-author-r1-dda7')}
root_author=Path('/tmp/hia-progress-v149-20261114-dda7')
names=('R9-CONTROLS-ADMISSION-EXEC.json','R9-CONTROLS-ADMISSION-RETURN.json','R9-CONTROLS-AUTHOR-RECIPE.json',
    'R9-CONTROLS-EXEC.json','R9-CONTROLS-R2-EXEC.json','R9-CONTROLS-R2-RETURN.json',
    'R9-CONTROLS-ROOT-LAUNCHER-R1-FAILURE-RETAINED.json','author_r9_controls_admission.py',
    'author_r9_controls_outer.py','author_r9_controls_outer_r2.py','launch_r9_controls_r1.py',
    'launch_r9_controls_r2.py','r9_controls_admission_body.py.txt','r9_controls_outer_header.py.txt',
    'r9_controls_outer_main_prefix.py.txt','verify_r9_controls_admission.py')
extras={n:root_author/n for n in names}
extras['R4-ORIGINAL-SEMANTIC-REPORT.json']=Path('/dev/shm/hia-u32-r8-controls-r4-dda7/semantic/evidence/compact-vm-remaining-r1/REPORT.json')
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(n,b):
 p=ROOT/n
 with p.open('xb') as f:f.write(b)
 p.chmod(0o644)
totals={}
for label,root in roots.items():
 count=size=0
 for here,dirs,files in os.walk(root,followlinks=False):
  if label=='r9_author' and Path(here)==root:dirs[:]=[d for d in dirs if d!='publication-r1']
  for d in dirs:assert stat.S_ISDIR((Path(here)/d).lstat().st_mode)
  for n in files:
   s=(Path(here)/n).lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
   count+=1;size+=s.st_size
 totals[label]={'files':count,'bytes':size}
for p in extras.values():assert stat.S_ISREG(p.lstat().st_mode) and p.lstat().st_nlink==1
assert totals['fresh_admission']['files']==4 and totals['r9_author']['files']==87
actual_count=totals['r9_actual']['files']+totals['r9_outer']['files']
actual_bytes=totals['r9_actual']['bytes']+totals['r9_outer']['bytes']
original=OLD.read_bytes();text=original.decode();before=text
a=text.index('ROOTS={');b=text.index('\ndef need(',a)
new='ROOTS={\n'+''.join(' '+repr(k)+':Path('+repr(str(v))+'),\n' for k,v in roots.items())+'}\nEXTRAS={\n'+''.join(' '+repr(k)+':Path('+repr(str(v))+'),\n' for k,v in extras.items())+'}\n'
text=text[:a]+new+text[b:]
needle='  for here,ds,ns in os.walk(root,followlinks=False):\n   ds.sort();ns.sort();here=Path(here);s=here.lstat()'
# The retained sealer has no s= in the directory line; use its actual exact block.
needle='  for here,ds,ns in os.walk(root,followlinks=False):\n   ds.sort();ns.sort();here=Path(here)'
assert text.count(needle)==1
text=text.replace(needle,'  for here,ds,ns in os.walk(root,followlinks=False):\n   if label==\'r9_author\' and Path(here)==root:ds[:]=[d for d in ds if d!=\'publication-r1\']\n   ds.sort();ns.sort();here=Path(here)')
text=text.replace('r4_actual/','r9_actual/').replace('r4_outer/','r9_outer/').replace('r4_author/','r9_author/')
text=text.replace('hepta.r8.r4','hepta.r9.controls').replace('R4','R9')
assert text.count('2105')==2 and text.count('1110378385')==2
text=text.replace('2105',str(actual_count)).replace('1110378385',str(actual_bytes))
text=text.replace("need(sum(n.startswith('fresh_admission/') for n in rows)==5,'admission raw closure differs')", "need(sum(n.startswith('fresh_admission/') for n in rows)==4,'admission raw closure differs')")
text=text.replace("need(sum(n.startswith('admission_author/') for n in rows)==14,'admission author closure differs')", "need(sum(n.startswith('root_author/') for n in rows)==17,'Root original metadata closure differs')")
text=text.replace("need(sum(n.startswith('r9_author/') for n in rows)==86,'R9 author closure differs')", "need(sum(n.startswith('r9_author/') for n in rows)==87,'R9 author closure differs')")
assert "admission_author/" not in text
write('R4-SEALER-ORIGINAL.py',original)
write('build_custody.py',text.encode())
write('SEALER.diff',''.join(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile='R4-sealer',tofile='R9-sealer')).encode())
write('CUSTODY-SCOPE.json',enc({'schema':'hia.R9.complete-custody-scope.v1','roots':{k:str(v) for k,v in roots.items()},
 'root_extras':{k:str(v) for k,v in extras.items()},'expected_scope_totals':totals,
 'actual_product_outer_files':actual_count,'actual_product_outer_bytes':actual_bytes,
 'original_sealer':pin(original),'projected_sealer':pin(text.encode()),
 'author_recipe':'0495153ef956e3e06eddc2f6bce978068d66ff85',
 'prefix_raw_root_owned_archive':'c8651cfaa94c66c0e69c9a03f891848e81c9b921',
 'author_publication_directory_excluded_as_already_Git_closed_transport':True,
 'all_current_actual_four_groups_included':True,'later_four_not_started':True,
 'whole_source_runtime_original_input_payloads_not_duplicated':True,'archive_only_no_unpacked_copy':True,
 'all_originals_preserved':True,'qualification':'FAIL','products':0}))
print(json.dumps({'scope':totals,'extra_files':len(extras),'actual_files':actual_count,'actual_bytes':actual_bytes,'sealer':pin(text.encode()),'products':0},sort_keys=True))
