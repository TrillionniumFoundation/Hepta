from pathlib import Path
import ast, hashlib, json, shutil

ROOT=Path('/workspace/scratch/dda74a4fae35')
BEFORE=ROOT/'v76-qualification-v10r2-joint-draft'
OUT=ROOT/'v76-qualification-v10r2-published-4b19-r1'
HEAD='4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE='1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
assert not OUT.exists()
shutil.copytree(BEFORE,OUT,ignore=shutil.ignore_patterns('delivery','__pycache__'))
changes={}
def change(name,after):
    p=OUT/name;before=p.read_bytes();after=after.encode() if isinstance(after,str) else after
    old=OUT/'originals/pin-parent-joint-draft'/name
    old.parent.mkdir(parents=True,exist_ok=True);old.write_bytes(before)
    assert before!=after
    p.write_bytes(after)
    changes[name]={'before_bytes':len(before),'before_sha256':hashlib.sha256(before).hexdigest(),
                   'after_bytes':len(after),'after_sha256':hashlib.sha256(after).hexdigest(),
                   'before_retained':str(old.relative_to(OUT))}
def replace(name, before, after):
    text=(OUT/name).read_text();assert text.count(before)==1,(name,before)
    change(name,text.replace(before,after,1))

change('candidate_pin.py','"""Exact published product source; this pin grants no qualification."""\n'
       +"EXPECTED_HEAD = '"+HEAD+"'\nEXPECTED_TREE = '"+TREE+"'\nPUBLISHED_SOURCE_PIN_REQUIRED = True\n")
d=json.loads((OUT/'DEPENDENCIES.json').read_bytes())
d['historical_joint_projection_target']=d['target']
d['configuration']={'head':HEAD,'tree':TREE,'scope':'PUBLISHED_JOINT_SOURCE_PINNED_NOT_QUALIFIED'}
d['target']={'head':HEAD,'tree':TREE,'business_source_materialization':'Exact generated 3153-file product tree; source run 43191903430 completed 80 generators and 728 unique source controls; each byte/mode and full Git tree independently verified.'}
d['prior_joint_packet_blob']='a60522b2be05c896773563436485311e1984285a'
d['new_owner_family_boundary']='Adds MACHINE_ELF, MACHINE_PLAN and SERVICE_CONTEXT for exact published 4b19 source; no previous cold, component or full qualification is inherited.'
d['status']='PUBLISHED_SOURCE_PINNED_STATIC_REVIEW_ONLY_NOT_QUALIFIED'
d['static_review']='observations/published-4b19-static-r1.json'
d['actual_loader_observation']='observations/published-4b19-loader-r1.json'
change('DEPENDENCIES.json',json.dumps(d,sort_keys=True,indent=2)+'\n')
s=(OUT/'build_source_packet.py').read_text()
s=s.replace('import zlib\n','import zlib\nfrom candidate_pin import EXPECTED_HEAD, EXPECTED_TREE\n',1)
s=s.replace("'status': 'AUTHORED_STATIC_REVIEW_ONLY_NOT_QUALIFIED'", "'status': 'PUBLISHED_SOURCE_PINNED_STATIC_REVIEW_ONLY_NOT_QUALIFIED'",1)
before="'configuration': {'head': None, 'tree': None,\n                                'scope': 'UNPUBLISHED_JOINT_SOURCE_PROJECTION'}"
assert before in s
s=s.replace(before,"'configuration': {'head': EXPECTED_HEAD, 'tree': EXPECTED_TREE,\n                                'scope': 'PUBLISHED_JOINT_SOURCE_PINNED_NOT_QUALIFIED'}",1)
s=s.replace("'requires_new_published_source_pin_and_frozen_packet_before_launch': True,",
            "'requires_new_published_source_pin_and_frozen_packet_before_launch': False,\n              'requires_new_matching_source_cold_and_full_qualification': True,\n              'prior_joint_packet_blob': 'a60522b2be05c896773563436485311e1984285a',",1)
change('build_source_packet.py',s)
replace('workflow-v10r2.template.yml',"ref: '@@CANDIDATE_HEAD@@'","ref: '"+HEAD+"'")
replace('check_workflow_static.py',"'observations/joint-workflow-syntax-r2'","'observations/published-4b19-workflow-syntax-r1'")
s=(OUT/'README.md').read_text()
a=s.index('**This joint draft has no product commit or tree pin.**')
b=s.index('The root-owned joint source projection is ',a)
s=s[:a]+('**This successor is pinned to the published product source.**\n'
          'Head: \x60'+HEAD+'\x60; tree: \x60'+TREE+'\x60.\n'
          'The full 3,153-file tree was independently admitted from source run\n'
          '43191903430 after 80 generators and all 728 unique source controls passed.\n'
          'This establishes source generation only. Current-source cold, full native,\n'
          'default selection and legacy deletion remain unqualified.\n\n'
          'The prior unpinned joint packet \x60a60522b2be05c896773563436485311e1984285a\x60\n'
          'and every earlier observation remain immutable. Each pin-dependent file\n'
          'changed by this successor is retained under originals/pin-parent-joint-draft.\n'
          'A separate workflow will resolve this successor packet identity before any\n'
          'launch; the packet template retains packet placeholders to avoid self-reference.\n\n')+s[b:]
s=s.replace('The root-owned joint source projection is \x60v76-unified-integration-r1/source\x60.',
            'The admitted exact local export is \x60v76-product-publication-r1/source\x60.',1)
s=s.replace('Bind a new published joint head/tree, recheck final workflow and source-owned\nqualifier bytes, rerun static projection on exact source, freeze the complete\npacket and resolve workflow identity. This draft triggers no CI and changes\nno product/ref.',
            'The published head/tree are bound in this successor. Recheck the exact\nworkflow and source-owned qualifier bytes, retain fresh loader/static observations,\nfreeze the complete packet and resolve workflow identity before launch. This\nauthoring step itself triggers no CI and changes no product/ref.',1)
change('README.md',s)
for name in changes:
    if name.endswith('.py'):compile((OUT/name).read_bytes(),str(OUT/name),'exec')
authority=json.loads((ROOT/'v76-product-publication-r1/PUBLICATION.json').read_bytes())
assert authority['head']==HEAD and authority['tree']==TREE
(OUT/'PUBLISHED-PIN-AUTHORITY.json').write_text(json.dumps(authority,sort_keys=True,indent=2)+'\n')
result={'schema':'hia.qualification-v10r2.published-pin-authoring.v1','head':HEAD,'tree':TREE,
        'prior_joint_packet_blob':'a60522b2be05c896773563436485311e1984285a',
        'changes':changes,'active_runner_changed':False,'original_tests_or_budgets_changed':False,
        'qualification_executed':False,'current_source_cold_qualified':False,
        'whole_native_delivery_qualified':False}
(OUT/'PUBLISHED-PIN-DELTA.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result),flush=True)

