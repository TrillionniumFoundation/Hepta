"""Mechanical static R9-to-R10 diagnostic author; no project/product execution."""
from pathlib import Path
import ast,difflib,hashlib,json,os
OLD=Path('/tmp/hia-r9-cross-counted-author-r1-dda7')
ROOT=Path(__file__).resolve().parent
OUTPUT='/workspace/hia-r10-cross-counted-r1-dda7'
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644);assert p.read_bytes()==b
def dump(p,x):write(p,(json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())
assert not os.path.lexists(OUTPUT)
for name in ('counted_machine.py','counted_support.py','run_cross_counted.py','freeze_authoring.py','FROZEN-3180-SOURCE.json','EXECUTION-PLAN.json','LAUNCH.json','CONTRACT.md'):
    write(ROOT/'before'/name,(OLD/name).read_bytes())
proof={}
for name in ('run_cross_counted.py','counted_support.py','freeze_authoring.py'):
    before=(OLD/name).read_bytes();text=before.decode();edits=[]
    def change(a,b,count=None):
        global text
        n=text.count(a);assert n and (count is None or n==count),(name,a,n,count)
        edits.append({'before':a,'after':b,'count':n});text=text.replace(a,b)
    change('R9','R10');change('r9','r10')
    if name=='run_cross_counted.py':change('==6347,','==6299,',1)
    if name=='freeze_authoring.py':
        for a,b in [
        ("OLD=Path('/tmp/hia-r8-r10-controls-author-r1-dda7')","OLD=Path('/tmp/hia-r10-controls-author-r1-dda7')"),
        ("EVIDENCE=Path('/hia-r8-r10-controls-20261114-dda7/semantic/evidence')","EVIDENCE=Path('/workspace/hia-r10-controls-r1-dda7/semantic/evidence')"),
        ('/hia-r8-r10-execution-20261114-dda7/generated/file_render_checker_word64.hepta','/workspace/hia-r10-prefix-r1-dda7/generated/file_render_checker_word64_bytes.hepta'),
        ('/hia-r8-r10-execution-20261114-dda7/size-pack/R8.u32.image.bin','/workspace/hia-r10-prefix-r1-dda7/size-pack/R8.u32.image.bin'),
        ('5e998dee9ed4c5b4156ba3b778b218ca1fd5992c','dcf7ab874951a9e0742b8cc17138095cd2af0973'),
        ('4caa8a0e7c76128b260b8384689ecba873fd63e2','78b32200cc4843860a6e60a9870d6ac306ae76d7'),
        ("'R8_to_R10_whole_inverse'","'R9_to_R10_whole_inverse'")]:change(a,b,1)
    after=text.encode();inverse=text
    for edit in reversed(edits):
        assert inverse.count(edit['after'])==edit['count'];inverse=inverse.replace(edit['after'],edit['before'])
    assert inverse.encode()==before and ast.dump(ast.parse(inverse))==ast.dump(ast.parse(before));ast.parse(after)
    write(ROOT/name,after);write(ROOT/'diffs'/(name+'.diff'),''.join(difflib.unified_diff(before.decode().splitlines(True),text.splitlines(True),fromfile='R9/'+name,tofile='R10/'+name)).encode())
    proof[name]={'before':pin(before),'after':pin(after),'edits':edits,'whole_byte_inverse_equal':True,'whole_AST_inverse_equal':True}
for name in ('counted_machine.py','FROZEN-3180-SOURCE.json'):write(ROOT/name,(OLD/name).read_bytes())
dump(ROOT/'EXACT-INVERSE.json',{'schema':'hepta.r10.cross-counted-mechanical-inverse.v1','status':'STATIC_ONLY','product_executions':0,'project_imports':0,'Counted_class_file_whole_equal':True,'Counted_class_file':pin((ROOT/'counted_machine.py').read_bytes()),'source_map_whole_equal':True,'files':proof})
dump(ROOT/'AUTHORING-STEP.json',{'status':'TEXT_PROJECTED_NO_PRODUCT','files':sorted(proof),'future_output_absent':not os.path.lexists(OUTPUT),'new_counted_machine_invocations':0})
print(json.dumps({'status':'AUTHORING_TEXT_READY','files':{k:v['after'] for k,v in proof.items()},'products':0},sort_keys=True))
