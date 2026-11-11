"""Development differential only; never a matching-source cold qualification."""
import copy
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path('/workspace/scratch/623459b0e1bc/Hepta')
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
from hepta.hia_program import verify_program, HIAProgramRejected
from hepta.hia_core_admission_native import NativeCoreAdmission, SOURCE, ERROR_CODES
from tests.test_hia_core_admission_native import interpreted, wire, VALID, returned_aliases
from tools.qualify_hia_selfhost import compile_stage

OUT = ROOT.parent / 'core-admission-development'
OUT.mkdir(exist_ok=True)
compiler = Path(sys.argv[1]).resolve()
assert interpreted(wire(VALID)) == 0
assert interpreted(wire(returned_aliases(('mutbuf','mutbuf')))) == 0xfffffff8
original = subprocess.check_output(['git', 'show', 'c2d937e5eec734af5c1d5d0519afc7e3a91df58a:examples/hia_bootstrap/core_admission.hiaasm'])
old_image, _ = compile_stage(OUT, 'original-core-admission', compiler, original)
image, receipt = compile_stage(OUT, 'core-admission', compiler, SOURCE.read_bytes())
raw = image.read_bytes()
native = NativeCoreAdmission(raw, sha256(raw).hexdigest())
old = old_image.read_bytes()
old_native = NativeCoreAdmission(old, sha256(old).hexdigest())
witnesses=[]
for types in (('mutbuf','mutbuf'),('readbuf','mutbuf'),('mutbuf','readbuf'),('u32','mutbuf','buffer','readbuf'),('readbuf','readbuf'),('u32','readbuf','buffer','readbuf'),('buffer','chain','u64','mutbuf')):
    doc=returned_aliases(types)
    try:
        verify_program(doc);expected=0
    except HIAProgramRejected as exc:
        expected=exc.code
    witnesses.append({'types':types,'host':expected,'original_native':old_native.status(wire(doc)),'fixed_native':native.status(wire(doc))})
print('RETURN WITNESSES', json.dumps(witnesses), flush=True)

corpus=[('empty',copy.deepcopy(VALID))]
modules=['test_hia_program','test_hia_returned_loans','test_hia_returned_chain_loans','test_hia_returned_loan_interfaces','test_hia_returned_loan_budgets','test_hia_rust_returned_loans','test_hia_rust_returned_chains','test_hia_rust_chain_shadow','test_hia_program_native_review']
for module_name in modules:
    module=importlib.import_module('tests.'+module_name)
    for name,fn in vars(module).items():
        if not inspect.isfunction(fn) or fn.__module__!=module.__name__:continue
        if any(p.default is inspect.Parameter.empty and p.kind not in (inspect.Parameter.VAR_POSITIONAL,inspect.Parameter.VAR_KEYWORD) for p in inspect.signature(fn).parameters.values()):continue
        try:value=fn()
        except Exception:continue
        if type(value) is dict and str(value.get('schema','')).startswith('hepta.hia.program.v') and 'types' not in value:
            corpus.append((module_name+'.'+name,value))

rng=random.Random(889713)
checks=0
different=[]
acceptance=[]
coverage={}
def compare(label,doc):
    global checks
    try:verify_program(doc);expected=None
    except HIAProgramRejected as exc:expected=exc.code
    except Exception as exc:expected=type(exc).__name__
    status=native.status(wire(doc))
    actual=ERROR_CODES.get(status,str(status)) if status else None
    checks+=1;coverage[expected or 'accepted']=coverage.get(expected or 'accepted',0)+1
    if actual!=expected:
        record={'label':label,'expected':expected,'observed':actual,'status':status,'document':doc}
        different.append(record)
        if bool(status)!=bool(expected):
            acceptance.append(record);print('ACCEPTANCE DIFFERENCE',label,expected,actual,flush=True)
        elif len(different)<=10:print('DIAGNOSTIC DIFFERENCE',label,expected,actual,flush=True)
    return len(acceptance)<10

for name,doc in corpus:compare(name,doc)
print('BASE CORPUS',len(corpus),'DIFFERENCES',len(different),flush=True)
def nodes(doc):
    found=[]
    def walk(obj,path):
        if type(obj) is dict:
            for k,v in obj.items():found.append((path+[k],v));walk(v,path+[k])
        elif type(obj) is list:
            for k,v in enumerate(obj):found.append((path+[k],v));walk(v,path+[k])
    walk(doc,[]);return found

values=[None,False,True,0,1,-1,2**64,-2**63-1,'x','missing','alloc','read','write','trap','u8','u32','i64','usize','buffer','chain','readbuf','mutbuf',[],{},['x']]
for iteration in range(12000):
    name,source=rng.choice(corpus);doc=copy.deepcopy(source)
    path,old_value=rng.choice(nodes(doc));holder=doc
    for key in path[:-1]:holder=holder[key]
    mode=rng.randrange(7)
    if mode==0 and type(old_value) is list and old_value:
        new=copy.deepcopy(old_value);del new[rng.randrange(len(new))]
    elif mode==1 and type(old_value) is list and old_value:
        new=copy.deepcopy(old_value);new.insert(rng.randrange(len(new)+1),copy.deepcopy(rng.choice(old_value)))
    elif mode==2 and type(old_value) is list:
        new=copy.deepcopy(old_value);rng.shuffle(new)
    elif mode==3 and type(old_value) is str:
        new=rng.choice([v for _,v in nodes(source) if type(v) is str])
    elif mode==4 and type(old_value) is dict and old_value:
        new=copy.deepcopy(old_value);del new[rng.choice(list(new))]
    else:new=copy.deepcopy(rng.choice(values))
    holder[path[-1]]=new
    if not compare(f'{iteration}:{name}:{path}',doc):break
    if iteration%2000==1999:print('CHECKED',checks,'DIFFERENT',len(different),'ACCEPTANCE',len(acceptance),flush=True)
summary={'development_only':True,'compiler_image_sha256':sha256(compiler.read_bytes()).hexdigest(),'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),'image_sha256':sha256(raw).hexdigest(),'original_image_sha256':sha256(old_image.read_bytes()).hexdigest(),'returned_alias_witnesses':witnesses,'corpus':[n for n,_ in corpus],'checks':checks,'coverage':coverage,'acceptance_differences':acceptance,'all_differences':different}
(OUT/'differential.json').write_text(json.dumps(summary,indent=2)+'\n')
print('COMPLETE',checks,len(different),len(acceptance),flush=True)
