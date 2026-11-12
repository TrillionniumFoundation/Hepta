from pathlib import Path
from hashlib import sha256
from copy import deepcopy
import json
import subprocess
import sys
import time
import yaml

ROOT=Path(__file__).resolve().parent
before={p:sha256((ROOT/p).read_bytes()).hexdigest() for p in ('original-r2.yml','revised-r3.yml')}
old=yaml.load((ROOT/'original-r2.yml').read_text(),Loader=yaml.BaseLoader)
new=yaml.load((ROOT/'revised-r3.yml').read_text(),Loader=yaml.BaseLoader)
projected=deepcopy(new)
projected['name']=old['name']
projected['on']['push']['branches']=old['on']['push']['branches']
steps=projected['jobs']['context-development']['steps']
checkout=[s for s in steps if s.get('name')=='Checkout exact current product source']
assert len(checkout)==1
assert checkout[0]['with'].pop('fetch-depth')=='2'
assert projected==old
commands=[]
def call(label,argv,cwd,expected=0):
    started=time.monotonic_ns()
    result=subprocess.run(argv,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
    record={'label':label,'argv':argv,'cwd':str(cwd),'returncode':result.returncode,
            'stdout':result.stdout.decode(),'stderr':result.stderr.decode(),
            'elapsed_ns':time.monotonic_ns()-started,'timeout_seconds':15}
    commands.append(record)
    (ROOT/(label+'.stdout.log')).write_bytes(result.stdout)
    (ROOT/(label+'.stderr.log')).write_bytes(result.stderr)
    assert result.returncode==expected,record
    return result.stdout.decode().strip()
fixture=ROOT/'git-fixture'
fixture.mkdir(exist_ok=False)
origin=fixture/'origin'
call('init',['git','init','--initial-branch=main',str(origin)],ROOT)
call('name',['git','config','user.name','HIA fixture'],origin)
call('email',['git','config','user.email','hia-fixture@example.invalid'],origin)
(origin/'witness.txt').write_text('original parent\n')
call('add-parent',['git','add','witness.txt'],origin)
call('commit-parent',['git','commit','-m','fixture parent'],origin)
parent=call('parent',['git','rev-parse','HEAD'],origin)
(origin/'witness.txt').write_text('exact child\n')
call('add-child',['git','add','witness.txt'],origin)
call('commit-child',['git','commit','-m','fixture child'],origin)
head=call('head',['git','rev-parse','HEAD'],origin)
for depth in (1,2):
    target=fixture/('depth-'+str(depth))
    call('clone-'+str(depth),['git','clone','--depth='+str(depth),origin.as_uri(),str(target)],ROOT)
    assert call('head-'+str(depth),['git','rev-parse','HEAD'],target)==head
    value=call('parent-'+str(depth),['git','rev-parse','HEAD^'],target,128 if depth==1 else 0)
    if depth==2:
        assert value==parent
assert before=={p:sha256((ROOT/p).read_bytes()).hexdigest() for p in before}
report={'schema':'hia.context-ci.checkout-depth-controls.v1','status':'PASS',
        'tests':3,'observations':['exact workflow projection preserves all old steps and limits',
                                 'real depth-one Git checkout refuses strict parent lookup with 128',
                                 'real depth-two Git checkout returns exact original parent'],
        'python':sys.version,'commands':commands,'input_sha256_before_after':before,
        'fixture_only':True,'product_git_identity_tested':False,'native_execution_performed':False,
        'original_remote_failure_blob':'42999ce8957a519185e7231768ddccc02c8b4831'}
(ROOT/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':'PASS','tests':3,'depth_one_parent_returncode':128,'depth_two_exact_parent':True}))
