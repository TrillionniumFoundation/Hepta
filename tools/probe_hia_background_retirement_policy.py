"""Offline source-policy probes; these are not native execution qualification.

Inputs model the concrete new dependency contracts. In particular a consumed
reference and a successful status are deliberately independent observations.
"""
from pathlib import Path
import json
from tools import hia_background_retirement_source as policy

O=bytearray(4096)
C={**policy.MAGICS,'PUBLIC_REPLY':int.from_bytes(b'HIABFRP1','little'),
   'RP':1024,'PUBLIC_OUT':2048,'FEEDBACK':8,'DROP_ACTIVE':16,'DROP_KNOWN':24,
   'VALUE_PENDING':32,'JOB_PENDING':40,'FUTURE_PENDING':48}
def get(o,at):return int.from_bytes(o[at:at+8],'little')
def put(o,at,n):o[at:at+8]=n.to_bytes(8,'little');return 0
def zero(o,at,n):o[at:at+n]=bytes(n);return 0
def valid(o,at,magic):return int(get(o,C['FEEDBACK'])==0 and get(o,at)==magic)
env={**C,'u64':int,'mutbuf':bytearray,'get':get,'put':put,'zero':zero,'valid':valid,
     'choose':lambda condition,a,b:a if condition else b}
exec(policy.SOURCE,env)
CAP=(91,181,271);CAP_AT=256
rows=[]
def run(label,kind,fields,expected,mutations=(),feedback=0):
    O[:]=bytes(len(O))
    for i,n in enumerate(CAP):put(O,CAP_AT+8*i,n)
    put(O,C['FEEDBACK'],feedback)
    if kind=='value':
        base=C['RP'];magic=C['VALUE_DROP_REPLY'];fn='release_value'
    elif kind=='job':
        base=C['RP'];magic=C['JOB_DROP_REPLY'];fn='release_job'
    elif kind=='future':
        base=C['PUBLIC_OUT'];magic=C['PUBLIC_DROP_REPLY'];fn='release_future'
    else:raise AssertionError(kind)
    put(O,base,magic)
    for k,v in fields.items():put(O,base+k,v)
    for k,v in mutations:put(O,base+k,v)
    env['release_begin'](O)
    rc=env[fn](O,CAP_AT)
    state=(rc,tuple(get(O,CAP_AT+8*i)for i in range(3)),
           get(O,C['DROP_ACTIVE']),get(O,C['DROP_KNOWN']),
           get(O,C['VALUE_PENDING']),get(O,C['JOB_PENDING']),get(O,C['FUTURE_PENDING']))
    assert state==expected,(label,state,expected)
    rows.append({'label':label,'accepted_to_continue':bool(rc),'cap_cleared':state[1]==(0,0,0),
                 'known_class':state[3],'pending':list(state[4:])})
    return state

def expect(rc,cleared,known,v=0,j=0,f=0):
    return(rc,(0,0,0)if cleared else CAP,0 if rc else 1,known,v,j,f)

v={8:0,80:0,88:1,96:1}
run('value ordinary consumption','value',v,expect(1,True,1))
run('value actual munmap EIO after consumption','value',{**v,8:11,80:1},expect(1,True,1,v=1))
run('value consumed dependency failure without recorded mapping','value',{**v,8:11},expect(0,True,2))
for status in (1,6,11):
    run('value proven pre-consumption '+str(status),'value',{**v,8:status,96:0},expect(0,False,1))
run('value closed mapping still pending','value',{8:6,80:1,88:1,96:0},expect(0,False,1,v=1))
for at in list(range(16,80,8))+list(range(104,128,8)):
    run('value reserved '+str(at),'value',v,expect(0,False,0),[(at,1)])
for fields in ({88:0,96:0},{88:2},{96:2},{80:2},{8:9},{8:5},{8:999},{8:1},{8:6},{96:0},{80:1},{8:1,96:0,80:1}):
    run('value contradictory '+repr(fields),'value',{**v,**fields},expect(0,False,0))
run('value transport failure','value',v,expect(0,False,0),feedback=4294967293)

j={8:0,128:1,136:1,144:0}
run('Job ordinary consumption','job',j,expect(1,True,1))
run('Job post-consumption retirement retained','job',{**j,8:9,144:1},expect(1,True,1,j=1))
run('Job consumed failure without retained owner','job',{**j,8:9},expect(0,True,2))
for status in (1,5,6,9):
    run('Job pre-consumption '+str(status),'job',{**j,8:status,128:0},expect(0,False,1))
for fields in ({136:0},{128:2},{144:2},{128:0},{144:1},{8:4},{8:1}):
    run('Job contradictory '+repr(fields),'job',{**j,**fields},expect(0,False,0))

f={8:0,16:0,96:1,104:1}
run('Future ordinary consumption','future',f,expect(1,True,1))
run('Future RuntimeError after consumption','future',{**f,8:1,16:107},expect(1,True,1,f=1))
run('Future successful call with owner cleanup warning','future',{**f,120:(1<<64)-1},expect(1,True,1,f=1))
for status in (1,3):
    run('Future pre-consumption '+str(status),'future',{**f,8:status,16:107,96:0},expect(0,False,1))
for fields in ({104:0,96:0},{104:2},{96:2},{96:0},{8:2,16:200},{8:3,16:107},{72:123},{80:456},{88:789}):
    run('Future unknown/contradictory '+repr(fields),'future',{**f,**fields},expect(0,False,0))

def retry(label,fn,magic,fields,expect_rc,expect_known,expect_pending):
    O[:]=bytes(len(O));put(O,C['VALUE_PENDING'],1);put(O,C['JOB_PENDING'],1);put(O,C['FUTURE_PENDING'],1)
    put(O,C['RP'],magic)
    for k,v in fields.items():put(O,C['RP']+k,v)
    env['release_begin'](O);rc=env[fn](O)
    got=(rc,get(O,C['DROP_KNOWN']),[get(O,C[x])for x in('VALUE_PENDING','JOB_PENDING','FUTURE_PENDING')])
    assert got==(expect_rc,expect_known,expect_pending),(label,got)
    rows.append({'label':label,'accepted_to_continue':bool(rc),'known_class':got[1],'pending':got[2]})

retry('value mapping EIO repeat','release_value_retry',C['VALUE_DROP_REPLY'],{8:11,80:1,88:1,96:0},0,1,[1,1,1])
retry('value mapping retry completes','release_value_retry',C['VALUE_DROP_REPLY'],{8:0,80:0,88:1,96:0},1,1,[0,1,1])
retry('value retry unknown dependency','release_value_retry',C['VALUE_DROP_REPLY'],{8:11,80:0,88:1,96:0},0,2,[1,1,1])
retry('value retry cannot emit bad-cap status','release_value_retry',C['VALUE_DROP_REPLY'],{8:1,80:0,88:1,96:0},0,0,[1,1,1])
retry('value retry cannot emit allocation status','release_value_retry',C['VALUE_DROP_REPLY'],{8:5,80:0,88:1,96:0},0,0,[1,1,1])
retry('value retry cannot claim success with pending mapping','release_value_retry',C['VALUE_DROP_REPLY'],{8:0,80:1,88:1,96:0},0,0,[1,1,1])
retry('value retry cannot consume a reference','release_value_retry',C['VALUE_DROP_REPLY'],{8:11,80:1,88:1,96:1},0,0,[1,1,1])
retry('Job claim busy is not empty','release_job_retry',C['JOB_DROP_REPLY'],{8:5,128:0,136:1,144:1},0,1,[1,1,1])
retry('Job retirement completes','release_job_retry',C['JOB_DROP_REPLY'],{8:0,128:0,136:1,144:0},1,1,[1,0,1])
retry('cell pending after successful retry','release_cell_query',C['CELL_QUERY_REPLY'],{8:0,128:0,136:1,144:1},0,1,[1,1,1])
retry('cell unknown empty is not proof','release_cell_query',C['CELL_QUERY_REPLY'],{8:0,128:0,136:0,144:0},0,0,[1,1,1])
retry('cell locked empty observation','release_cell_query',C['CELL_QUERY_REPLY'],{8:0,128:0,136:0,144:1},1,1,[1,1,0])

report={'schema':'hepta.hia.background.retirement-source-policy-probes.v1',
        'source_policy_probes_passed':len(rows),'rows':rows,
        'executed_native_product':False,'native_qualification':False,'whole_background':False}
path=Path(__file__).resolve().parents[1]/'docs/HIA_BACKGROUND_NATIVE_RETIREMENT_SOURCE_PROBES.json'
path.write_text(json.dumps(report,indent=2)+'\n')
print('source policy probes',len(rows),'PASS; native qualification pending')
