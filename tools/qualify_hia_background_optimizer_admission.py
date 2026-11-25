"""Actual native ordered admission leaves against original BG methods.

Original path/Core/runtime/thread effects are stopped or replaced only at leaf
boundaries. This qualifies the pure stages, not a live runtime or whole BG.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes as C,json,math,random,struct,sys,threading
from types import SimpleNamespace
from unittest.mock import patch
W=Path(__file__).resolve().parents[1];sys.path.insert(0,str(W))
import hepta.hia_background_optimizer as bg
from hepta.hia_program import _verify_program_reference
from tools.qualify_hia_background_optimizer_structure import Flat
from tools.qualify_hia_background_optimizer_json_capture import Capture,encode
NONE=(1<<64)-1
class Stop(BaseException):pass
def stop(*a,**k):raise Stop()
class Thread:
 def __init__(self,*a,**k):pass
 def start(self):pass
 def join(self):pass
class Runtime(bg.ScalarMultiversionRuntime):
 def __init__(self,snapshot=None):self.value=snapshot
 def snapshot(self):
  if self.value is None:raise Stop()
  return self.value
def original_error(call):
 try:call();return None
 except Stop:return None
 except Exception as e:return {'type':type(e).__name__,'message':str(e)}
def source(typ='u64',name='calculate',exports=False):
 f={'name':name,'params':[{'name':'x','type':typ}],'returns':[typ],'effects':[],'entry':'entry','blocks':[{'id':'entry','params':[{'name':'x','type':typ}],'ops':[],'term':{'op':'ret','values':['x']}}]}
 x={'schema':'hepta.hia.program.v9','module':'background_admission','functions':[f]}
 if exports:x['exports']=[name]
 return x
def snapshot(program,last=None,*,closed=False,current=0,epoch=0,baseline=True,current_kind=0):
 last=program if last is None else last
 rows=[]
 if baseline:rows.append({'baseline':True,'generation':0,'program_sha256':program.sha256,'input_sha256':program.input_sha256})
 if current_kind==0:
  if not baseline:rows.append({'baseline':False,'generation':current,'program_sha256':program.sha256,'input_sha256':program.input_sha256})
  elif current!=0:rows.append({'baseline':False,'generation':current,'program_sha256':program.sha256,'input_sha256':program.input_sha256})
 elif current_kind==1:rows.append({'baseline':False,'generation':current,'program_sha256':last.sha256,'input_sha256':last.input_sha256})
 elif current_kind==2:rows.append({'baseline':False,'generation':current,'program_sha256':'12'*32,'input_sha256':'34'*32})
 current=current if any(row['generation']==current for row in rows)else None
 return {'closed':closed,'current_generation':current,'selection_epoch':epoch,'generations':rows}
def snapshot_wire(s):
 originals=[row for row in s['generations'] if row['baseline']]
 cur=next((row for row in s['generations']if row['generation']==s['current_generation']),None)
 gen=str(s['current_generation']).encode()if cur is not None else b''
 epoch=str(s['selection_epoch']).encode()
 flags=int(bool(s['closed']))|(2 if len(originals)==1 else 0)|(4 if cur is not None else 0)
 raw=bytearray(256);raw[:8]=b'HIAMVBS1';struct.pack_into('<4Q',raw,16,flags,len(gen),len(epoch),256+len(gen)+len(epoch))
 if len(originals)==1:raw[64:96]=bytes.fromhex(originals[0]['program_sha256']);raw[96:128]=bytes.fromhex(originals[0]['input_sha256'])
 if cur is not None:raw[128:160]=bytes.fromhex(cur['program_sha256']);raw[160:192]=bytes.fromhex(cur['input_sha256'])
 return bytes(raw)+gen+epoch
def bare(program,last,snap):
 x=object.__new__(bg.BackgroundOptimizer);x._baseline=program;x._last_program=last;x._runtime=Runtime(snap)
 x._condition=threading.Condition();x._pending={};x._closed=False;x._max_pending=8;x._worker=Thread()
 return x
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 D=args.output;D.mkdir(exist_ok=False)
 flat=Flat(args.directory/'background_optimizer_admission.flat');cap=Capture(args.capture)
 rows=[];counts={};report={'passed':False,'whole_background_qualified':False,'flat_sha256':flat.sha,'capture_sha256':cap.flat.sha,'scope':__doc__,'counts':counts,'cases':rows}
 base=_verify_program_reference(source());last=_verify_program_reference(source(name='other'))
 def frame(mode,opts=None,core=None,snap=None,program=base,latest=last,gen=None,epoch=None):
  on=oa=cn=ca=b''
  if opts is not None:on=encode(opts);rc,oa,elapsed,stats=cap.decode(on);assert rc==0
  if core is not None:cn=encode(core);rc,ca,elapsed,stats=cap.decode(cn);assert rc==0
  gn=b''if gen is None else str(gen).encode();en=b''if epoch is None else str(epoch).encode();sn=b''if snap is None else snapshot_wire(snap)
  h=bytearray(256);h[:8]=b'HIABAD01';struct.pack_into('<8Q',h,8,mode,len(on),len(oa),len(cn),len(ca),len(gn),len(en),len(sn))
  h[80:112]=bytes.fromhex(program.sha256);h[112:144]=bytes.fromhex(program.input_sha256);h[144:176]=bytes.fromhex(latest.sha256);h[176:208]=bytes.fromhex(latest.input_sha256)
  return bytes(h)+on+oa+cn+ca+gn+en+sn,oa,ca
 def native(raw):
  sourcebuf=C.create_string_buffer(raw);out=C.create_string_buffer(544);work=C.create_string_buffer(1048576+32)
  C.memset(out,0xdb,len(out));C.memset(work,0xa5,len(work))
  rc=flat.entry(sourcebuf,len(raw),C.addressof(out)+16,512,C.addressof(work)+16,1048576)
  assert sourcebuf.raw==raw+b'\0'and out.raw[:16]+out.raw[-16:]==b'\xdb'*32 and work.raw[:16]+work.raw[-16:]==b'\xa5'*32
  if rc:return rc,None,None,out.raw[16:528]
  head=struct.unpack_from('<8s15Q',out,16);assert head[0]==b'HIABAR01'and head[1]in(0,1)
  error=json.loads(out.raw[16+128:16+128+head[3]])if head[1]else None
  return 0,error,head,out.raw[16:528]
 def run(name,mode,expected=None,**kw):
  raw,oa,ca=frame(mode,**kw);rc,error,head,out=native(raw)
  try:assert rc==0 and error==expected,(name,rc,error,expected)
  except BaseException:
   (D/'failure.input').write_bytes(raw);(D/'failure.output').write_bytes(out)
   (D/'failure.json').write_text(json.dumps({'case':name,'mode':mode,'rc':rc,'actual':error,'expected':expected,'completed':len(rows)},indent=2)+'\n');raise
  rows.append({'case':name,'mode':mode,'input_sha256':sha256(raw).hexdigest(),'expected':expected,'result':error,'words':list(head[1:]),'passed':True});counts[str(mode)]=counts.get(str(mode),0)+1
  if len(rows)%100==0:(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('ADMISSION_CASE',len(rows),name,flush=True)
  return head,oa,ca
 good={'function':'calculate','bridge':{'binary':'/tmp/binary','build_receipt':'/tmp/receipt'}}
 def options_oracle(x):
  kw=dict(x);function=kw.pop('function');bridge=kw.pop('bridge')
  with patch.object(bg,'Path',side_effect=Stop):
   return original_error(lambda:bg.BackgroundOptimizer(Runtime(),None,function=function,bridge=bridge,**kw))
 vals=[None,False,True,-1,0,1,2,8,9,60,61,5000,5001,2**63-1,2**63,2**64,10**80,1.0,8.0,60.0,0.0,-0.0,1e-300,5e-324,math.inf,-math.inf,math.nan,'','1','x',[],{},[1]]
 for key in ['max_pending','timeout_ms','bridge_timeout_s']:
  for i,value in enumerate(vals):
   x=copy.deepcopy(good);x[key]=value
   h,oa,_=run('option-'+key+'-'+str(i),0,options_oracle(x),opts=x)
   if h[1]==0:
    assert h[4]==x.get('max_pending',8)and h[5]==x.get('timeout_ms',2000)
    bits=struct.unpack('<Q',struct.pack('<d',x.get('bridge_timeout_s',10.0)))[0]
    assert h[6]==bits and h[7]==int(type(x.get('bridge_timeout_s',10.0))is int)
 for i,bridge in enumerate([None,False,1,'x',[],{}, {'binary':'a'},{'build_receipt':'b'},{'binary':'a','build_receipt':'b','extra':'c'},{'binary':None,'build_receipt':[]},{'build_receipt':'b','binary':'a'}]):
  x={**good,'bridge':bridge};h,oa,_=run('bridge-'+str(i),0,options_oracle(x),opts=x)
  if h[1]==0:
   keys=[]
   for node in [h[8],h[9]]:
    off,n=struct.unpack_from('<2Q',oa,64+72*node+40);keys.append(oa[off:off+n].decode())
   assert keys==list(bridge)
 rng=random.Random(291817)
 for i in range(180):
  x=copy.deepcopy(good)
  for key in ['max_pending','timeout_ms','bridge_timeout_s']:x[key]=rng.choice(vals)
  if i%3==0:x['bridge']=rng.choice([{},None,{'binary':'a'},{'build_receipt':'b','binary':'a'}])
  run('ordered-option-'+str(i),0,options_oracle(x),opts=x)
 programs=[_verify_program_reference(source(t))for t in ['bool','i8','i16','i32','i64','isize','u8','u16','u32','u64','usize','unit']]
 programs.append(_verify_program_reference(source(exports=True)))
 hidden=source();hidden['exports']=[];programs.append(_verify_program_reference(hidden))
 borrowed=source();borrowed['functions'][0]['params'][0]['type']='readbuf';borrowed['functions'][0]['blocks'][0]['params'][0]['type']='readbuf';borrowed['functions'][0]['blocks'][0]['ops']=[{'op':'const','args':[],'out':[{'name':'answer','type':'u64'}],'attrs':{'value':0}}];borrowed['functions'][0]['blocks'][0]['term']['values']=['answer'];programs.append(_verify_program_reference(borrowed))
 for i,program in enumerate(programs):
  for j,fn in enumerate(['calculate','missing','',False,0,1,None,[],{},'\ud800','calculate\0','x'*10000]):
   opts={**good,'function':fn}
   with patch.object(bg,'verify_program',return_value=program),patch.object(bg,'Path',return_value=SimpleNamespace(resolve=lambda:'/same')):
    expected=original_error(lambda:bg.BackgroundOptimizer(Runtime(),{},function=fn,bridge=good['bridge']))
   run('function-'+str(i)+'-'+str(j),1,expected,opts=opts,core=program.as_dict(),program=program)
 wide=source();wf=wide['functions'][0]
 wf['params']=[{'name':'x'+str(i),'type':'u64'}for i in range(23000)]
 wf['blocks'][0]['params']=copy.deepcopy(wf['params']);wf['blocks'][0]['term']['values']=['x0']
 wideprogram=_verify_program_reference(wide)
 for fn in ['calculate','missing']:
  opts={**good,'function':fn}
  with patch.object(bg,'verify_program',return_value=wideprogram),patch.object(bg,'Path',return_value=SimpleNamespace(resolve=lambda:'/same')):
   expected=original_error(lambda:bg.BackgroundOptimizer(Runtime(),{},function=fn,bridge=good['bridge']))
  h,oa,ca=run('wide-core-'+fn,1,expected,opts=opts,core=wideprogram.as_dict(),program=wideprogram)
  assert struct.unpack_from('<Q',ca,8)[0]>131072
 for i,program in enumerate([base,last]):
  for closed in [False,True]:
   for original in [False,True]:
    for current in [0,1,2**64+1,10**100]:
     for kind in [0,1,2,3]:
      snap=snapshot(program,last,closed=closed,current=current,baseline=original,current_kind=kind)
      with patch.object(bg,'verify_program',return_value=program),patch.object(bg,'Path',return_value=SimpleNamespace(resolve=lambda:'/same')),patch.object(bg.threading,'Thread',Thread):
       expected=original_error(lambda:bg.BackgroundOptimizer(Runtime(snap),{},function=next(iter(program.scalar_entrypoints)),bridge=good['bridge']))
      run('constructor-bind-'+str(i)+'-'+str(len(rows)),2,expected,snap=snap,program=program,latest=program)
      owner=bare(program,last,snap);expected=original_error(lambda:owner._current_program(snap))
      h,_,_=run('current-'+str(i)+'-'+str(len(rows)),4,expected,snap=snap,program=program,latest=last)
      if expected is None:assert h[10]==int(owner._current_program(snap)is last and last is not program and (last.sha256,last.input_sha256)!=(program.sha256,program.input_sha256))
 targets=[None,False,0,'',bg.TARGET,[],{},[bg.TARGET]]
 objectives=[None,False,0,'x',[],{}]+[{'target':x}for x in targets]
 for i,obj in enumerate(objectives):
  owner=bare(base,last,snapshot(base));owner._runtime=Runtime()
  expected=original_error(lambda:owner.submit([],{},obj))
  run('objective-'+str(i),3,expected,opts={'candidates':[],'observations':{},'objective':obj})
 measured=[None,False,0,'x',[],{}, {'abstain':None},{'abstain':[]},{'abstain':{}},{'abstain':{'program_sha256':base.sha256}},{'abstain':{'program_sha256':last.sha256}},{'abstain':{'program_sha256':base.sha256.upper()}}]
 for i,obs in enumerate(measured):
  owner=bare(base,last,snapshot(base))
  with patch.object(bg,'PublicationCancellation',side_effect=Stop):expected=original_error(lambda:owner.submit([],obs,{'target':bg.TARGET}))
  run('incumbent-'+str(i),5,expected,opts={'candidates':[],'observations':obs,'objective':{'target':bg.TARGET}})
 for i in range(60):
  gen=rng.choice([0,1,2**64,10**200]);epoch=rng.choice([0,1,2**64,10**200])
  snap=snapshot(base,current=gen,epoch=epoch,closed=bool(i%5==0),current_kind=0 if i%4 else 3)
  jgen=gen if i%3 else gen+1;jepoch=epoch if i%7 else epoch+1
  owner=bare(base,last,snap);want=owner._same_snapshot(SimpleNamespace(generation=jgen,epoch=jepoch))
  h,_,_=run('same-snapshot-'+str(i),6,None,snap=snap,gen=jgen,epoch=jepoch)
  assert bool(h[11])==want,(i,h[11],want)
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
 try:
  gen=10**100000;epoch=gen+7
  snap=snapshot(base,current=gen,epoch=epoch)
  owner=bare(base,last,snap)
  for n in range(2):
   want=owner._same_snapshot(SimpleNamespace(generation=gen+n,epoch=epoch))
   h,_,_=run('wide-decimal-snapshot-'+str(n),6,None,snap=snap,gen=gen+n,epoch=epoch)
   assert bool(h[11])==want
 finally:sys.set_int_max_str_digits(prior)
 for i,wait in enumerate(vals[:10]+[False,True]):
  for j,cancel in enumerate([False,True,None,0,1,'x',[],{}]):
   owner=bare(base,last,snapshot(base));expected=original_error(lambda:owner.shutdown(wait=wait,cancel_pending=cancel))
   h,_,_=run('shutdown-'+str(i)+'-'+str(j),7,expected,opts={'wait':wait,'cancel_pending':cancel})
   if expected is None:assert h[4]==int(wait)and h[5]==int(cancel)
 owner=bare(base,last,snapshot(base))
 run('copy',8,original_error(lambda:copy.copy(owner)))
 run('deepcopy',8,original_error(lambda:copy.deepcopy(owner)))
 run('runtime-type',9,original_error(lambda:bg.BackgroundOptimizer(None,None,function=None,bridge=None,max_pending=False)))
 raw,_,_=frame(0,opts=good)
 guards=[]
 for at in [0,8,72,208,216,224,232,240,248]:
  b=bytearray(raw);struct.pack_into('<Q',b,at,10 if at==8 else NONE)
  rc,err,head,out=native(bytes(b));assert rc==4294967293 and out==b'\xdb'*512,(at,rc)
  guards.append({'offset':at,'rc':rc,'atomic':True})
 for at in [16,24,32,40,48,56,64]:
  b=bytearray(raw);struct.pack_into('<Q',b,at,NONE)
  rc,err,head,out=native(bytes(b));assert rc==4294967293 and out==b'\xdb'*512,(at,rc)
  guards.append({'offset':at,'rc':rc,'atomic':True})
 report.update(passed=True,total=len(rows),guards=guards,guard_count=len(guards),actual_capture_calls=cap.calls)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 print('BG_ADMISSION_QUALIFIED',len(rows),len(guards),flat.sha,flush=True)
if __name__=='__main__':main()
