"""Canonical subprocess exception identity and actual TimeoutExpired stdout alias."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,platform,struct,subprocess,traceback
from tools.qualify_hia_result_value_platform import Bound,Engine,Values as PriorValues,sweep,word,args_and_dict,periodic_gc,objects
from tools.qualify_hia_result_value_records import equivalent
from tools.qualify_hia_result_value_invocations import echo_field
from tools import qualify_hia_generation_lease_owner_bound as faults
from tools.qualify_hia_result_value_exceptions import frame
ZERO=(0,0,0)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def make_value(values,source):
 if type(source)in(list,tuple):
  children=[make_value(values,item)for item in source]
  result=values.lst(children)if type(source)is list else values.tuple(children)
  for child in children:values.drop(child)
  return result
 if type(source)is dict:
  result=values.keep(values.raw(4))
  for key,value in source.items():
   k=make_value(values,key);v=make_value(values,value)
   values.raw(10,a=result,b=k,c=v)
   values.drop(k);values.drop(v)
  return result
 return values.scalar(source)
class Values(PriorValues):
 def builtin(self,index):
  if index==73:return self.keep(self.raw(112,arg0=index))
  return self.keep(self.raw(110,arg0=index))if index>=71 else super().builtin(index)
 def field(self,obj,index,value=None,write=False,want=0):
  out=self.raw(111,a=obj,b=value if write else ZERO,arg0=index,arg1=int(write),want=want)
  assert word(out,88)==1 and word(out,96)==int(want==0)and word(out,80)==0,out[:128].hex()
  if want:return ZERO
  assert word(out,64)==1
  return self.keep(out)
 def timeout(self,cls,fields,args=None):
  if args is None:args=self.tuple(fields[:2]);owned=True
  else:owned=False
  namespace=self.keep(self.raw(4))
  for name,value in zip(('cmd','timeout','output','stderr'),fields):
   key=self.scalar(name);self.raw(10,a=namespace,b=key,c=value);self.drop(key)
  result=self.keep(self.raw(75,a=cls,b=args,c=namespace))
  self.drop(namespace)
  if owned:self.drop(args)
  return result
def run(owner,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 report=dict(passed=False,subprocess_exception_component_qualified=False,whole_public_api_qualified=False,
             dynamic_python_attribute_override_qualified=False,product=pin(owner.read_bytes()))
 groups=[];before=set(os.listdir('/proc/self/fd'))
 try:
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b));base=v.builtin(71);timeout=v.builtin(72);exception=v.builtin(22)
  for index,cls,py,direct in((71,base,subprocess.SubprocessError,exception),(72,timeout,subprocess.TimeoutExpired,base)):
   other=v.builtin(index);assert v.same(other,cls);v.drop(other)
   name=v.keep(v.raw(38,a=cls));assert v.python_value(name)==py.__name__;v.drop(name)
   mro=v.keep(v.raw(38,a=cls,arg0=2));one=v.scalar(1);actual=v.keep(v.raw(12,a=mro,b=one));assert v.same(actual,direct)
   for cap in(mro,one,actual):v.drop(cap)
   bad=bytearray(frame(101,arg0=index));bad[:8]=b'HIABVQ05';rc,reply=v.engine.call(bytes(bad));assert rc==0xfffffffd
  groups.append(dict(case='two-canonical-identities-and-real-subprocess-inheritance-old101-boundary'))
  print('SUBPROCESS_VALUE_PASS catalog',flush=True)
  from hepta.hia_background_optimizer import BackgroundOptimizationRejected
  cls=v.builtin(73);valueerror=v.builtin(24);label=v.keep(v.raw(38,a=cls))
  assert v.python_value(label)==BackgroundOptimizationRejected.__name__
  mro=v.keep(v.raw(38,a=cls,arg0=2));index=v.scalar(1);direct=v.keep(v.raw(12,a=mro,b=index))
  assert v.same(direct,valueerror)
  expected=BackgroundOptimizationRejected('E_HIA_BACKGROUND: invalid submission')
  message=v.scalar(expected.args[0]);args=v.tuple([message]);error=v.keep(v.raw(75,a=cls,b=args))
  assert v.isinst(error,valueerror)and not v.isinst(error,base)
  namespace,captured,name=args_and_dict(v,error);assert v.python_value(namespace)=={}and v.python_value(captured)==expected.args
  function=v.function(echo_field(1,2),env=error);argv=v.tuple([]);raised=v.invoke(function,argv,disposition=2)
  assert v.same(raised,error)
  for op,number in((110,73),(112,72),(112,74)):
   bad=bytearray(frame(op,arg0=number));bad[:8]=b'HIABVQ05';rc,reply=v.engine.call(bytes(bad));assert rc==0xfffffffd
  for cap in(cls,valueerror,label,mro,index,direct,message,args,error,namespace,captured,name,function,argv,raised):v.drop(cap)
  groups.append(dict(case='canonical-background-rejection-real-ValueError-base-args-and-native-raised-identity'))
  print('SUBPROCESS_VALUE_PASS background-rejection',flush=True)
  cases=[
   ('clang',3,None,None),
   (['clang','--version'],0.125,b'out\xff',b'err\0'),
   (b'clang',-1,'text\ud800\udc00',None),
   ({'cmd':1},True,[],{'raw':[1,2]}),
   (None,1<<100,b'',b''),
  ]
  for fields in cases:
   expected=subprocess.TimeoutExpired(fields[0],fields[1],output=fields[2],stderr=fields[3])
   caps=[make_value(v,x)for x in fields];error=v.timeout(timeout,caps)
   typ=v.keep(v.raw(36,a=error));assert v.same(typ,timeout)and v.isinst(error,base);v.drop(typ)
   for index,name in enumerate(('cmd','timeout','output','stderr','stdout')):
    cap=v.field(error,index);assert equivalent(v.python_value(cap),getattr(expected,name)),(name,fields,v.python_value(cap))
    assert v.same(cap,caps[2 if index==4 else index]);v.drop(cap)
   namespace,args,name=args_and_dict(v,error)
   assert equivalent(v.python_value(args),expected.args)
   assert list(v.python_value(namespace))==list(expected.__dict__)and equivalent(v.python_value(namespace),expected.__dict__)
   for cap in(namespace,args,name,error,*caps):v.drop(cap)
  groups.append(dict(case='actual-args-and-four-namespace-edges-preserve-arbitrary-values',cases=len(cases)))
  print('SUBPROCESS_VALUE_PASS fields',flush=True)
  initial=[v.scalar('clang'),v.scalar(3),v.lst([]),v.scalar(None)];error=v.timeout(timeout,initial)
  replacement=v.lst([v.scalar(71)]);none=v.field(error,4,replacement,True);assert v.python_value(none)is None;v.drop(none)
  output=v.field(error,2);stdout=v.field(error,4);assert v.same(output,replacement)and v.same(stdout,replacement)
  child=v.scalar(9);v.raw(16,a=replacement,b=child);assert v.python_value(output)==[71,9]
  namespace,args,name=args_and_dict(v,error);assert 'stdout'not in v.python_value(namespace)and list(v.python_value(namespace))==['cmd','timeout','output','stderr']
  key=v.scalar('output');v.raw(10,a=namespace,b=key,c=initial[2]);refreshed=v.field(error,4);assert v.same(refreshed,initial[2])
  for cap in(output,stdout,namespace,args,name,key,refreshed,replacement,child,error,*initial):v.drop(cap)
  groups.append(dict(case='stdout-setter-and-dict-output-mutation-share-one-real-edge'))
  print('SUBPROCESS_VALUE_PASS live-alias',flush=True)
  derived=v.cls('ActualTimeoutChild',[timeout]);fields=[v.scalar('c'),v.scalar(0),v.scalar(b'x'),v.scalar(b'y')];error=v.timeout(derived,fields)
  assert v.isinst(error,timeout)and v.isinst(error,base)
  actual=v.field(error,4);assert v.same(actual,fields[2]);v.drop(actual)
  cause=v.keep(v.raw(75,a=base,b=v.tuple([v.scalar('actual cause')])));r=v.raw(106,a=error,b=cause,arg0=0);none=v.keep(r);v.drop(none)
  retrieved=v.keep(v.raw(107,a=error,arg0=0));assert v.same(retrieved,cause);v.drop(retrieved)
  actual=v.field(error,4);assert v.same(actual,fields[2]);v.drop(actual)
  function=v.function(echo_field(1,2),env=error);argv=v.tuple([]);raised=v.invoke(function,argv,disposition=2);assert v.same(raised,error)
  for cap in(derived,error,cause,function,argv,raised,*fields):v.drop(cap)
  fakeclass=v.cls('TimeoutExpired',[]);fake=v.instance(fakeclass);v.field(fake,4,want=2)
  missing=v.keep(v.raw(75,a=timeout,b=v.tuple([])));v.field(missing,4,want=3)
  for cap in(fakeclass,fake,missing):v.drop(cap)
  groups.append(dict(case='real-subclass-cause-and-native-raised-identity-reject-same-name-impostor'))
  print('SUBPROCESS_VALUE_PASS class-cause-raise',flush=True)
  fields=[v.scalar('clang'),v.scalar(3),v.scalar(b'old'),v.scalar(None)];error=v.timeout(timeout,fields);fresh=v.scalar(b'new')
  count=word(v.raw(47),48)
  def denied():
   faults.deny_fixed_syscall(b.value,b.value+(owner.parent/'hia-generation-lease-values.core.bin').stat().st_size,318,errno.EIO)
   return v.raw(111,a=error,b=fresh,arg0=4,arg1=1,want=11)
  failed=faults.thread_result(denied);assert word(failed,88)==1 and word(failed,96)==0 and failed[24:48]==bytes(24)
  after=v.field(error,4);assert v.same(after,fields[2]);v.drop(after);assert word(v.raw(47),48)==count
  completed=v.field(error,4,fresh,True);v.drop(completed)
  after=v.field(error,2);assert v.same(after,fresh);v.drop(after)
  for cap in(error,fresh,*fields):v.drop(cap)
  groups.append(dict(case='actual-getrandom-EIO-precedes-stdout-mutation-and-publish',failure=failed[:128].hex()))
  print('SUBPROCESS_VALUE_PASS actual-failure',flush=True)
  for cap in list(v.held):v.drop(cap)
  probe=v.scalar(None);periodic_gc(v,probe);baseline=objects(v)
  timeout=v.builtin(72);fields=[v.scalar('self'),v.scalar(3),v.scalar(None),v.scalar(None)];cycle=v.timeout(timeout,fields)
  result=v.field(cycle,4,cycle,True);v.drop(result)
  for cap in(cycle,timeout,*fields):v.drop(cap)
  periodic_gc(v,probe);assert objects(v)==baseline,(objects(v),baseline)
  v.drop(probe);sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
  groups.append(dict(case='real-exception-output-self-cycle-is-collected-by-shared-native-GC'))
  print('SUBPROCESS_VALUE_PASS cyclic-custody',flush=True)
  report.update(passed=True,subprocess_exception_component_qualified=True,groups=groups,source=pin(Path(__file__).read_bytes()))
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
