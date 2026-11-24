import gdb, json, os, struct, hashlib, time, traceback
from pathlib import Path
from collections import Counter, deque
import _remote_debugging
cfg=json.loads(Path(config_file).read_text())
base=Path(cfg['layout_base'])
L=json.loads((base/'external-state-layout.json').read_text()); H=json.loads((base/'external-heap-types-layout.json').read_text()); F=json.loads((base/'frozen-row-owner-layout.json').read_text()); T=json.loads((base/'frozen-traceback-layout.json').read_text()); I=json.loads((base/'inline-layout.json').read_text())
J=json.loads(Path(cfg['frame_layout']).read_text())
expected_ids=cfg['ordered_ids']; selected=set(cfg['diagnostic_ordinals']); stop_after=cfg.get('stop_after',len(expected_ids))
step=0; world=0; interp=None; runtime=None; case_id=None; activewatch=None; phasewatch=None; eventwatch=None; itemwatch=None; namespace=0; initial_environment=None; unwinder=None
watch_trace=[]; failures=[]; progress=[]; gc_events=[]; captured={}; output_rows=0; natural_exit=None; stopped_early=False; completed=False; started=time.monotonic()
stream=Path(cfg['records']).open('x',encoding='utf-8')
class Memory:
 def __init__(self):
  self.pid=gdb.selected_inferior().pid;self.fd=os.open('/proc/'+str(self.pid)+'/mem',os.O_RDONLY);self.types={};self.objects={};self.counts=Counter();self.pages={}
 def close(self):os.close(self.fd)
 def read(self,a,n):
  if n>4096:
   raw=os.pread(self.fd,n,a)
   if len(raw)!=n:raise ValueError('short memory read '+hex(a)+' '+str(n))
   return raw
  pieces=[]
  while n:
   page=a&~4095;at=a-page;take=min(n,4096-at)
   raw=self.pages.get(page)
   if raw is None:
    raw=os.pread(self.fd,4096,page)
    if len(raw)!=4096:raise ValueError('short memory page '+hex(page))
    self.pages[page]=raw
   pieces.append(raw[at:at+take]);a+=take;n-=take
  return b''.join(pieces)
 def ptr(self,a):return int.from_bytes(self.read(a,8),'little')
 def num(self,a,n=4):return int.from_bytes(self.read(a,n),'little',signed=True)
 def text(self,a,cap=500):
  if not a:return ''
  n=self.ptr(a+F['length'])
  if not 0<=n<=cap:return ''
  return self.read(a+F['ascii_size'],n).decode('ascii','replace')
 def typename(self,a):
  if not a:return '<NULL>'
  tp=self.ptr(a+H['object_type'])
  if tp not in self.types:self.types[tp]=self.read(self.ptr(tp+H['type_name']),160).split(b'\0',1)[0].decode('ascii','replace')
  return self.types[tp]
 def description(self,a):
  if not a:return {'address':'0x0','type':'<NULL>'}
  ty=self.typename(a);v={'address':hex(a),'type':ty,'refcount_word':self.ptr(a),'gc_list':self.objects.get(a,(None,None))[1]}
  if ty=='str':v['text']=self.text(a)
  return v
 def keyslots(self,keys,values=0):
  if not keys:return {}
  count=self.ptr(keys+F['dk_nentries']);kind=self.read(keys+F['dk_kind'],1)[0]
  if count>30000 or kind>2:raise ValueError('dict key layout sanity')
  base=keys+F['dk_indices']+(1<<self.read(keys+F['dk_log2_index_bytes'],1)[0]);size=24 if kind==0 else 16
  raw=self.read(base,size*count);out={}
  for n in range(count):
   at=n*size+(8 if kind==0 else 0);key=int.from_bytes(raw[at:at+8],'little')
   slot=values+I['values']+n*8 if values else base+at+8
   value=self.ptr(slot) if values else int.from_bytes(raw[at+8:at+16],'little')
   if key and value:
    name=self.text(key,500) if self.typename(key)=='str' else '@'+hex(key)
    out[name]=(value,slot,key)
  return out
 def dictslots(self,a):return self.keyslots(self.ptr(a+F['ma_keys']),self.ptr(a+I['ma_values']))
 def attrs(self,a):
  tp=self.ptr(a+8);flags=self.ptr(tp+I['tp_flags'])
  if flags&I['managed_dict_flag']:
   md=self.ptr(a-24)
   if md:return self.dictslots(md)
   if flags&I['inline_values_flag']:
    values=a+self.ptr(tp+I['tp_basicsize'])
    if not self.read(values+I['values_valid'],1)[0]:return {}
    return self.keyslots(self.ptr(tp+I['ht_cached_keys']),values)
   return {}
  offset=self.num(tp+I['tp_dictoffset'],8)
  if offset>0 and offset<100000:
   md=self.ptr(a+offset)
   if md:return self.dictslots(md)
  return {}
 def frame(self,ob):
  fr=self.ptr(ob+F['f_frame']);code=self.ptr(fr+F['f_executable'])&~3
  n=self.num(code+F['co_nlocalsplus']);names=self.ptr(code+F['co_localsplusnames'])
  if not 0<=n<=500:raise ValueError('frame local count sanity')
  slots={}
  for k in range(n):
   name=self.text(self.ptr(names+F['ob_item']+8*k));slot=fr+F['localsplus']+8*k;v=self.ptr(slot)&~3
   if v:slots[name]=(v,slot)
  return self.text(self.ptr(code+F['co_qualname'])),slots,fr
 def gc(self):
  for off in H['lists']:
   head=interp+off;at=self.ptr(head)&~3;n=0;seen=set();cap=min(2000000,max(10000,self.num(interp+L['heap'][0],8)+8192))
   while at!=head:
    if not at or n>cap or at in seen:raise ValueError('GC list shape sanity off='+str(off)+' head='+hex(head)+' at='+hex(at)+' n='+str(n)+' repeat='+str(at in seen)+' heap='+str(self.num(interp+L['heap'][0],8))+' collecting='+str(self.num(interp+7600)))
    seen.add(at)
    ob=at+H['gc_head'];name=self.typename(ob);self.objects[ob]=(name,off);self.counts[name]+=1
    at=self.ptr(at)&~3;n+=1
 def weaklabels(self,w):
  attrs=self.attrs(w);refs=attrs['refs'][0];out={}
  for tag,(ref,slot,key) in self.dictslots(refs).items():
   if self.typename(ref) not in ('weakref','weakref.ReferenceType'):raise ValueError('World.refs expected weakrefs')
   target=self.ptr(ref+I['weakref_target'])
   out[tag]=None if self.typename(target)=='NoneType' else target
  return out
 def phase(self):return self.text(self.attrs(world)['phase'][0]) if world else None
 def edges(self,a,name):
  out=[]
  if name in ('dict','TrackedMap'):
   for k,(v,slot,key) in self.dictslots(a).items():out.append(('dict['+k+']',v));out.append(('dict.key',key))
  elif name in ('list','tuple'):
   n=self.ptr(a+16)
   if n>300000:raise ValueError('sequence extent sanity')
   start=self.ptr(a+24) if name=='list' else a+32
   raw=self.read(start,n*8)
   out.extend(('item['+str(i)+']',int.from_bytes(raw[i*8:i*8+8],'little')) for i in range(n))
  elif name=='frame':
   qual,slots,_=self.frame(a);out.extend(('local '+qual+'.'+k,v) for k,(v,slot) in slots.items())
  elif name=='traceback':out.extend((('tb_frame',self.ptr(a+T['tb_frame'])),('tb_next',self.ptr(a+T['tb_next']))))
  elif name in ('TypeError','AttributeError','ValueError','RuntimeError','MemoryError','KeyboardInterrupt','SystemExit','KeyError'):
   out.extend((k,self.ptr(a+T[k])) for k in ('traceback','context','cause'))
  elif name=='method':out.extend((('im_func',self.ptr(a+16)),('im_self',self.ptr(a+24))))
  elif name=='cell':out.append(('ob_ref',self.ptr(a+16)))
  elif name=='module':out.append(('md_dict',self.ptr(a+16)))
  elif name=='function':out.extend((('func_globals',self.ptr(a+16)),('func_closure',self.ptr(a+72))))
  elif name.endswith('.Session'):
   names=('module','function','binding','frame_type','unknown','admission','frame','record','series','ambient','ambient_exit','series_exit','pending','pending_exit','context_token','sql_attempt','retained_frame','iterator_custody')
   out.extend((k,self.ptr(a+16+8*i)) for i,k in enumerate(names))
  elif name.endswith('.CursorIteration'):out.extend((('session',self.ptr(a+16)),('iterator',self.ptr(a+24))))
  if name not in ('frame','traceback','dict','list','tuple','function','module','type','cell','weakref','weakref.ReferenceType'):
   out.extend(('attr '+k,v) for k,(v,slot,key) in self.attrs(a).items())
  return [(k,v) for k,v in out if v]

class Reader(Memory):
 def text(self,a,cap=1000000):
  if not a:return ''
  n=self.ptr(a+16)
  if n>cap:raise ValueError('unicode extent exceeds cap')
  state=self.num(a+32);kind=(state>>2)&7;compact=bool(state&32);ascii_only=bool(state&64)
  if not compact or kind not in (1,2,4):raise ValueError('unsupported unicode layout')
  at=a+(40 if ascii_only else 56)
  return self.read(at,n*kind).decode({1:'latin1',2:'utf-16-le',4:'utf-32-le'}[kind],'surrogatepass')
 def value(self,a,depth=0):
  if not a:raise ValueError('NULL value')
  if depth>100:raise ValueError('JSON nesting cap')
  name=self.typename(a)
  if name=='NoneType':return None
  if name=='str':return self.text(a)
  if name in ('int','bool'):
   tag=self.ptr(a+16);n=tag>>3
   if n>256:raise ValueError('integer extent cap')
   raw=self.read(a+24,4*n);v=sum(int.from_bytes(raw[i*4:i*4+4],'little')<<(30*i) for i in range(n))
   if tag&3==2:v=-v
   return bool(v) if name=='bool' else v
  if name=='float':return struct.unpack('<d',self.read(a+16,8))[0]
  if name in ('dict','TrackedMap'):
   return {self.text(k):self.value(v,depth+1) for _,(v,slot,k) in self.dictslots(a).items()}
  if name in ('list','tuple'):
   n=self.ptr(a+16)
   if n>100000:raise ValueError('JSON sequence extent cap')
   at=self.ptr(a+24) if name=='list' else a+32
   raw=self.read(at,n*8)
   return [self.value(int.from_bytes(raw[i*8:i*8+8],'little'),depth+1) for i in range(n)]
  raise ValueError('non-JSON value '+name)
 def iframe(self,fr):
  code=self.ptr(fr+F['f_executable'])&~3
  if not code or self.typename(code)!='code':return None,{}
  n=self.num(code+F['co_nlocalsplus']);names=self.ptr(code+F['co_localsplusnames'])
  if not 0<=n<=500:raise ValueError('interpreter frame local extent')
  slots={}
  for k in range(n):
   name=self.text(self.ptr(names+F['ob_item']+8*k));slot=fr+F['localsplus']+8*k
   slots[name]=(self.ptr(slot)&~3,slot)
  return self.text(self.ptr(code+F['co_qualname'])),slots
 def findframe(self,name):
  thread=self.ptr(interp+J['interp_threads_head'])
  if self.ptr(thread+8):raise ValueError('gate requires one Python thread')
  fr=self.ptr(thread+J['tstate_current_frame']);seen=set()
  while fr and fr not in seen and len(seen)<200:
   seen.add(fr);qual,slots=self.iframe(fr)
   if qual==name:return slots,fr
   fr=self.ptr(fr+J['frame_previous'])
  raise ValueError('Python frame absent: '+name)
def failure(where,error):
 if len(failures)<16:failures.append({'where':where,'step':step,'id':case_id,'error':str(error),'debugger_traceback':traceback.format_exc()})
def canonical(value):return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'))
def sample_consumer(m):
 attrs=m.attrs(world);case=m.value(attrs['case'][0])
 if case['id']!=case_id:raise ValueError('active World differs from declared case')
 slots,fr=m.findframe('World.observe')
 if slots['self'][0]!=world:raise ValueError('World.observe identity mismatch')
 for name in ('result','args','kwargs','subject'):
  if m.typename(slots[name][0])!='NoneType':raise ValueError('consumer local still owns '+name)
 refs=m.weaklabels(world);alive={k:v for k,v in refs.items() if v}
 return {
  'case_id':case_id,'ordinal':step,
  'handler':{k:case[k] for k in ('id','template','method','outer_exception')},
  'consumer_snapshot':{'events':m.value(attrs['events'][0]),'alive':list(alive),'outcome':m.value(slots['outcome'][0])},
  'fake_sql_effects':m.value(attrs['effects'][0]),
  'sql_prefix_length':m.value(attrs['sql_at'][0]),
  'complete_request_packets':m.value(attrs['requests'][0]),
  'fault_hits':m.value(attrs['fault_hits'][0]),
  'unraisable':m.value(attrs['unraisable'][0]),
  'provider_ownership':{k:{'type':m.typename(v),'refcount_word':m.ptr(v)} for k,v in alive.items()},
  'boundary':'original consumer_release.end appended; before original copy_json consumer snapshot',
  'target_observation_allocations':0}
def sample_seal(m):
 attrs=m.attrs(world);refs=m.weaklabels(world);alive={k:v for k,v in refs.items() if v}
 events=m.value(attrs['events'][0])
 return {'alive':list(alive),'provider_ownership':{k:{'type':m.typename(v),'refcount_word':m.ptr(v)} for k,v in alive.items()},
         'events_sha256':hashlib.sha256(canonical(events).encode()).hexdigest(),'event_count':len(events),
         'boundary':'original phase assignment case-sealed; before original final record copy_json'}
class Watch(gdb.Breakpoint):
 def __init__(self,address,kind):
  self.kind=kind
  super().__init__('*(unsigned long long*)'+hex(address),type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_WRITE,internal=True)
  self.silent=True
 def stop(self):
  global world,phasewatch,eventwatch
  try:
   m=Reader()
   try:
    if step<=2:watch_trace.append({'kind':self.kind,'phase':m.phase() if world else None})
    if self.kind=='active':
     ns=m.dictslots(namespace);world=ns['ACTIVE'][0];attrs=m.attrs(world)
     if m.value(attrs['case'][0])['id']!=case_id:raise ValueError('ACTIVE assignment case mismatch')
     if phasewatch is not None or eventwatch is not None:raise ValueError('previous case watches not retired')
     phasewatch=Watch(attrs['phase'][1],'phase')
     eventwatch=Watch(attrs['events'][0]+16,'events');eventwatch.enabled=False
    elif self.kind=='phase':
     phase=m.phase()
     if phase=='consumer-release':eventwatch.enabled=True
     elif phase=='case-sealed':
      if 'consumer' not in captured:raise ValueError('case sealed without consumer boundary')
      captured['seal_diagnostic']=sample_seal(m)
    elif self.kind=='events':
     attrs=m.attrs(world);events=attrs['events'][0];n=m.ptr(events+16)
     if n:
      event_slots,_=m.findframe('World.event')
      name=m.value(event_slots['name'][0])
      if step<=2:watch_trace.append({'event_name':name,'length':n,'events_pointer':hex(events),'items_pointer':hex(m.ptr(events+24))})
      if name=='observer.consumer_release.end':
       self.enabled=False
       slot=m.ptr(events+24)+(n-1)*8;last=m.ptr(slot)
       ready=False
       try:ready=m.typename(last)=='dict' and m.value(m.dictslots(last)['event'][0])==name
       except (OSError,ValueError,KeyError,OverflowError):pass
       if step<=2:watch_trace.append({'slot':hex(slot),'last':hex(last),'ready':ready})
       if ready:
        if 'consumer' in captured:raise ValueError('duplicate consumer boundary')
        captured['consumer']=sample_consumer(m)
       else:
        global itemwatch
        cframes=[];frame=gdb.newest_frame();selected_frame=None;previous_frame=None
        while frame is not None and len(cframes)<10:
         cname=frame.name();cframes.append(cname)
         if cname=='_PyEval_EvalFrameDefault':
          selected_frame=previous_frame;break
         if cname in ('_PyList_AppendTakeRefListResize','list_append','list_append_impl','PyList_Append'):
          selected_frame=frame;break
         previous_frame=frame;frame=frame.older()
        if step<=2:watch_trace.append({'append_c_frames':cframes})
        if selected_frame is None:raise ValueError('no completed append boundary: '+str(cframes))
        itemwatch=AppendReturn(selected_frame)
    elif self.kind=='item':
     self.enabled=False
     if 'consumer' in captured:raise ValueError('duplicate consumer boundary')
     captured['consumer']=sample_consumer(m)
   finally:m.close()
  except Exception as e:failure('watch-'+self.kind,e);return True
  return False
class AppendReturn(gdb.FinishBreakpoint):
 def __init__(self,frame):super().__init__(frame,internal=True)
 def stop(self):
  try:
   m=Reader()
   try:
    global itemwatch
    if 'consumer' in captured:raise ValueError('duplicate append-return boundary')
    slots,_=m.findframe('World.event')
    if m.value(slots['name'][0])!='observer.consumer_release.end':raise ValueError('append return escaped original event')
    attrs=m.attrs(world);events=attrs['events'][0];n=m.ptr(events+16)
    slot=m.ptr(events+24)+(n-1)*8;last=m.ptr(slot);ready=False
    try:ready=m.typename(last)=='dict' and m.value(m.dictslots(last)['event'][0])=='observer.consumer_release.end'
    except (OSError,ValueError,KeyError,OverflowError):pass
    if step<=2:watch_trace.append({'append_return_slot':hex(slot),'last':hex(last),'ready':ready})
    if ready:captured['consumer']=sample_consumer(m)
    else:itemwatch=Watch(slot,'item')
   finally:m.close()
  except Exception as e:failure('append-return',e);return True
  return False
class GCHit(gdb.Breakpoint):
 def __init__(self,end=False):
  self.end=end
  super().__init__('-probe-stap python:gc__'+('done' if end else 'start'),internal=True)
  self.enabled=False
 def stop(self):
  global unwinder
  try:
   if world and step in selected:
    m=Reader()
    try:
     if unwinder is None:unwinder=_remote_debugging.RemoteUnwinder(m.pid)
     stack=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.funcname} for t in unwinder.get_stack_trace() for f in t.frame_info][:16]
     gc_events.append({'ordinal':step,'id':case_id,'boundary':'done' if self.end else 'start','phase':m.phase(),'alive':[k for k,v in m.weaklabels(world).items() if v],'stack':stack})
    finally:m.close()
  except Exception as e:failure('GC probe',e);return True
  return False
class WriteHit(gdb.Breakpoint):
 def __init__(self):super().__init__('write@plt',internal=True)
 def stop(self):
  global runtime,interp,namespace,activewatch,phasewatch,eventwatch,itemwatch,initial_environment,step,case_id,world,captured,output_rows,stopped_early,completed
  try:
   n=int(gdb.parse_and_eval('$rdx'))
   if not 28<n<240:return False
   inf=gdb.selected_inferior();raw=bytes(inf.read_memory(int(gdb.parse_and_eval('$rsi')),n))
   if not raw.startswith(b'{"event":') or not raw.endswith(b'\n'):return False
   row=json.loads(raw)
   if row.get('event') not in ('started','stopped') or 'id' not in row:return False
   if runtime is None:
    runtime=int(gdb.parse_and_eval('(unsigned long)&_PyRuntime'))
    interp=int.from_bytes(inf.read_memory(runtime+L['interpreter'],8),'little')
    initial_environment=dict(x.decode().split('=',1) for x in Path('/proc/'+str(inf.pid)+'/environ').read_bytes().split(b'\0') if x)
    if initial_environment!=cfg['expected_environment']:raise ValueError('inferior initial environment differs')
    m=Reader()
    try:
     slots,_=m.findframe('observe_all');namespace=slots['namespace'][0]
     if m.typename(namespace)=='cell':namespace=m.ptr(namespace+16)
     if m.typename(namespace)!='dict':raise ValueError('observer namespace is not a dict')
     activewatch=Watch(m.dictslots(namespace)['ACTIVE'][1],'active')
    finally:m.close()
   if row['event']=='started':
    step+=1;case_id=row['id'];world=0;captured={}
    if case_id!=expected_ids[step-1]:raise ValueError('ordered case differs')
    gcp.enabled=step in selected;gce.enabled=step in selected
   else:
    if row['id']!=case_id or set(captured)!={'consumer','seal_diagnostic'}:raise ValueError('incomplete case boundary coverage')
    stream.write(canonical({'consumer':captured['consumer'],'seal_diagnostic':captured['seal_diagnostic']})+'\n');stream.flush();output_rows+=1
    for bp in (phasewatch,eventwatch,itemwatch):
     if bp is not None and bp.is_valid():bp.delete()
    phasewatch=None;eventwatch=None;itemwatch=None
    if step==len(expected_ids):
     completed=True;activewatch.enabled=False;gcp.enabled=False;gce.enabled=False;self.enabled=False
    elif step==stop_after:
     stopped_early=True;activewatch.enabled=False;gcp.enabled=False;gce.enabled=False;self.enabled=False
   progress.append({'ordinal':step,'event':row['event'],'id':case_id})
   if step%100==0 and row['event']=='stopped':Path(cfg['report']+'.checkpoint').write_text(canonical({'phase':'RUNNING','cases':output_rows,'elapsed_seconds':time.monotonic()-started,'failures':failures}))
   return stopped_early or bool(failures)
  except Exception as e:failure('progress',e);return True
def exited(event):
 global natural_exit
 natural_exit=getattr(event,'exit_code',None)
gdb.events.exited.connect(exited)
gdb.execute('set auto-solib-add off');gdb.execute('set sysroot /unable-to-load-local-images')
gdb.execute('set pagination off');gdb.execute('set print thread-events off');gdb.execute('set disable-randomization off');gdb.execute('set startup-with-shell off');gdb.execute('set breakpoint pending on');gdb.execute('set confirm off')
gdb.execute('unset environment',to_string=True)
for key,value in cfg['expected_environment'].items():gdb.execute('set environment '+key+'='+value,to_string=True)
gcp=GCHit();gce=GCHit(True);wp=WriteHit()
try:gdb.execute('run')
except Exception as e:failure('gdb run',e)
if gdb.selected_inferior().pid:gdb.execute('kill')
stream.close()
Path(cfg['report']).write_text(canonical({
 'schema':'hepta.slot-external-consumer-lifetime.v1',
 'scope':'separate non-allocating external observation; original observer/cases/product/GC policy unchanged',
 'watch_trace':watch_trace,'failures':failures,'progress':progress,'cases':output_rows,'expected_cases':len(expected_ids),
 'completed':completed,'stopped_early':stopped_early,'natural_inferior_exit_code':natural_exit,
 'initial_environment':initial_environment,'gc_events_selected_cases':gc_events,
 'elapsed_seconds':time.monotonic()-started,
 'read_only_target_memory':True,'target_python_calls':0,'target_allocations_by_probe':0,
 'status':'RECORDED' if not failures and completed and natural_exit==0 else 'PARTIAL_DIAGNOSTIC' if not failures and stopped_early else 'HOLD'}))
