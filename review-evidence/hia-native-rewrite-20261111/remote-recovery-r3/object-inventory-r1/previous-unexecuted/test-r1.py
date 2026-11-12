"""Full original ELF64/62 inventory oracle and actual native ELF producer join.
Hand-built malformed ELF values are test inputs only. Neither symbol inspection
nor object construction is delegated to Python during the production calls.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,ctypes,importlib.util,json,resource,signal,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
GROW=0xfffffffe
MAX=(1<<64)-1
PIN_HELPER="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
PIN_OWNER="5b8807b7eaee30a04c12fe2d96a5c457abb0a6f2517804e6b001fbbfc32d16ce"
PINS={"object_symbols.py":"aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f",
 "object_structure.py":"4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8",
 "hia_program_native.py":"bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
 "hia_machine_elf.py":"c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"}
IMPORTS=("abort","calloc","malloc","free","memset","memcpy","memmove")
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
COMMAND=magic("HIAMIC01");EVENT=magic("HIAMIE01")
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def load(name,path,expected=None):
 raw=Path(path).read_bytes()
 if expected:assert digest(raw)==expected
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 exec(compile(raw,str(path),"exec"),m.__dict__);return m
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def modify(raw,at,n,value):
 result=bytearray(raw);result[at:at+n]=int(value).to_bytes(n,"little");return bytes(result)
def symbol(name=b"f",binding=1,kind=2,section=1,value=0,size=1,other=0,**kw):
 return dict(name=name,binding=binding,kind=kind,section=section,value=value,size=size,other=other,**kw)
def fixture(tables=None,text=b"\xc3",extra_sections=0):
 """Only a test fixture constructor; emits deliberately unconstrained ELF fields."""
 if tables is None:tables=[[symbol()]]
 names=bytearray(b"\0");encoded=[];name_offsets=[]
 for rows in tables:
  table=[b"\0"*24];offsets=[]
  for row in rows:
   name=row["name"];offset=0
   if name is not None:offset=len(names);names.extend(name);names.append(0)
   offsets.append(offset);offset=row.get("name_off",offset)
   table.append(struct.pack("<IBBHQQ",offset,(row["binding"]<<4)|row["kind"],
       row["other"],row["section"],row["value"],row["size"]))
  encoded.append(b"".join(table));name_offsets.append(offsets)
 raw=bytearray(64);text_at=len(raw);raw.extend(text);names_at=len(raw);raw.extend(names)
 raw.extend(b"\0"*((-len(raw))&7));sym_at=[]
 for table in encoded:
  sym_at.append(len(raw));raw.extend(table)
 section_at=(len(raw)+7)&~7;raw.extend(b"\0"*(section_at-len(raw)))
 section_count=3+len(tables)+extra_sections
 sections=[(0,0,0,0,0,0,0,0,0,0),(0,1,6,0,text_at,len(text),0,0,1,0),
           (0,3,0,0,names_at,len(names),0,0,1,0)]
 sections.extend((0,2,0,0,at,len(table),2,0,8,24) for at,table in zip(sym_at,encoded))
 sections.extend((0,8,0,0,MAX,MAX,0,0,1,0) for _ in range(extra_sections))
 for sec in sections:raw.extend(struct.pack("<IIQQQQIIQQ",*sec))
 ident=b"\x7fELF\x02\x01\x01"+b"\0"*9
 raw[:64]=struct.pack("<16sHHIQQQIHHHHHH",ident,1,62,1,0,0,section_at,0,64,0,0,64,section_count,0)
 return bytes(raw),dict(text=text_at,names=names_at,names_n=len(names),sym=sym_at,
     sections=section_at,count=section_count,offsets=name_offsets)
def command(data,exports,lease=31,request=1,expected_lease=43):
 assert type(exports) in(list,tuple) and all(type(name) is str for name in exports)
 names=[name.encode("utf-8","surrogatepass") for name in exports]
 base=128+len(names)*16;rows=[];pool=bytearray()
 for name in names:rows.append((base+len(pool),len(name)));pool.extend(name)
 return (struct.pack("<16Q",COMMAND,1,lease,request,expected_lease,len(data),len(names),128,
      base,len(pool),base+len(pool),0,0,0,0,0)+
      b"".join(struct.pack("<2Q",*row) for row in rows)+pool)

class Oracle:
 def __init__(self,read,root,out):
  package=types.ModuleType("inventory_original");package.__path__=[];sys.modules[package.__name__]=package
  self.modules={}
  for name in("object_structure","object_symbols","hia_machine_elf"):
   raw=read(root/"reference"/(name+".py"),PINS[name+".py"])
   module=types.ModuleType(package.__name__+"."+name);module.__file__=str(root/"reference"/(name+".py"))
   module.__package__=package.__name__;sys.modules[module.__name__]=module
   exec(compile(raw,module.__file__,"exec"),module.__dict__);self.modules[name]=module
  raw=read(root/"reference/hia_program_native.py",PINS["hia_program_native.py"])
  tree=ast.parse(raw);wanted={"HIAProgramNativeRejected","_reject","_inspect_object"}
  nodes=[n for n in tree.body if getattr(n,"name",None) in wanted or
      isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="IMPORTS" for t in n.targets)]
  assert len(nodes)==4 and {n.name for n in nodes if isinstance(n,(ast.FunctionDef,ast.ClassDef))}==wanted
  self.backend=types.ModuleType("inventory_backend_original")
  self.backend.inspect_object_symbols=self.modules["object_symbols"].inspect_object_symbols
  exec(compile(ast.Module(body=nodes,type_ignores=[]),str(root/"reference/hia_program_native.py"),"exec"),self.backend.__dict__)
  save(out/"oracle-extraction.json",dict(full_structure_and_symbols_source_unchanged=True,
       original_backend_AST_nodes_unchanged=sorted(wanted|{"IMPORTS"}),pins=PINS,
       extracted_AST=ast.unparse(ast.Module(body=nodes,type_ignores=[]))))
 def expect(self,data,exports):
  try:return dict(value=self.backend._inspect_object(data,exports),error=None)
  except (self.backend.HIAProgramNativeRejected,self.modules["object_symbols"].ObjectSymbolsRejected) as error:
   return dict(value=None,error=dict(class_name=type(error).__name__,text=str(error)))
 def block(self):
  def forbidden(*args,**kwargs):raise AssertionError("original semantic owner called during native execution")
  saved=[]
  for owner,name in((self.backend,"_inspect_object"),(self.backend,"inspect_object_symbols"),
      (self.modules["object_symbols"],"inspect_object_symbols"),(self.modules["object_structure"],"qualified_object"),
      (self.modules["hia_machine_elf"],"write_elf_object")):
   saved.append((owner,name,getattr(owner,name)));setattr(owner,name,forbidden)
  return saved
 def restore(self,saved):
  for owner,name,value in saved:setattr(owner,name,value)

class Suite:
 def __init__(self,args):
  self.a=args;self.root=Path(__file__).resolve().parents[1];self.out=args.out;self.cases=[];self.calls={"inventory":0,"elf-producer":0}
  self.controls=0;self.joined=0;self.pins={};self.closed=False;self.mappings={}
  self.pin(__file__);self.pin(self.root/"tools/hia_elf_object_inventory.py",PIN_OWNER)
  self.F=load("object_inventory_evidence",self.root/"tests/function_frame_test_reference.py",PIN_HELPER)
  self.pin(self.root/"tests/function_frame_test_reference.py",PIN_HELPER)
  (self.out/"full-CAS").mkdir();self.evidence=self.F.Evidence(self.out/"full-CAS");self.buffers=self.F.Buffers()
  self.oracle=Oracle(self.pin,self.root,self.out)
  loader_path=args.reference/"hepta/hia_json_preflight_native.py";raw=self.pin(loader_path)
  loader=types.ModuleType("inventory_flat_loader");loader.__file__=str(loader_path)
  exec(compile(raw,str(loader_path),"exec"),loader.__dict__)
  for name,path in(("inventory",args.inventory),("elf-producer",args.producer)):
   m=json.loads(self.pin(path));assert m["component"]==name
   assert m["schema"]=="hepta.hia.elf-object-inventory-development.v1"
   assert m["status"]=="BUILT_ONLY" and m["compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
   for typ in("source","image"):assert len(self.pin(m[typ+"_path"],m[typ+"_sha256"]))==m[typ+"_bytes"]
   r=m["compile_receipt"];assert r["input_sha256"]==m["source_sha256"] and r["produced_sha256"]==m["image_sha256"]
   assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
   image=self.pin(m["image_path"]);self.mappings[name]=loader.NativeHiaJsonImage(image,expected_sha256=digest(image))
 def pin(self,path,expected=None):
  path=Path(path).absolute();info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
  path=path.resolve();raw=path.read_bytes()
  if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
  if path in self.pins:assert self.pins[path][0]==raw
  else:
   self.pins[path]=(raw,stat.S_IMODE(info.st_mode))
   dst=self.out/"sources"/str(len(self.pins))/path.name;dst.parent.mkdir(parents=True);dst.write_bytes(raw);dst.chmod(stat.S_IMODE(info.st_mode))
  return raw
 def entry(self,label,role,buffers):
  before=[self.evidence.memory(b,label+"-"+str(i)) for i,b in enumerate(buffers)]
  number=sum(self.calls.values());self.calls[role]+=1
  row=dict(number=number,label=label,role=role,status="ENTERING",before=before,
      sizes=[b["size"] for b in buffers],readonly=[b["readonly"] for b in buffers])
  self.evidence.entry(row);start=time.monotonic_ns()
  a,r,w=buffers
  result=int(self.mappings[role]._entry(a["address"],a["size"],r["address"],r["size"],w["address"],w["size"]))
  for b in buffers:self.buffers.check(b)
  after=[self.evidence.memory(b,label+"-"+str(i)) for i,b in enumerate(buffers)]
  assert before[0]["sha256"]==after[0]["sha256"] and before[1]["sha256"]==after[1]["sha256"]
  event=struct.unpack("<16Q",ctypes.string_at(w["address"],128)) if w["size"]>=4096 else None
  self.evidence.entry(dict(row,status="RETURNED",returned=result,after=after,event=event,
      elapsed_ns=time.monotonic_ns()-start,readonly_bytes_equal=True,all_canaries_intact=True))
  return result,event
 def run(self,label,data,cmd,role="inventory",capacity=4096,grow=True,fill=0xa5):
  a=r=w=None;events=[];saved=None
  try:
   a=self.buffers.allocate(len(data),data,True);r=self.buffers.allocate(len(cmd),cmd,True)
   w=self.buffers.allocate(capacity,bytes([fill])*capacity)
   saved=self.oracle.block()
   for _ in range(128):
    ret,event=self.entry(label,role,(a,r,w));events.append(dict(returned=ret,event=event))
    if ret==GROW and grow:
     assert event[0]==(EVENT if role=="inventory" else magic("HIAELE01")) and event[1:3]==(1,1)
     needed=event[8] if role=="inventory" else event[6]
     assert needed>w["size"] and needed<=1<<30
     previous=w;w=None;self.buffers.close(previous);w=self.buffers.allocate(needed,bytes([fill])*needed)
     continue
    raw=ctypes.string_at(w["address"],w["size"])
    return dict(returned=ret,event=event,workspace=raw,events=events)
   raise AssertionError(("development GROW watchdog",label,events))
  finally:
   if saved is not None:self.oracle.restore(saved)
   for b in(w,r,a):self.buffers.close(b)
 def check(self,label,data,exports=("f",),capacity=4096,kind="ORIGINAL_ELF_ORACLE",want=None):
  expected=self.oracle.expect(data,exports)
  if want is not None:
   assert expected["error"] is not None and expected["error"]["text"]==want,(label,expected,want)
  start=dict(self.calls);cmd=command(data,exports,request=len(self.cases)+1)
  actual=self.run(label,data,cmd,capacity=capacity);event=actual["event"]
  assert actual["returned"]==128 and event[0]==EVENT and event[1]==1
  assert event[3:6]==(31,len(self.cases)+1,43) and event[15]==0
  at,n=event[9:11];assert at<=len(actual["workspace"]) and 0<n<=len(actual["workspace"])-at
  payload=actual["workspace"][at:at+n]
  if expected["error"] is None:
   assert event[2]==0 and event[6:8]==(0,0) and event[14]==5
   wire=json.dumps(expected["value"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
   assert payload==wire,(label,payload,wire)
   assert event[11:13]==(len(expected["value"]["defined"]),len(expected["value"]["undefined"]))
  else:
   domain=2 if expected["error"]["class_name"]=="HIAProgramNativeRejected" else 1
   assert event[2]==2 and event[6]==domain and 1<=event[7]<=17
   assert payload.decode("ascii")==expected["error"]["text"],(label,payload,expected)
  row=dict(label=label,status="PASS",kind=kind,object=self.evidence.raw(data),
      expected_command=self.evidence.raw(cmd),expected=expected,
      result=self.evidence.raw(payload),event=event,events=actual["events"],
      actual_entries={k:self.calls[k]-start[k] for k in self.calls},
      original_error_class_and_complete_text_equal=True,complete_sorted_inventory_equal=expected["error"] is None)
  self.cases.append(row);self.evidence.case(row)
  save(self.out/"cases"/(str(len(self.cases)).zfill(4)+".json"),row)
  return row
 def bad(self,label,data,cmd,capacity=4096):
  start=dict(self.calls);actual=self.run(label,data,cmd,capacity=capacity,grow=False)
  assert actual["returned"]==BAD
  if capacity>=4096:assert actual["event"][0:3]==(EVENT,1,3) and actual["event"][15]!=0
  else:assert actual["workspace"]==b"\xa5"*capacity
  row=dict(label=label,status="PASS",kind="PRIVATE_ABI_BAD",object=self.evidence.raw(data),
      expected_command=self.evidence.raw(cmd),event=actual["event"],events=actual["events"],
      actual_entries={k:self.calls[k]-start[k] for k in self.calls},
      pure_stateless_recompute=True,persistent_poison_claim=False)
  self.controls+=1;self.cases.append(row);self.evidence.case(row)
  save(self.out/"cases"/(str(len(self.cases)).zfill(4)+".json"),row)
 def finish(self):
  if self.closed:return
  self.closed=True;errors=[];custody={}
  try:custody=self.evidence.finish()
  except BaseException as error:errors.append(error)
  for m in self.mappings.values():
   try:m._mapping.close()
   except BaseException as error:errors.append(error)
  rows=[]
  for p,(raw,mode) in self.pins.items():
   try:rows.append(dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=mode,same=p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode))
   except BaseException as error:rows.append(dict(path=str(p),same=False,error=repr(error)))
  save(self.out/"source-before-after.json",rows)
  if not all(row["same"] for row in rows):errors.append(AssertionError("source changed"))
  if errors:
   for error in errors[1:]:errors[0].add_note(repr(error))
   raise errors[0]
  return dict(files=len(rows),all_bytes_and_modes_equal=True,full_CAS=custody)

def corpus(group,variant=0):
 raw,at=fixture();sec=at["sections"];sym=at["sym"][0]+24
 cases=[]
 def add(label,data=raw,exports=("f",)):cases.append((label,data,exports))
 if group=="headers":
  for n in range(65):add("prefix-"+str(n),raw[:n])
  for label,off,n,value in(("magic",0,4,0),("class",4,1,1),("endian",5,1,2),("type",16,2,2),
      ("machine",18,2,63),("ehsize",52,2,63),("shoff",40,8,0),("shentsize",58,2,0),("count0",60,2,0),("count4097",60,2,4097)):
   add(label,modify(raw,off,n,value))
  for label,off,n,value in(("EI_VERSION-ignored",6,1,0),("e_version-ignored",20,4,0),("shstrndx-ignored",62,2,65535)):
   add(label,modify(raw,off,n,value))
 elif group=="sections":
  for field,n,value in((4,4,1),(32,8,1),(24,8,MAX),(8,8,MAX)):
   add("null-"+str(field),modify(raw,sec+field,n,value))
  for value in(0,63,len(raw),len(raw)+1,MAX):
   add("text-offset-"+str(value),modify(raw,sec+64+24,8,value))
  for value in(0,1,2,MAX):
   add("text-size-"+str(value),modify(raw,sec+64+32,8,value))
  for value in(len(raw),len(raw)+1,MAX):
   value_raw=modify(modify(raw,sec+128+32,8,0),sec+128+24,8,value)
   add("zero-string-offset-"+str(value),value_raw)
  value_raw=modify(modify(modify(raw,sec+64+4,4,8),sec+64+24,8,MAX),sec+64+32,8,MAX)
  add("nobits-not-file-bound",value_raw)
  add("late-structure-before-early-binding",modify(modify(raw,sym+4,1,0xf2),sec+192+32,8,MAX))
  value_raw,_=fixture(extra_sections=4092);add("4096-sections",value_raw)
  add("4097-sections",modify(value_raw,60,2,4097))
  add("truncated-section-tail",raw[:-1])
 elif group=="tables":
  for value in(0,1,4,(1<<32)-1):add("link-"+str(value),modify(raw,sec+192+40,4,value))
  for value in(0,1,23,25,MAX):add("entsize-"+str(value),modify(raw,sec+192+56,8,value))
  for value in(0,1,23,25,MAX):add("size-"+str(value),modify(raw,sec+192+32,8,value))
  for value in(0,1,2,8):add("string-kind-"+str(value),modify(raw,sec+128+4,4,value))
  add("dynsym-is-not-symtab",modify(raw,sec+192+4,4,11))
  for value in(len(raw),len(raw)+1,MAX):
   add("names-empty-"+str(value),modify(modify(raw,sec+128+32,8,0),sec+128+24,8,value))
  add("empty-symtab-offset-ignored",modify(modify(raw,sec+192+32,8,0),sec+192+24,8,MAX))
 elif group=="bindings":
  for binding in range(16):
   data,_=fixture([[symbol(),symbol(b"abort",binding=binding,kind=0,section=0)]])
   add("binding-"+str(binding),data)
   data,_=fixture([[symbol(),symbol(None,binding=binding,kind=15,section=65535,name_off=0)]])
   add("zero-name-offset-"+str(binding),data)
   data,_=fixture([[symbol(),symbol(b"",binding=binding,kind=15,section=65535)]])
   add("empty-name-"+str(binding),data)
  data,_=fixture([[symbol(),symbol(b"\xff",binding=0,section=65535,name_off=(1<<32)-1)]])
  add("local-bad-name-skipped",data)
  for kind in range(16):
   data,_=fixture([[symbol(),symbol(b"abort",kind=kind,section=0)]])
   add("undefined-kind-"+str(kind),data)
 elif group=="names":
  if variant==0:
   for value in range(1,128):
    name=b"a"+bytes([value])+b"z";data,_=fixture([[symbol(name)]])
    add("ASCII-"+str(value),data,(name.decode("ascii"),))
  elif variant==1:
   for value in range(128,256):
    data,_=fixture([[symbol(b"x"+bytes([value])+b"y")]])
    add("non-ASCII-"+str(value),data)
  else:
   data,_=fixture([[symbol(),symbol(b"",binding=2,kind=15,section=65535)]])
   add("empty-weak-defined-skipped",data)
   for byte_value in(65,255):
    data,meta=fixture([[symbol(bytes([byte_value]))]])
    end=meta["names"]+meta["names_n"]-1
    add("unterminated-"+str(byte_value),modify(data,end,1,byte_value))
   for offset in(at["names_n"],at["names_n"]+1,(1<<32)-1,0):
    add("offset-"+str(offset),modify(raw,sym,4,offset))
 elif group=="definitions":
  for kind in range(16):
   data,_=fixture([[symbol(kind=kind)]])
   add("defined-kind-"+str(kind),data)
  for binding in(0,1,2):
   for section in(0,1,2,3,4,65535):
    data,_=fixture([[symbol(binding=binding,section=section)]])
    add("section-"+str(binding)+"-"+str(section),data)
  for flags in(0,1,2,4,5,6,7,MAX):
   add("flags-"+str(flags),modify(raw,sec+64+8,8,flags))
  for value,size in((0,0),(1,1),(MAX,1),(0,2),(0,MAX),(0,1)):
   data,_=fixture([[symbol(value=value,size=size)]])
   add("range-"+str(value)+"-"+str(size),data)
 elif group=="duplicates":
  rows=[
   [symbol(),symbol()],
   [symbol(),symbol(b"f",section=0)],
   [symbol(b"f",section=0),symbol()],
   [symbol(),symbol(b"abort",section=0),symbol(b"abort",binding=2,section=0)],
   [symbol(),symbol(b"f",binding=2)],
   [symbol(),symbol(b"f",kind=1)],
   [symbol(b"f",kind=1),symbol()],
   [symbol(),symbol(b"f",section=65535)],
   [symbol(),symbol(b"f",size=0)]]
  for i,values in enumerate(rows):add("order-"+str(i),fixture([values])[0])
 elif group=="closed":
  for name in IMPORTS:
   data,_=fixture([[symbol(),symbol(name.encode(),section=0)]])
   add("import-"+name,data)
  for name in("evil","Abort","mallocX","", "\x7f"):
   data,_=fixture([[symbol(),symbol(name.encode(),section=0)]])
   add("import-other-"+repr(name),data)
  for names in((),("f","f"),("f","x"),("x",),("F",),("f\0",),("\ud800",),("\u00e9",)):
   add("expected-"+repr(names),raw,names)
  data,_=fixture([[symbol(b"z"),symbol(b"a"),symbol(b"m")]],text=b"\xc3")
  add("sorted-exports",data,("z","a","m","a"))
 elif group=="multi":
  tables=[
   [[symbol()],[symbol(b"abort",section=0)]],
   [[symbol()],[symbol()]],
   [[symbol(b"f",section=0)],[symbol()]],
   [[symbol()],[symbol(b"f",section=0)]],
   [[],[symbol()]],
   [[symbol(b"",kind=15)],[symbol()]],
   [[symbol(),symbol(b"x",binding=3)],[symbol(b"\xff")]],
   [[symbol(b"\xff")],[symbol(b"x",binding=3)]]]
  for i,t in enumerate(tables):add("table-order-"+str(i),fixture(t)[0])
 elif group=="grow":
  for count in(1,33,513):
   rows=[symbol(("name"+str(i).zfill(4)).encode()) for i in range(count)]
   data,_=fixture([rows]);add("nodes-"+str(count),data,tuple(r["name"].decode() for r in rows))
 elif group=="large":
  if variant==0:
   rows=[symbol()]+[symbol(b"abort",binding=2,section=0)]*65537
   add("65537-duplicate-imports",fixture([rows])[0])
  elif variant==1:
   rows=[symbol()]+[symbol(("external"+str(i).zfill(5)).encode(),section=0) for i in range(65537)]
   add("65537-unique-imports-no-inventory-quota",fixture([rows])[0])
  elif variant==2:
   name=b"x"*(1<<20);data,_=fixture([[symbol(name)]])
   add("one-megabyte-name",data,(name.decode(),))
  else:
   rows=[symbol(("entry"+str(i).zfill(4)).encode()) for i in range(1024)]
   data,_=fixture([rows]);add("1024-exports-private-inventory",data,tuple(r["name"].decode() for r in rows))
 elif group=="bytes":
  wanted=(64<<20)+variant
  add("raw-padding-"+str(wanted),raw+b"\0"*(wanted-len(raw)))
 else:raise ValueError(group)
 return cases

def protocol(suite):
 raw,_=fixture();cmd=command(raw,("f",));n=0
 for size in(0,1,63,127):suite.bad("command-short-"+str(size),raw,cmd[:size]);n+=1
 for at,value in((0,0),(8,2),(16,0),(24,0),(32,0),(40,len(raw)+1),(48,MAX),(56,0),(64,128),(72,0),(80,len(cmd)-1)):
  suite.bad("command-word-"+str(at),raw,modify(cmd,at,8,value));n+=1
 for at in range(88,128,8):suite.bad("reserved-"+str(at),raw,modify(cmd,at,8,1));n+=1
 for at,value in((128,0),(128,len(cmd)+1),(136,MAX)):
  suite.bad("name-span-"+str(at)+"-"+str(value),raw,modify(cmd,at,8,value));n+=1
 for size in(0,1,127,4095):suite.bad("workspace-short-"+str(size),raw,cmd,capacity=size);n+=1
 # Each invocation is stateless. No header equality is claimed to authenticate
 # the immutable source: the caller owns the source lease and any retry.
 assert n==27
 return n

def producer(suite):
 for i in range(8):
  names=("z","a") if i&1 else ("entry",)
  imports=IMPORTS if i&2 else ("abort",)
  text=b"\xe8\0\0\0\0"*len(imports)+b"\xc3"*len(names)
  start=5*len(imports)
  syms=[dict(name=name,offset=start+j,size=1,global_=True) for j,name in enumerate(names)]
  syms=[{("global" if k=="global_" else k):v for k,v in row.items()} for row in syms]
  rels=[dict(offset=1+5*j,symbol=name,type=4,addend=-4) for j,name in enumerate(imports)]
  align=(16,32,64,16)[i%4]
  ref=suite.oracle.modules["hia_machine_elf"].write_elf_object(text,syms,rels,text_alignment=align)
  graph=suite.F.capture([align,text,syms,rels],17)
  cmd=struct.pack("<12Q",magic("HIAELC01"),1,17,i+1,len(graph),q(graph,24),0,0,0,0,0,0)
  before=suite.calls["elf-producer"];actual=suite.run("producer-"+str(i),graph,cmd,role="elf-producer")
  event=actual["event"];assert actual["returned"]==128 and event[0:3]==(magic("HIAELE01"),1,0)
  at,n=event[7:9];obj=actual["workspace"][at:at+n];assert obj==ref
  row=suite.check("native-producer-to-inventory-"+str(i),obj,names,kind="ACTUAL_NATIVE_ELF_PRODUCER_JOIN")
  row["native_producer"]=dict(entries=suite.calls["elf-producer"]-before,event=event,
       graph=suite.evidence.raw(graph),command=suite.evidence.raw(cmd),object=suite.evidence.raw(obj),
       complete_native_object_equals_original_writer=True,raw_object_opaque_forwarded=True)
  row["actual_entries"]["elf-producer"]+=suite.calls["elf-producer"]-before
  save(suite.out/"cases"/(str(len(suite.cases)).zfill(4)+".json"),row);suite.joined+=1

EXPECTED={("headers",0):78,("sections",0):21,("tables",0):23,("bindings",0):65,
 ("names",0):127,("names",1):128,("names",2):7,("definitions",0):48,
 ("duplicates",0):9,("closed",0):21,("multi",0):8,("grow",0):3,
 **{("large",i):1 for i in range(4)},("bytes",0):1,("bytes",1):1,
 ("protocol",0):27,("producer",0):8}
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def deadline(*unused):raise TimeoutError("object inventory original 180 wall")
 signal.signal(signal.SIGALRM,deadline);signal.alarm(180)
 p=argparse.ArgumentParser()
 for name in("reference","inventory","producer","out"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--group",required=True);p.add_argument("--variant",type=int,default=0)
 a=p.parse_args();a.reference=a.reference.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False)
 started=time.monotonic();suite=None;report=dict(status="INCOMPLETE",group=a.group,variant=a.variant,cases=0,native_entries=0)
 try:
  assert sys.version_info[:3]==(3,12,14) and (a.group,a.variant) in EXPECTED
  suite=Suite(a)
  if a.group=="protocol":protocol(suite)
  elif a.group=="producer":producer(suite)
  else:
   fixtures=corpus(a.group,a.variant)
   assert len(fixtures)==EXPECTED[(a.group,a.variant)],("fixture count",len(fixtures),EXPECTED[(a.group,a.variant)])
   save(a.out/"fixture-plan.json",[dict(label=label,object_bytes=len(data),object_sha256=digest(data),expected_exports=list(exports)) for label,data,exports in fixtures])
   for label,data,exports in fixtures:suite.check(label,data,exports)
  assert len(suite.cases)==EXPECTED[(a.group,a.variant)]
  report["status"]="PASS"
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  if suite is not None:
   report.update(cases=len(suite.cases),native_entries=sum(suite.calls.values()),by_role=suite.calls,
       private_controls=suite.controls,actual_native_producer_joins=suite.joined,
       complete_error_class_and_text=True,complete_inventory=True)
   try:report["source_custody"]=suite.finish()
   except BaseException as error:
    report.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc());traceback.print_exc()
  report.update(elapsed_seconds=time.monotonic()-started,limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
      address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
      new_component_execution_only=True,old_results_inherited=False,full_public_backend=False,
      whole_emitter_join=False,COFF_or_MachO=False,shared_library_inspection=False,installed=False,cold=False)
  save(a.out/"summary.json",report);print(json.dumps(report,sort_keys=True),flush=True);signal.alarm(0)
 if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
