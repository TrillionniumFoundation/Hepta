from pathlib import Path
import ctypes,hashlib,json,mmap,os,re,shutil,signal,stat,struct,subprocess,sys,tomllib,traceback
import argparse,shutil
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime-source',type=Path,required=True)
parser.add_argument('--components',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--cargo',type=Path,default=shutil.which('cargo'))
parser.add_argument('--rustc',type=Path)
parser.add_argument('--cargo-home',type=Path)
parser.add_argument('--mounts',action='store_true')
args=parser.parse_args();R=args.runtime_source.resolve(strict=True);D=args.components.resolve(strict=True);Q=args.output.resolve();Q.mkdir(mode=0o700)
assert args.cargo,'an external Rust oracle compiler is required'
(Q/'qualifier.py').write_text(Path(__file__).read_text())
manifest=json.loads((D/'build-status.json').read_text());assert manifest['phase']=='ready'
build_env=dict(os.environ)
if args.cargo_home:build_env['CARGO_HOME']=str(args.cargo_home)
if args.rustc:build_env['RUSTC']=str(args.rustc)
original=(R/'src/bin/jobctl.rs').read_text();assert hashlib.sha256(original.encode()).hexdigest()=='575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81'
files={n:(R/'src/mcp'/n).read_bytes()for n in ['rea_engine_job_owner.rs','rea_engine_directory.rs']};assert hashlib.sha256(files['rea_engine_job_owner.rs']).hexdigest()=='2025571154747e012e40fe8493bf73d50f4bc1d13b58a7c877b942c9237f9d78';assert hashlib.sha256(files['rea_engine_directory.rs']).hexdigest()=='e338f3b27e52cd0c891114d9a41e96f2baf5d7508e93b50c5beec35311134fa9';oracle=Q/'oracle';(oracle/'src').mkdir(parents=True)
for n,raw in files.items():(oracle/'src'/n).write_bytes(raw)
atomic=original[original.index('fn atomic('):original.index('fn dispatch_after_launch_namespace_sync')]
main=r'''#![allow(dead_code,unused_imports)]
use anyhow::{Context,Result};use serde::Serialize;use serde_json::{json,Value};use std::io::{BufRead,Write};use std::fs::{self,File,OpenOptions};use std::path::Path;use std::os::unix::fs::OpenOptionsExt;
#[path="rea_engine_job_owner.rs"]mod engine;
'''+atomic+r'''
fn emit(value:Value){println!("{}",value);std::io::stdout().flush().unwrap();}
fn run()->Result<()>{let stdin=std::io::stdin();let mut lines=stdin.lock().lines();let q:Value=serde_json::from_str(&lines.next().unwrap()?)?;
if q["op"]=="selected"{let args:Vec<String>=serde_json::from_value(q["args"].clone())?;let selected=engine::selected(&args,q["input"].as_str());emit(json!({"selected":selected}));return Ok(())}
let state=Path::new(q["state"].as_str().unwrap());let id=q["id"].as_str().unwrap();let nonce=q["nonce"].as_str().unwrap();if q["collision"]==true{fs::write(state.join(format!("engine-scratch.tmp-{}",std::process::id())),b"sentinel")?;}
let owner=engine::ScratchOwner::prepare(&fs::canonicalize(state)?,id,nonce)?;atomic(&state.join("engine-scratch.json"),&owner.binding)?;emit(json!({"ok":true,"binding":owner.binding}));
let next:Value=serde_json::from_str(&lines.next().unwrap()?)?;let receipt=if next["op"]=="retained"{let receipt=owner.retained(next["reason"].as_str().unwrap());atomic(&state.join("engine-scratch.retained.json"),&receipt)?;receipt}else{owner.finish(next["pid"].as_u64().unwrap()as u32,next["stopped"].as_bool().unwrap())};emit(json!({"ok":true,"receipt":receipt}));Ok(())}
fn main(){if let Err(error)=run(){emit(json!({"ok":false,"error":format!("{error:#}")}));}}
'''
(oracle/'src/main.rs').write_text(main);lock=tomllib.loads((R/'Cargo.lock').read_text());vers={n:next(p['version']for p in lock['package']if p['name']==n)for n in ['anyhow','libc','serde','serde_json']};cargo='[package]\nname="scratch-owner-oracle"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\n'
for n,v in vers.items():cargo+=n+'={version="='+v+'"'+(',features=["derive"]'if n=='serde'else',features=["float_roundtrip","raw_value"]'if n=='serde_json'else'')+'}\n'
(oracle/'Cargo.toml').write_text(cargo);p=subprocess.run([str(args.cargo),'build','--offline','--release','--manifest-path',str(oracle/'Cargo.toml')],capture_output=True,env=build_env);(Q/'oracle-build.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr[-4000:];binary=oracle/'target/release/scratch-owner-oracle'
NONE=(1<<64)-1;libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long;images={};code=[]
for name in ['scratch','scratch_directory','scratch_group','value']:
 raw=(D/(name+'.flat')).read_bytes();assert hashlib.sha256(raw).hexdigest()==manifest['images'][name+'.flat']['sha256'];m=mmap.mmap(-1,len(raw),prot=7);m.write(raw);code.append(m);images[name]=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)(ctypes.addressof(ctypes.c_char.from_buffer(m)))
class Native:
 def __init__(self):
  self.w=mmap.mmap(-1,128<<20);self.address=ctypes.addressof(ctypes.c_char.from_buffer(self.w));self.plan=ctypes.create_string_buffer(128);self.input=ctypes.create_string_buffer(b'X');self.calls=[]
 def get(self,at):return struct.unpack_from('<Q',self.w,at)[0]
 def put(self,at,value):struct.pack_into('<Q',self.w,at,value&NONE)
 def slot(self,slot,at,raw):
  if isinstance(raw,str):raw=raw.encode()
  self.w[at:at+len(raw)]=raw;self.w[at+len(raw)]=0;self.put(slot,at);self.put(slot+8,len(raw))
 def init(self,state,args=None,raw=None,interactive=0,id='job-test',nonce='n'*32):
  args=['rea-static-worker']if args is None else args;raw='{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}'if raw is None else raw
  self.put(62024,interactive);self.put(62032,len(args));self.slot(62040,102<<20,args[0]if args else'');self.put(62056,int(raw is not False));self.slot(62064,100<<20,raw if raw is not False else'');self.slot(62080,104<<20,str(state));self.slot(62096,106<<20,id);self.slot(62112,(106<<20)+4096,nonce)
 def run(self,operation,pure=False):
  self.put(0,3000);self.put(62000,operation);self.put(62008,9000)
  for _ in range(2000000):
   phase=self.get(0);name='scratch'if phase<3100 else'scratch_directory'if phase<3500 else'scratch_group'
   action=images[name](self.input,1,self.plan,128,self.address,128<<20)
   if action in (8,21,22,23):
    if self.get(0)==9000:break
    continue
   if action==14:
    a,b,c,d,e,f=struct.unpack_from('<6Q',self.plan);self.put(8,images['value'](self.address+a,b,self.address+c,d,self.address+e,f));continue
   assert action==1,('invalid native action',action,phase)
   values=struct.unpack_from('<8Q',self.plan);number=values[0]
   if pure:return {'selected':bool(self.get(62192))}
   self.calls.append({'phase':self.get(0),'number':number});args=[]
   for i,value in enumerate(values[1:7]):
    ptr=(values[7]>>(i*2))&3
    if ptr:value+=self.address if ptr==3 else ctypes.addressof(self.plan)if ptr==2 else ctypes.addressof(self.input)
    args.append(ctypes.c_uint64(value))
   ctypes.set_errno(0);result=libc.syscall(ctypes.c_long(number),*args)
   if result==-1:result=-ctypes.get_errno()
   self.put(8,result)
  else:raise AssertionError('continuation did not finish')
  if pure:return {'selected':bool(self.get(62192))}
  if self.get(62144):
   at,size=self.get(62176),self.get(62184);assert 0<=size<=2097152;return {'ok':False,'error':self.w[at:at+size].decode()}
  at,size=self.get(62160),self.get(62168);assert size<=8388608
  return {'ok':True,'binding'if operation==0 else'receipt':json.loads(self.w[at:at+size])}
 def close(self):
  for at in [62200,62208,62248,62360,62368,62464,62472]:
   fd=self.get(at)
   if fd!=NONE and fd>2:
    try:os.close(fd)
    except OSError:pass
  self.w.close()
def enc(v):return json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()
def read(p):
 line=p.stdout.readline();assert line,('oracle exited',p.poll(),p.stderr.read());return json.loads(line)
def tree(path):
 out={}
 for p in sorted(path.rglob('*')):
  rel=str(p.relative_to(path));st=p.lstat()
  if stat.S_ISDIR(st.st_mode):out[rel]=['dir',stat.S_IMODE(st.st_mode)]
  elif stat.S_ISLNK(st.st_mode):out[rel]=['link',os.readlink(p)]
  elif stat.S_ISREG(st.st_mode):
   data=p.read_bytes()
   try:value=json.loads(data);out[rel]=['json',value]
   except Exception:out[rel]=['file',hashlib.sha256(data).hexdigest(),len(data)]
  else:out[rel]=['special',stat.S_IFMT(st.st_mode)]
 return out
def normalize(value,root,binding=None):
 if isinstance(value,dict):
  result={re.sub(r'tmp-[0-9]+','tmp-<pid>',k):normalize(v,root,binding)for k,v in value.items()}
  if 'device'in result:result['device']='<device>'
  if 'inode'in result:result['inode']='<inode>'
  return result
 if isinstance(value,list):return[normalize(v,root,binding)for v in value]
 if isinstance(value,str):return value.replace(str(root),'<root>')
 return value
mounts=[]
rows=[]
def record(row):
 rows.append(row);(Q/'status.json').write_text(json.dumps({'state':'running','rows':rows},ensure_ascii=False,indent=2)+'\n');assert row['pass'],row
base={'schema':'hepta.rea.static-request.v1','profile':{'provider':'jadx'}}
selected_cases=[('normal',['rea-static-worker'],json.dumps(base)),('ghidra',['rea-static-worker'],json.dumps({**base,'profile':{'provider':'ghidra'}})),('none',['rea-static-worker'],None),('args-empty',[],json.dumps(base)),('args-two',['rea-static-worker','x'],json.dumps(base)),('args-wrong',['other'],json.dumps(base)),('invalid',['rea-static-worker'],'{'),('root-sequence',['rea-static-worker'],'[]'),('last-wins',['rea-static-worker'],'{"schema":"bad","schema":"hepta.rea.static-request.v1","profile":{"provider":"bad","provider":"jadx"}}'),('escaped-duplicate',['rea-static-worker'],'{"schema":"bad","sch\\u0065ma":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}'),('overwritten-nonfinite',['rea-static-worker'],'{"schema":1e400,"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}'),('ignored-nonfinite',['rea-static-worker'],json.dumps(base)[:-1]+',"unknown":1e400}')]
for name,args,raw in selected_cases:
 p=subprocess.run([binary],input=enc({'op':'selected','args':args,'input':raw})+b'\n',capture_output=True,check=True);expected=json.loads(p.stdout);n=Native();n.init(Q,args=args,raw=raw if raw is not None else False)
 try:actual=n.run(0,pure=True);record({'case':'selected-'+name,'original':expected,'native':actual,'pass':expected==actual})
 finally:n.close()
def populate(kind,state,binding):
 scratch=Path(binding['path'])
 if kind=='files':
  (scratch/'file').write_bytes(b'payload');(scratch/'child').mkdir();(scratch/'child/nested').write_bytes(b'nested');(scratch/'link').symlink_to('/does/not/exist');os.mkfifo(scratch/'pipe')
 if kind.startswith('depth-'):
  p=scratch
  for i in range(int(kind.split('-')[1])):p=p/str(i);p.mkdir()
  (p/'leaf').write_text('leaf')
 if kind=='permissions':scratch.chmod(0o755)
 if kind=='replaced':scratch.rename(state/'original-scratch');scratch.mkdir(mode=0o700);(scratch/'foreign').write_text('must remain')
 if kind=='parent-replaced':
  state.rename(state.with_name('old-state'));state.mkdir(mode=0o700);(state/'engine-scratch').mkdir(mode=0o700);(state/'engine-scratch/foreign').write_text('must remain')
 if kind.startswith('claim-'):
  claim={'schema':'hepta.rea.engine-scratch-claim.v1','owner':binding,'worker_pid':123,'engine':'jadx'}
  raw=enc(claim);mode=0o600
  if kind=='claim-wrong-pid':claim['worker_pid']=124;raw=enc(claim)
  if kind=='claim-owner-extra':claim['owner']={**binding,'extra':0};raw=enc(claim)
  if kind=='claim-owner-float':claim['owner']={**binding,'inode':float(binding['inode'])};raw=enc(claim)
  if kind=='claim-duplicate':raw=raw[:-1]+b',"engine":"bad","engine":"jadx"}'
  if kind=='claim-invalid':raw=b'{'
  if kind=='claim-oversize':raw+=b' '*16385
  if kind=='claim-wrong-mode':mode=0o644
  if kind=='claim-wrong-owner':mode=0o600
  if kind=='claim-pid-float':claim['worker_pid']=123.0;raw=enc(claim)
  if kind=='claim-symlink':
   (state/'elsewhere').write_bytes(raw);(scratch/'claim.json').symlink_to(state/'elsewhere');return
  path=scratch/'claim.json';path.write_bytes(raw);path.chmod(mode)
  if kind=='claim-hardlink':os.link(path,state/'hardlink')
  if kind=='claim-wrong-owner':os.chown(path,65534,65534)
 if kind=='mounted-descendant':
  target=scratch/'mounted';target.mkdir();source=state/'foreign';source.mkdir();(source/'untouched').write_text('foreign mount')
  subprocess.run(['mount','--bind',str(source),str(target)],check=True);mounts.append(target)
 if kind=='read-only':
  (scratch/'untouched').write_text('read only')
  subprocess.run(['mount','--bind',str(scratch),str(scratch)],check=True);mounts.append(scratch)
  subprocess.run(['mount','-o','remount,bind,ro',str(scratch)],check=True)
case_names=['empty','files','unconfirmed','retained','permissions','replaced','parent-replaced','depth-32','depth-33','claim-valid','claim-wrong-pid','claim-owner-extra','claim-owner-float','claim-duplicate','claim-invalid','claim-oversize','claim-wrong-mode','claim-symlink','claim-hardlink','claim-pid-float','unicode','alias','repeated-slash']
if args.mounts:
 assert os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt');case_names+=['claim-wrong-owner','mounted-descendant','read-only']
for name in case_names:
 case=Q/name;case.mkdir();oldroot=case/'original';newroot=case/'native';oldroot.mkdir();newroot.mkdir();oldstate=oldroot/'state';newstate=newroot/'state';oldstate.mkdir(mode=0o700);newstate.mkdir(mode=0o700)
 oldarg=oldstate;newarg=newstate
 if name=='alias':
  (oldroot/'alias').symlink_to(oldstate);(newroot/'alias').symlink_to(newstate);oldarg=oldroot/'alias';newarg=newroot/'alias'
 if name=='repeated-slash':oldarg=str(oldstate)+'/./';newarg=str(newstate)+'/./'
 jobid='job-test';nonce='雪\n\t'+chr(0)+'end'if name=='unicode'else'n'*32
 q={'state':str(oldarg),'id':jobid,'nonce':nonce};p=subprocess.Popen([binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);p.stdin.write(enc(q)+b'\n');p.stdin.flush();expected_binding=read(p);n=Native();n.init(newarg,id=jobid,nonce=nonce);fds_before=len(os.listdir('/proc/self/fd'))
 try:
  actual_binding=n.run(0);assert len(os.listdir('/proc/self/fd'))==fds_before+2;assert actual_binding['ok'],actual_binding;assert expected_binding['ok'],expected_binding
  for state,binding in [(oldstate,expected_binding['binding']),(newstate,actual_binding['binding'])]:
   info=Path(binding['path']).stat();assert (binding['device'],binding['inode'])==(info.st_dev,info.st_ino);assert json.loads((state/'engine-scratch.json').read_bytes())==binding;populate(name,state,binding)
  next={'op':'retained','reason':'failure: 原始错误\nwith details'}if name=='retained'else{'op':'finish','pid':123,'stopped':name!='unconfirmed'}
  p.stdin.write(enc(next)+b'\n');p.stdin.flush();expected=read(p);p.stdin.close();assert p.wait(timeout=8)==0
  n.put(62128,123);n.put(62136,int(name!='unconfirmed'))
  if name=='retained':n.slot(62176,90<<20,next['reason'])
  actual=n.run(4 if name=='retained'else 3)
  assert len(os.listdir('/proc/self/fd'))==fds_before-1,('descriptor leak',fds_before,len(os.listdir('/proc/self/fd')))
  assert all(n.get(at)==NONE for at in [62200,62208,62248,62360,62368,62464,62472])
  oldtree=normalize(tree(oldroot),oldroot);newtree=normalize(tree(newroot),newroot)
  # The retained claim hardlink contains its original owner JSON, with exactly
  # the same independently checked device/inode/path normalization.
  equal=normalize(expected,oldroot)==normalize(actual,newroot) and oldtree==newtree
  record({'case':name,'original':normalize(expected,oldroot),'native':normalize(actual,newroot),'tree_equal':oldtree==newtree,'original_tree':oldtree,'native_tree':newtree,'calls':len(n.calls),'pass':equal})
 finally:
  n.close()
  if p.poll()is None:p.kill();p.wait()
  while mounts:subprocess.run(['umount',str(mounts.pop())],check=True)
assert all(hashlib.sha256((D/(n+'.flat')).read_bytes()).hexdigest()==manifest['images'][n+'.flat']['sha256']for n in images)
report={'state':'passed','cases':len(rows),'rows':rows,'images':{n:hashlib.sha256((D/(n+'.flat')).read_bytes()).hexdigest()for n in images},'oracle_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};(Q/'status.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('SCRATCH OWNER PASS',len(rows),flush=True)
