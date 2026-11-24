from pathlib import Path
import ctypes,hashlib,json,mmap,os,signal,struct,subprocess,time,tomllib,traceback,sys
import argparse,shutil
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime-source',type=Path,required=True)
parser.add_argument('--components',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--cargo',type=Path,default=shutil.which('cargo'))
parser.add_argument('--rustc',type=Path)
parser.add_argument('--cargo-home',type=Path)
args=parser.parse_args();R=args.runtime_source.resolve(strict=True);D=args.components.resolve(strict=True);Q=args.output.resolve();Q.mkdir(mode=0o700)
assert args.cargo,'an external Rust oracle compiler is required'
(Q/'qualifier.py').write_text(Path(__file__).read_text())
manifest=json.loads((D/'build-status.json').read_text());assert manifest['phase']=='ready'
build_env=dict(os.environ)
if args.cargo_home:build_env['CARGO_HOME']=str(args.cargo_home)
if args.rustc:build_env['RUSTC']=str(args.rustc)
sources={n:(R/'src/mcp'/n).read_bytes()for n in ['rea_engine_job_owner.rs','rea_engine_directory.rs']}
assert hashlib.sha256(sources['rea_engine_job_owner.rs']).hexdigest()=='2025571154747e012e40fe8493bf73d50f4bc1d13b58a7c877b942c9237f9d78'
assert hashlib.sha256(sources['rea_engine_directory.rs']).hexdigest()=='e338f3b27e52cd0c891114d9a41e96f2baf5d7508e93b50c5beec35311134fa9'
oracle=Q/'oracle';(oracle/'src').mkdir(parents=True)
for n,raw in sources.items():(oracle/'src'/n).write_bytes(raw)
owner=sources['rea_engine_job_owner.rs'].decode();start=owner.index('\t\tif bytes.len() > 16384',owner.index('fn members('));end=owner.index('\n\t}\n\tOk(members)',start);section=owner[start:end]
main=r'''#![allow(dead_code,unused_imports)]
use anyhow::{bail,Context,Result};use std::io::Read;use serde_json::json;
#[path="rea_engine_job_owner.rs"]mod owner;
fn stat(bytes:&[u8],group:i32)->Result<bool>{let mut members=Vec::new();let pid=1;
'''+section+r'''
Ok(!members.is_empty())}
fn spawn(kind:&str)->i32{unsafe{let mut pipe=[0;2];assert_eq!(libc::pipe(pipe.as_mut_ptr()),0);let pid=libc::fork();assert!(pid>=0);if pid==0{libc::close(pipe[0]);assert_eq!(libc::setpgid(0,0),0);if kind=="descendant"{let child=libc::fork();if child==0{libc::close(pipe[1]);loop{libc::pause();}}}
let byte=[1u8];libc::write(pipe[1],byte.as_ptr().cast(),1);libc::close(pipe[1]);if kind=="exit"||kind=="descendant"{libc::_exit(0);}loop{libc::pause();}}
libc::close(pipe[1]);let mut byte=[0u8];assert_eq!(libc::read(pipe[0],byte.as_mut_ptr().cast(),1),1);libc::close(pipe[0]);pid}}
fn main(){let args:Vec<String>=std::env::args().collect();let mut bytes=Vec::new();std::io::stdin().read_to_end(&mut bytes).unwrap();let mode=args[1].as_str();let result:Result<bool>=match mode{
"visibility"=>(||{owner::confirm_group_visibility(std::str::from_utf8(&bytes)?)?;Ok(true)})(),
"stat"=>stat(&bytes,123),
"live"|"exit"|"descendant"=>{let pid=spawn(mode);let result=owner::stop_original_group(pid as u32).map(|_|true);unsafe{let mut st=0;let wait=libc::waitpid(pid,&mut st,libc::WNOHANG);if result.is_ok(){assert_eq!(wait,pid,"group stop reaped its original child");}if wait==0{libc::kill(-pid,9);libc::waitpid(pid,&mut st,0);}}result},
"observe"=>{let pid=spawn("live");let a=owner::original_exited(pid as u32).unwrap();assert!(!a);unsafe{libc::kill(-pid,9);}while !owner::original_exited(pid as u32).unwrap(){std::thread::sleep(std::time::Duration::from_millis(1));}assert!(owner::original_exited(pid as u32).unwrap());unsafe{let mut st=0;assert_eq!(libc::waitpid(pid,&mut st,0),pid);}Ok(true)},
"lost"=>owner::original_exited(std::process::id()),"zero"=>owner::original_exited(0),_=>panic!()};
match result{Ok(value)=>println!("{}",json!({"ok":true,"value":value})),Err(error)=>println!("{}",json!({"ok":false,"error":format!("{error:#}")}))}}
'''
(oracle/'src/main.rs').write_text(main);lock=tomllib.loads((R/'Cargo.lock').read_text());vers={n:next(p['version']for p in lock['package']if p['name']==n)for n in ['anyhow','libc','serde_json']}
cargo='[package]\nname="scratch-group-oracle"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\n'
for n,v in vers.items():cargo+=n+'="='+v+'"\n'
(oracle/'Cargo.toml').write_text(cargo);p=subprocess.run([str(args.cargo),'build','--offline','--release','--manifest-path',str(oracle/'Cargo.toml')],capture_output=True,env=build_env);(Q/'oracle-build.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr[-4000:]
binary=oracle/'target/release/scratch-group-oracle'
flat=(D/'scratch_group.flat').read_bytes();assert hashlib.sha256(flat).hexdigest()==manifest['images']['scratch_group.flat']['sha256'];assert flat and flat[:4]!=b'\x7fELF';code=mmap.mmap(-1,len(flat),prot=7);code.write(flat);entry=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)(ctypes.addressof(ctypes.c_char.from_buffer(code)))
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long;NONE=(1<<64)-1
class Native:
 def __init__(self):
  self.w=mmap.mmap(-1,128<<20);self.address=ctypes.addressof(ctypes.c_char.from_buffer(self.w));self.plan=ctypes.create_string_buffer(128);self.input=ctypes.create_string_buffer(b'X');self.calls=[]
 def get(self,at):return struct.unpack_from('<Q',self.w,at)[0]
 def put(self,at,value):struct.pack_into('<Q',self.w,at,value&NONE)
 def run(self,phase,op=2,pid=123,raw=None,pure=False):
  self.put(0,phase);self.put(62000,op);self.put(62008,9000);self.put(62128,pid)
  if raw is not None:self.w[70<<20:(70<<20)+len(raw)]=raw;self.put(62632,len(raw))
  if phase==3602:self.put(62688,1);self.put(62680,123);self.put(62648,0);self.put(62656,0);self.put(62664,0)
  for _ in range(1000000):
   action=entry(self.input,1,self.plan,128,self.address,128<<20)
   if action==8:
    if self.get(0)==9000:break
    continue
   assert action==1,('action',action,self.get(0))
   values=struct.unpack_from('<8Q',self.plan);number=values[0]
   if pure:break
   self.calls.append(number);args=[]
   for i,value in enumerate(values[1:7]):
    ptr=(values[7]>>(i*2))&3
    if ptr:value+=self.address if ptr==3 else ctypes.addressof(self.plan)if ptr==2 else ctypes.addressof(self.input)
    args.append(ctypes.c_uint64(value))
   ctypes.set_errno(0);result=libc.syscall(ctypes.c_long(number),*args)
   if result==-1:result=-ctypes.get_errno()
   self.put(8,result)
  else:raise AssertionError('continuation did not finish')
  if self.get(62144):
   at,size=self.get(62176),self.get(62184);assert size<=2097152,('error span',at,size);return {'ok':False,'error':self.w[at:at+size].decode()}
  return {'ok':True,'value':bool(self.get(62664))if phase==3602 else bool(self.get(62152))if op==1 else True}
 def close(self):self.w.close()
def spawn(kind):
 read,write=os.pipe();pid=os.fork()
 if pid==0:
  os.close(read);os.setpgid(0,0)
  if kind=='descendant':
   child=os.fork()
   if child==0:
    os.close(write)
    while True:signal.pause()
  os.write(write,b'X');os.close(write)
  if kind in ('exit','descendant'):os._exit(0)
  while True:signal.pause()
 os.close(write);assert os.read(read,1)==b'X';os.close(read);return pid
rows=[]
def check(name,mode,raw=b''):
 expected=json.loads(subprocess.run([binary,mode],input=raw,capture_output=True,check=True,timeout=8).stdout);n=Native()
 try:
  if mode=='visibility':actual=n.run(3504,raw=raw,pure=True)
  elif mode=='stat':actual=n.run(3602,raw=raw,pure=True)
  elif mode in ('live','exit','descendant'):
   pid=spawn(mode)
   try:
    actual=n.run(3500,pid=pid)
    observed,st=os.waitpid(pid,os.WNOHANG)
    if actual['ok']:assert observed==pid,'native group stop reaped its original child'
   finally:
    try:os.killpg(pid,9)
    except ProcessLookupError:pass
    try:os.waitpid(pid,0)
    except ChildProcessError:pass
  elif mode=='observe':
   pid=spawn('live')
   try:
    assert n.run(3500,op=1,pid=pid)=={'ok':True,'value':False};os.killpg(pid,9)
    while not n.run(3500,op=1,pid=pid)['value']:time.sleep(.001)
    assert n.run(3500,op=1,pid=pid)['value'];assert os.waitpid(pid,0)[0]==pid;actual={'ok':True,'value':True}
   finally:
    try:os.killpg(pid,9)
    except ProcessLookupError:pass
    try:os.waitpid(pid,0)
    except ChildProcessError:pass
  else:actual=n.run(3500,op=1,pid=os.getpid()if mode=='lost' else 0)
  row={'case':name,'original':expected,'native':actual,'calls':len(n.calls),'pass':actual==expected};rows.append(row);(Q/'status.json').write_text(json.dumps({'state':'running','rows':rows},indent=2)+'\n');assert actual==expected,row
 finally:n.close()
try:
 base=b'1 2 0:1 / /proc rw,nosuid - proc proc rw\n'
 for name,raw in [('valid',base),('missing',b''),('other',base.replace(b'/proc',b'/other')),('invalid-utf8',base+b'\xff'),('unicode-fields',base.replace(b' ',b'\xe3\x80\x80')),('overline',b'\n'+base+b'\n')]:check('mount-'+name,'visibility',raw)
 for value in [b'0',b'off',b'1',b'2',b'invisible',b'',b'00',b'OFF']:
  for location in [b'rw,hidepid='+value,b'hidepid='+value+b',rw']:
   check('hidepid-'+location.decode(),'visibility',base.replace(b'rw,nosuid',location))
 for name,raw in [('live',b'1 (worker) S 2 123 0'),('zombie',b'1 (worker) Z 2 123 0'),('dead',b'1 (worker) X 2 123 0'),('other',b'1 (worker) S 2 124 0'),('nested-parenthesis',b'1 (a) b)) S 2 123'),('absent',b'1 (x) S 2'),('malformed',b'no parenthesis'),('signed',b'1 (x) S 2 +00123'),('negative',b'1 (x) S 2 -123'),('double-sign',b'1 (x) S 2 -+123'),('overflow',b'1 (x) S 2 2147483648'),('utf8',b'1 (x) S 2 123 \xff'),('multistate',b'1 (x) ZZ 2 123'),('wide',b'1 (x) S 2 123'+b' '*16385)]:check('stat-'+name,'stat',raw)
 for mode in ['live','exit','descendant','observe','lost','zero']:check('real-'+mode,mode)
 assert (D/'scratch_group.flat').read_bytes()==flat
 report={'state':'passed','cases':len(rows),'rows':rows,'flat_sha256':hashlib.sha256(flat).hexdigest(),'oracle_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_sha256':{n:hashlib.sha256(b).hexdigest()for n,b in sources.items()}};(Q/'status.json').write_text(json.dumps(report,indent=2)+'\n');print('SCRATCH GROUP PASS',len(rows),flush=True)
except BaseException:
 (Q/'failure.txt').write_text(traceback.format_exc());raise
