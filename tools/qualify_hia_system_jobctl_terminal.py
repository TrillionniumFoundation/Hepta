"""External native-flat/unchanged Rust typed Exit and witness differential."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,mmap,os,shutil,struct,subprocess,sys,tomllib
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime-source',type=Path,required=True)
parser.add_argument('--flat',type=Path,required=True)
parser.add_argument('--flat-sha256',required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--cargo',default=shutil.which('cargo'))
args=parser.parse_args();R=args.runtime_source.resolve(strict=True);D=args.output.resolve();D.mkdir(mode=0o700)
assert args.cargo,'an external Cargo oracle compiler is required'
flat_input=args.flat.resolve(strict=True);assert sha256(flat_input.read_bytes()).hexdigest()==args.flat_sha256
original=(R/'src/bin/jobctl.rs').read_text();assert sha256(original.encode()).hexdigest()=='575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81'
declarations=original[original.index('#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]\nenum TerminalProtocol'):original.index('impl Exit {')]
validation=original[original.index('fn validate_capture('):original.index('struct ConfirmedExit {')]
oracle=D/'oracle';(oracle/'src').mkdir(parents=True,exist_ok=True)
prefix='use serde::{Serialize,Deserialize};use serde_json::Value;use anyhow::{bail,Context,Result};use std::io::{Read,Write};const LOG_MAX:u64=16*1024*1024;\n'
main=r'''
fn main(){let mut raw=Vec::new();std::io::stdin().read_to_end(&mut raw).unwrap();let mut out=std::io::stdout();
if std::env::args().nth(1).as_deref()==Some("witness"){match serde_json::from_slice::<TerminalWitness>(&raw){Ok(value)=>{out.write_all(&serde_json::to_vec(&value).unwrap()).unwrap()},Err(_)=>std::process::exit(65)}}
else{match serde_json::from_slice::<Exit>(&raw){Ok(value)=>{let valid=validate_capture(&value,value.terminal_protocol).is_ok();out.write_all(if valid {b"{\"valid\":true,\"typed\":"} else {b"{\"valid\":false,\"typed\":"}).unwrap();out.write_all(&serde_json::to_vec(&value).unwrap()).unwrap();out.write_all(b"}").unwrap()},Err(_)=>std::process::exit(65)}}}
'''
(oracle/'src/main.rs').write_text(prefix+declarations+validation+main)
lock=tomllib.loads((R/'Cargo.lock').read_text());versions={n:next(p['version'] for p in lock['package'] if p['name']==n) for n in ('serde','serde_json','anyhow')}
(oracle/'Cargo.toml').write_text('[package]\nname="jobctl-terminal-oracle"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[dependencies]\nserde={version="='+versions['serde']+'",features=["derive"]}\nserde_json={version="='+versions['serde_json']+'",features=["float_roundtrip","raw_value"]}\nanyhow="='+versions['anyhow']+'"\n')
env={**os.environ,'CARGO_TARGET_DIR':str(D/'oracle-target')};build=subprocess.run([str(args.cargo),'build','--offline','--release','--manifest-path',str(oracle/'Cargo.toml')],env=env,capture_output=True);(D/'oracle-build.log').write_bytes(build.stdout+build.stderr);assert build.returncode==0,(build.returncode,build.stderr[-4000:])
binary=D/'oracle-target/release/jobctl-terminal-oracle'
flat=flat_input.read_bytes();code=mmap.mmap(-1,len(flat),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);code.write(flat);entry=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)(ctypes.addressof(ctypes.c_char.from_buffer(code)))
work=mmap.mmap(-1,128<<20);address=ctypes.addressof(ctypes.c_char.from_buffer(work));out=ctypes.create_string_buffer(128);NONE=(1<<64)-1
def get(at):return struct.unpack_from('<Q',work,at)[0]
def text_at(slot):
 at=get(slot);return None if at==NONE else work[at:at+get(slot+8)].decode('utf-8')
def decode(raw,mode):
 inp=ctypes.create_string_buffer(raw);struct.pack_into('<Q',work,54000,mode);ok=entry(inp,len(raw),out,128,address,128<<20)
 if ok!=1:return None
 if mode==1:
  row={k:text_at(55936+i*16) for i,k in enumerate(('job_id','nonce','terminal_protocol','exit_sha256'))};return row
 row={'job_id':text_at(54528),'nonce':text_at(54544),'exit_code':ctypes.c_int64(get(54560)).value,'timed_out':bool(get(54576)),'cancelled':bool(get(54592)),'at_unix_ms':int(text_at(54608))}
 if get(54024):row['terminal_protocol']=text_at(54624)
 row['output_complete']=None if get(54640)==NONE else bool(get(54640));row['output_durable']=None if get(54656)==NONE else bool(get(54656));row['capture']=None
 if get(54032):
  row['capture']={}
  for side,name in enumerate(('stdout','stderr')):
   at=55360+side*160;stream={}
   for i,key in enumerate(('seen','saved','eof','truncated','drain_timeout','read_error','write_error','sync_error','synced')):stream[key]=get(at+i*16) if i<2 else text_at(at+i*16) if 5<=i<8 else bool(get(at+i*16))
   row['capture'][name]=stream
 if get(54056)!=NONE:row['scratch_cleanup']=json.loads(raw[get(54056):get(54056)+get(54064)])
 struct.pack_into('<Q',work,54000,2);valid=entry(inp,0,out,128,address,128<<20)==1
 return {'valid':valid,'typed':row}
encode=lambda value:json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
stream={'seen':4,'saved':4,'eof':True,'truncated':False,'drain_timeout':False,'read_error':None,'write_error':None,'sync_error':None,'synced':True}
base={'job_id':'test-a','nonce':'a'*32,'exit_code':0,'timed_out':False,'cancelled':False,'at_unix_ms':1,'terminal_protocol':'captured_v1','output_complete':True,'output_durable':True,'capture':{'stdout':stream,'stderr':stream}}
cases=[]
def add(name,value,mode=0):cases.append((name,encode(value) if not isinstance(value,bytes) else value,mode))
add('captured',base)
for protocol in (None,'pty_v1'):
 value={k:v for k,v in base.items() if k not in ('terminal_protocol','output_complete','output_durable','capture')}
 if protocol:value['terminal_protocol']=protocol
 add('protocol-'+str(protocol),value)
for field in ('job_id','nonce','exit_code','timed_out','cancelled','at_unix_ms','terminal_protocol','output_complete','output_durable','capture'):
 for form in ('absent','null','wrong'):
  value=json.loads(encode(base));value.pop(field,None)
  if form!='absent':value[field]=None if form=='null' else []
  add(field+'-'+form,value)
for number in (-2147483649,-2147483648,-1,0,2147483647,2147483648,1.0):value=dict(base);value['exit_code']=number;add('code-'+str(number),value)
add('code-negative-zero',encode(base).replace(b'"exit_code":0',b'"exit_code":-0'))
for number in (0,(1<<64)-1,1<<64,(1<<128)-1,1<<128,-1,1.0):value=dict(base);value['at_unix_ms']=number;add('timestamp-'+str(number),value)
for field in stream:
 for form in ('absent','null','wrong'):
  value=json.loads(encode(base));value['capture']['stdout'].pop(field,None)
  if form!='absent':value['capture']['stdout'][field]=None if form=='null' else []
  add('stream-'+field+'-'+form,value)
for side in ('stdout','stderr'):
 for field,value in (('seen',3),('saved',16777217),('seen',(1<<64)-1),('saved',(1<<64)),('eof',False),('truncated',True),('drain_timeout',True),('synced',False),('read_error','x'),('write_error','x'),('sync_error','x')):
  changed=json.loads(encode(base));changed['capture'][side][field]=value;add(side+'-'+field+'-'+str(value),changed)
for suffix in (b',"unknown":"\\ud800"',b',"unknown":"\xff"',b',"unknown":1e400',b',"unknown":'+b'['*56000+b'0'+b']'*56000,b',"unknown":1,"unknown":2',b',"unknown":[0,]',b',"job_id":"test-a"',b',"\\ud800":1'):
 add('root-extra-'+str(len(cases)),encode(base)[:-1]+suffix+b'}')
for field in ('job_id','nonce'):
 value=encode(base);old=encode(base[field]);add(field+'-surrogate',value.replace(b'"'+field.encode()+b'":'+old,b'"'+field.encode()+b'":"\\ud800"'))
value=dict(base);value['terminal_protocol']={'captured_v1':None};add('protocol-object',value)
value=dict(base);value['scratch_cleanup']={'x':1.0,'negative':-0.0,'nested':[None,False,'雪']};add('known-value-deferred-canonical-valid',value)
witness={'job_id':'test-a','nonce':'a'*32,'terminal_protocol':'captured_v1','exit_sha256':'b'*64};add('witness',witness,1)
for field in witness:
 value=dict(witness);value.pop(field);add('witness-missing-'+field,value,1)
value=dict(witness);value['terminal_protocol']={'pty_v1':None};add('witness-enum-object',value,1)
add('witness-ignored',encode(witness)[:-1]+b',"unknown":"\\ud800"}',1)
# serde derive's positional sequence input is part of the original domain.
exit_fields=('job_id','nonce','exit_code','timed_out','cancelled','at_unix_ms','terminal_protocol','output_complete','output_durable','capture','scratch_cleanup')
seq=[base.get(k) for k in exit_fields]
for count in range(13):add('exit-sequence-length-'+str(count),(seq+[0])[:count])
for count in range(6):add('witness-sequence-length-'+str(count),([witness[k] for k in ('job_id','nonce','terminal_protocol','exit_sha256')]+[0])[:count],1)
for count in range(4):
 value=json.loads(encode(base));value['capture']=([stream,stream,None])[:count];add('capture-sequence-length-'+str(count),value)
stream_seq=[stream[k] for k in ('seen','saved','eof','truncated','drain_timeout','read_error','write_error','sync_error','synced')]
for count in range(11):
 value=json.loads(encode(base));value['capture']['stdout']=(stream_seq+[None])[:count];add('stream-sequence-length-'+str(count),value)
value=list(seq);value[9]=[stream_seq,stream_seq];add('all-structures-positional',value)
value=json.loads(encode(base));value['terminal_protocol']=['captured_v1'];add('protocol-is-not-struct-sequence',value)
rows=[]
for name,raw,mode in cases:
 run=subprocess.run([binary,*(['witness'] if mode else [])],input=raw,capture_output=True,env={'PATH':''},timeout=10)
 assert run.returncode in (0,65),(name,run.returncode,run.stderr)
 native=decode(raw,mode);expected=None if run.returncode else json.loads(run.stdout)
 if native!=expected:
  (D/'mismatch.json').write_text(json.dumps({'case':name,'raw_hex':raw.hex(),'native':native,'original':expected},indent=2)+'\n');raise AssertionError((name,native,expected))
 rows.append({'case':name,'raw_sha256':sha256(raw).hexdigest(),'original_accepts':run.returncode==0,'exact_typed_and_capture_equal':True})
assert flat_input.read_bytes()==flat
assert sha256((R/'src/bin/jobctl.rs').read_bytes()).hexdigest()==sha256(original.encode()).hexdigest()
report={'scope':'pure typed Exit/Witness and capture validation; Value field canonicalization is a separate observation-owner continuation','status':'passed','cases':len(rows),'rows':rows,'flat_sha256':sha256(flat).hexdigest(),'original_source_sha256':sha256(original.encode()).hexdigest(),'oracle_sha256':sha256(binary.read_bytes()).hexdigest()};(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('TERMINAL TYPED PASS',len(rows),flush=True)
