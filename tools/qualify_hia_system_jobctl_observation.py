"""External original/native root jobctl observation differential qualification.

All mount changes are confined to this process's private mount namespace. The
fixed systemctl path is supplied with sealed per-case host facts. Neither owner
implementation, its state machine, its assertions nor its budgets are changed.
"""
from pathlib import Path
from hashlib import sha256
import argparse,base64,copy,datetime,json,os,signal,subprocess,sys,traceback
parser=argparse.ArgumentParser(description=__doc__)
for name in ('native','oracle','output','original-source'):
 parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--native-sha256',required=True)
parser.add_argument('--oracle-sha256',required=True)
args=parser.parse_args()
assert os.geteuid()==0,'run via sudo unshare --mount --propagation private'
namespace=os.readlink('/proc/self/ns/mnt')
assert namespace!=os.readlink('/proc/1/ns/mnt'),'a private mount namespace is required'
native=args.native.resolve(strict=True);oracle=args.oracle.resolve(strict=True)
assert sha256(native.read_bytes()).hexdigest()==args.native_sha256
assert sha256(oracle.read_bytes()).hexdigest()==args.oracle_sha256
original_sha='575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81'
assert sha256(args.original_source.read_bytes()).hexdigest()==original_sha
Q=args.output.resolve();Q.mkdir(mode=0o700)
identity='native-observe';nonce='a'*32
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
record=dict(job_id=identity,unit=f'hepta-job-{identity}.service',request_digest='0'*64,boot_id=boot,nonce=nonce,invocation_id=None,launch_state='launched',created_unix_ms=1)
receipt=dict(job_id=identity,nonce=nonce,exit_code=0,timed_out=False,cancelled=False,at_unix_ms=1)
retained=dict(schema='hepta.rea.engine-scratch-cleanup.v1',job_id=identity,launch_nonce=nonce,directory='engine-scratch',state='retained',device=1,inode=2,error='retained after original owner stopped',removed=False,durable=False,worker_adopted=False,original_process_group_stopped=False,original_child_reaped=False)
def enc(v):return json.dumps(v,ensure_ascii=True,separators=(',',':')).encode()+b'\n'
def b64(v):return base64.b64encode(v).decode()
def properties(active='active',**fields):
 p=dict(LoadState='loaded',ActiveState=active,SubState='running',Result='success',InvocationID='b'*32,Description=f'Hepta Runtime {identity} {nonce}',ExecMainStatus='0',ExecMainCode='0');p.update(fields)
 return ''.join(k+'='+v+'\n' for k,v in p.items()).encode()
def stream(size=0,**kw):
 s=dict(seen=size,saved=size,eof=True,truncated=False,drain_timeout=False,read_error=None,write_error=None,sync_error=None,synced=True);s.update(kw);return s
def terminal(proto=None,**kw):
 e=copy.deepcopy(receipt);e.update(kw)
 if proto is not None:e['terminal_protocol']=proto
 if proto=='captured_v1' and 'capture' not in kw:
  e.update(capture=dict(stdout=stream(),stderr=stream()),output_complete=True,output_durable=True)
 return e
def witness(e,raw=None,**kw):
 v=dict(job_id=identity,nonce=nonce,terminal_protocol=e['terminal_protocol'],exit_sha256=sha256(enc(e) if raw is None else raw).hexdigest());v.update(kw);return enc(v)
cases=[]
def add(name,op='status',proto=None,record_changes=None,files=None,show=None,stop_rc=0,show_rc=0,request=None,**extra):
 r=copy.deepcopy(record)
 if proto is not None:r['terminal_protocol']=proto
 if record_changes:r.update(record_changes)
 q=dict(op=op,job_id=identity);q.update(request or {})
 c=dict(name=name,record=r,request=q,files=dict(files or {}),show=properties() if show is None else show,show_rc=show_rc,stop_rc=stop_rc)
 c.update(extra);cases.append(c)
def termcase(name,op='status',proto=None,record_proto='same',e=None,**extra):
 e=terminal(proto) if e is None else e;files={'exit.json':enc(e)}
 if e.get('terminal_protocol'):files['exit.witness']=witness(e)
 files.update(extra.pop('files',{}))
 add(name,op,proto if record_proto=='same' else record_proto,files=files,**extra)
for proto in [None,'captured_v1','pty_v1']:
 tag='legacy' if proto is None else proto
 for state in ['active','activating','deactivating','failed','inactive','']:
  add(tag+'-'+state,proto=proto,show=properties(state))
 add(tag+'-not-found',proto=proto,show=b'LoadState=not-found\n')
 add(tag+'-record-cancelled',proto=proto,record_changes={'launch_state':'cancelled'})
 add(tag+'-reboot',proto=proto,record_changes={'boot_id':'old-boot'})
 add(tag+'-description-mismatch',proto=proto,show=properties(Description='foreign owner'))
 add(tag+'-invocation-empty',proto=proto,show=properties(InvocationID=''))
 add(tag+'-incarnation-mismatch',proto=proto,record_changes={'invocation_id':'old-invocation'})
 add(tag+'-bound',proto=proto,record_changes={'invocation_id':'b'*32})
 termcase(tag+'-completed',proto=proto)
 termcase(tag+'-completed-reboot',proto=proto,record_changes={'boot_id':'old-boot'})
 termcase(tag+'-completed-record-cancelled',proto=proto,record_changes={'launch_state':'cancelled'})
 for code in [-2147483648,-1,7,2147483647]:termcase(tag+'-exit-'+str(code),proto=proto,e=terminal(proto,exit_code=code))
 termcase(tag+'-timeout-cancel',proto=proto,e=terminal(proto,timed_out=True,cancelled=True))
 termcase(tag+'-cancel',proto=proto,e=terminal(proto,cancelled=True))
 for raw_name,raw in [('invalid',b'{'),('nonobject',b'null'),('negative-zero',enc(terminal(proto)).replace(b'"exit_code":0',b'"exit_code":-0'))]:
  add(tag+'-receipt-'+raw_name,proto=proto,files={'exit.json':raw})
 termcase(tag+'-identity-mismatch',proto=proto,e=terminal(proto,nonce='foreign'))
 add(tag+'-receipt-symlink',proto=proto,files={'target.json':enc(terminal(proto)),'exit.json':('symlink','target.json')})
 add(tag+'-receipt-directory',proto=proto,files={'exit.json':('directory',)})
 add(tag+'-receipt-fifo',proto=proto,files={'exit.json':('fifo',)})
 add(tag+'-receipt-oversize',proto=proto,files={'exit.json':('fill',1048577,b' ')})
 termcase(tag+'-scratch-value',proto=proto,e=terminal(proto,scratch_cleanup={'unicode':'雪😀','float':1.0,'negative_zero':-0.0,'large':18446744073709551615}))
 # Value fields are stricter than ignored typed metadata fields.
 for label,fragment in [('overflow',b'1e400'),('surrogate',b'"\\ud800"'),('depth',b'['*129+b'0'+b']'*129)]:
  e=terminal(proto);raw=enc(e).rstrip()[:-1]+b',"scratch_cleanup":'+fragment+b'}\n'
  add(tag+'-scratch-'+label,proto=proto,files={'exit.json':raw,'exit.witness':witness(e,raw=raw)} if proto else {'exit.json':raw})
 if proto:
  for variant in ['absent','invalid','mismatch','symlink','fifo']:
   e=terminal(proto);f={'exit.json':enc(e)}
   if variant=='invalid':f['exit.witness']=b'{}'
   elif variant=='mismatch':f['exit.witness']=witness(e,exit_sha256='0'*64)
   elif variant=='symlink':f.update({'real-witness':witness(e),'exit.witness':('symlink','real-witness')})
   elif variant=='fifo':f['exit.witness']=('fifo',)
   add(tag+'-witness-'+variant,proto=proto,files=f)
  wrong=terminal('pty_v1' if proto=='captured_v1' else 'captured_v1')
  termcase(tag+'-protocol-mismatch',proto=proto,e=wrong)
 # Invalid capture is pending even for a legacy record.
 e=terminal(proto,capture={'stdout':stream(2,saved=3),'stderr':stream()},output_complete=False,output_durable=False)
 termcase(tag+'-capture-invalid',proto=proto,e=e)

for desc,data in [('final-cr',properties()+b'Extra=trailing\r'),('crlf',properties().replace(b'\n',b'\r\n')),('duplicate-last',b'ActiveState=failed\n'+properties()),('duplicate-mismatch',properties()+b'Description=foreign\n'),('lossy',properties()+b'Extra=\xff\xed\xa0\x80\xf0\x80\x80\x80\xc3\n'),('first-equals',properties()+b'=emptykey\nExtra=a=b=c\nignoredline\n')]:
 add('properties-'+desc,show=data)
add('properties-exit-failure-ignored',show_rc=17)
for proto in [None,'captured_v1','pty_v1']:
 e=terminal(proto);publish={'exit.json':b64(enc(e))}
 if proto:publish['exit.witness']=b64(witness(e))
 for name,show in [('ownership-error',properties(Description='foreign')),('missing-unit',b'LoadState=not-found\n'),('show-exit-failure',properties())]:
  add(('legacy' if proto is None else proto)+'-race-'+name,proto=proto,show=show,show_rc=9,publish=publish)
 add(('legacy' if proto is None else proto)+'-race-bind-atomic-failure',proto=proto,publish=publish,tmp_collision=True)
add('bind-atomic-failure',tmp_collision=True)

# Retained scratch is negative evidence; it never becomes terminal authority.
for proto in [None,'captured_v1','pty_v1']:
 tag='legacy' if proto is None else proto
 add(tag+'-retained-read',op='read',proto=proto,files={'engine-scratch.retained.json':enc(retained)})
 if proto:
  add(tag+'-retained-finalizing',proto=proto,show=properties('inactive'),files={'engine-scratch.retained.json':enc(retained)})
  add(tag+'-retained-reboot',proto=proto,record_changes={'boot_id':'old-boot'},files={'engine-scratch.retained.json':enc(retained)})
for field,value in [('schema','wrong'),('launch_nonce','wrong'),('device',-1),('device',1.0),('inode',18446744073709551615),('removed',True),('error',None)]:
 r=dict(retained);r[field]=value;add('retained-'+field+'-'+str(value),op='read',files={'engine-scratch.retained.json':enc(r)})
for name,raw in [('duplicate-valid',enc({**retained,'schema':'wrong'}).rstrip()[:-1]+b',"schema":"hepta.rea.engine-scratch-cleanup.v1"}'),('overflow',enc(retained).rstrip()[:-1]+b',"extra":1e400}'),('negative-zero',enc(retained).replace(b'"device":1',b'"device":-0')),('ignored-unknown',enc({**retained,'extra':{'nested':['ok',3.5]}}))]:
 add('retained-'+name,op='read',files={'engine-scratch.retained.json':raw})

binary=bytes(range(256))*80+b'\xe9\x9b\xaa\xf0\x9f\x98\x80\xe2\x82'
for limit in [0,1,2,3,16383,16384,16385,18446744073709551615]:
 add('read-limit-'+str(limit),op='read',files={'stdout.log':binary,'stderr.log':b'err\x00\xff'},request={'limit':limit})
for offset in [0,1,255,len(binary),len(binary)+1,18446744073709551615]:
 add('read-offset-'+str(offset),op='read',files={'stdout.log':binary,'stderr.log':b''},request={'stdout_offset':offset,'limit':19})
add('read-absent',op='read')
add('read-absent-cursor',op='read',request={'stdout_offset':1})
add('read-oversize-legacy-log',op='read',files={'stdout.log':('fill',16777217,b'x')},request={'stdout_offset':16777216})
for typ in [('symlink','target.log'),('directory',),('fifo',)]:
 add('read-log-'+typ[0],op='read',files={'stdout.log':typ,'target.log':b'x'})
for proto in [None,'pty_v1']:
 termcase('read-'+str(proto)+'-confirmed-no-scratch',op='read',proto=proto,e=terminal(proto,scratch_cleanup={'example':True}),files={'stdout.log':b'hello'})
e=terminal('captured_v1',capture={'stdout':stream(5),'stderr':stream(3)},output_complete=True,output_durable=True)
for kind,logs in [('valid',{'stdout.log':b'hello','stderr.log':b'err'}),('missing',{'stderr.log':b'err'}),('short',{'stdout.log':b'hell','stderr.log':b'err'}),('long',{'stdout.log':b'hello!','stderr.log':b'err'})]:
 termcase('read-captured-'+kind,op='read',proto='captured_v1',e=e,files=logs,request={'stdout_offset':1,'limit':2})
termcase('read-captured-zero-missing',op='read',proto='captured_v1')
termcase('read-captured-zero-files',op='read',proto='captured_v1',files={'stdout.log':b'','stderr.log':b''})
e=terminal('captured_v1',capture={'stdout':stream(eof=False),'stderr':stream()},output_complete=False,output_durable=False)
termcase('captured-incomplete-exit-zero',proto='captured_v1',e=e)
termcase('legacy-observes-upgraded',record_proto=None,proto='captured_v1')
add('data-directory-is-file',record_changes={'boot_id':'old-boot'},data_file=True)

for state in ['active','activating','deactivating','failed','inactive','']:
 add('cancel-'+state,op='cancel',show=properties(state))
add('cancel-notfound',op='cancel',show=b'LoadState=not-found\n')
add('cancel-bound',op='cancel',record_changes={'invocation_id':'b'*32})
add('cancel-reboot',op='cancel',record_changes={'boot_id':'old-boot'})
add('cancel-foreign',op='cancel',show=properties(Description='foreign'))
add('cancel-incarnation',op='cancel',record_changes={'invocation_id':'old'})
add('cancel-stop-error',op='cancel',stop_rc=3)
add('cancel-bind-atomic-error',op='cancel',tmp_collision=True)
termcase('cancel-terminal-does-not-bypass-stop',op='cancel',proto='pty_v1')

# Typed unknown metadata is deliberately more permissive than Value decoding.
for label,fragment in [('surrogate',b'"\\ud800"'),('invalid-utf8',b'"\xff"'),('deep',b'['*2048+b'0'+b']'*2048),('huge-number',b'9'*4301),('overflow',b'1e400')]:
 raw=enc(receipt).rstrip()[:-1]+b',"unknown":'+fragment+b'}\n'
 add('typed-exit-unknown-'+label,files={'exit.json':raw})

# Value recursion budget includes the enclosing typed Exit map. Width remains
# governed by the original one-MiB file budget, not the MCP request node cap.
for depth in [125,126,127,128]:
 raw=enc(receipt).rstrip()[:-1]+b',"scratch_cleanup":'+b'['*depth+b'0'+b']'*depth+b'}\n'
 add('scratch-value-depth-'+str(depth),files={'exit.json':raw})
 raw=enc(retained).rstrip()[:-1]+b',"extra":'+b'['*depth+b'0'+b']'*depth+b'}\n'
 add('retained-value-depth-'+str(depth),op='read',files={'engine-scratch.retained.json':raw})
prefix=enc(receipt).rstrip()[:-1]+b',"scratch_cleanup":['
n=(1048576-len(prefix)-3)//2
raw=prefix+b'0,'*(n-1)+b'0]}\n'
assert len(raw)<=1048576 and n>500000
add('scratch-value-full-width',files={'exit.json':raw})
prefix=enc(retained).rstrip()[:-1]+b',"extra":['
n=(1048576-len(prefix)-3)//2
raw=prefix+b'0,'*(n-1)+b'0]}\n'
assert len(raw)<=1048576 and n>500000
add('retained-value-full-width-read',op='read',files={'engine-scratch.retained.json':raw})
add('retained-value-full-width-properties',proto='pty_v1',show=properties('inactive'),files={'engine-scratch.retained.json':raw})

# These wire arrays are accepted by the unchanged original derive visitors.
for proto in (None,'captured_v1','pty_v1'):
 e=terminal(proto);raw=enc([e.get(k) for k in ('job_id','nonce','exit_code','timed_out','cancelled','at_unix_ms','terminal_protocol','output_complete','output_durable','capture','scratch_cleanup')]);files={'exit.json':raw}
 if proto:files['exit.witness']=enc([identity,nonce,proto,sha256(raw).hexdigest()])
 add('sequence-terminal-'+str(proto),proto=proto,files=files)
 for count in (5,6,7,10,11,12):
  raw=enc(([e.get(k) for k in ('job_id','nonce','exit_code','timed_out','cancelled','at_unix_ms','terminal_protocol','output_complete','output_durable','capture','scratch_cleanup')]+[0])[:count]);files={'exit.json':raw}
  if proto:files['exit.witness']=witness(e,raw=raw)
  add('sequence-exit-'+str(proto)+'-'+str(count),proto=proto,files=files)
e=terminal('captured_v1');e['capture']=[[0,0,True,False,False,None,None,None,True]]*2
raw=enc(e);add('sequence-capture-stream',proto='captured_v1',files={'exit.json':raw,'exit.witness':witness(e,raw=raw)})
add('retained-Value-array-is-invalid',op='read',files={'engine-scratch.retained.json':enc(list(retained.values()))})

record_fields=('job_id','unit','request_digest','boot_id','nonce','invocation_id','launch_state','created_unix_ms','terminal_protocol')
for count in (7,8,9,10):
 add('record-sequence-'+str(count))
 cases[-1]['record_bytes']=enc(([cases[-1]['record'].get(k) for k in record_fields]+[0])[:count])
for count in range(16):
 add('request-sequence-'+str(count))
 cases[-1]['request']=(['status',identity,'',[],None,{},None,None,None,None,None,0,0,None,0])[:count]
for op in ('read','cancel'):
 add('request-full-sequence-'+op,op=op)
 cases[-1]['request']=[op,identity,'',[],None,{},None,None,None,None,None,0,0,None]

program=Q/'systemctl-fixture'
program.write_text('''#!/usr/bin/python3
import base64,json,os,sys
from pathlib import Path
p=Path(os.environ['HIA_JOBCTL_QA_FACTS']);c=json.loads(p.read_text())
with (p.parent/'calls.jsonl').open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
show=sys.argv[1]=='show'
if show:
 if c.get('tmp_collision'):
  q=Path('/var/lib/hepta-runtime-jobctl/native-observe')/('record.tmp-'+str(os.getppid()));q.mkdir()
 for n,b in c.get('publish',{}).items():(Path('/var/lib/hepta-job-native-observe')/n).write_bytes(base64.b64decode(b))
os.write(1,base64.b64decode(c['show'] if show else c.get('stop','')))
os.write(2,b'host observation fixture\\n')
sys.exit(c['show_rc'] if show else c['stop_rc'])
''');program.chmod(0o755)
def mount(source,target):subprocess.run(['/usr/bin/mount','--bind',str(source),str(target)],check=True,capture_output=True)
def unmount(target):subprocess.run(['/usr/bin/umount',str(target)],check=True,capture_output=True)
mount(program,'/usr/bin/systemctl')
results=[]
status={'phase':'running','started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'case_count':len(cases),'cases':results,'namespace':namespace,'native_sha256':args.native_sha256,'oracle_sha256':args.oracle_sha256,'original_source_sha256':original_sha,'scope':'STATUS/READ/CANCEL acceptance, JSON values, fixed command observations, persisted Record/tree and exact stderr bytes; complete systemd/supervisor qualification is separate'}
def save():(Q/'qualification.json').write_text(json.dumps(status,indent=2)+'\n')
save()
def run(c,label,exe):
 root=Q/c['name']/label;root.mkdir(parents=True)
 varlib=root/'varlib';reg=varlib/'hepta-runtime-jobctl'/identity;reg.mkdir(parents=True)
 rbytes=c.get('record_bytes',enc(c['record']));(reg/'record.json').write_bytes(rbytes)
 data=varlib/('hepta-job-'+identity)
 if c.get('data_file'):data.write_bytes(b'x')
 else:
  data.mkdir()
  for name,value in c['files'].items():
   p=data/name
   if isinstance(value,tuple):
    if value[0]=='symlink':p.symlink_to(value[1])
    elif value[0]=='directory':p.mkdir()
    elif value[0]=='fifo':os.mkfifo(p)
    elif value[0]=='fill':
     with p.open('wb') as f:
      f.write(value[2]);f.truncate(value[1]);f.seek(value[1]-1);f.write(value[2][:1])
   else:p.write_bytes(value)
 facts={k:c[k] for k in ['show_rc','stop_rc']};facts['show']=b64(c['show'])
 for k in ['publish','tmp_collision']:
  if k in c:facts[k]=c[k]
 (root/'facts.json').write_text(json.dumps(facts))
 env={'PATH':'','HIA_JOBCTL_QA_FACTS':str(root/'facts.json'),'LC_ALL':'C.UTF-8'}
 mount(varlib,'/var/lib')
 try:
  child=subprocess.Popen([str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
  try:stdout,stderr=child.communicate(enc(c['request']),timeout=20)
  except subprocess.TimeoutExpired:
   os.killpg(child.pid,signal.SIGKILL);child.communicate();raise
  p=subprocess.CompletedProcess([str(exe)],child.returncode,stdout,stderr)
 finally:unmount('/var/lib')
 (root/'stdout').write_bytes(p.stdout);(root/'stderr').write_bytes(p.stderr)
 q={'stderr_sha256':sha256(p.stderr).hexdigest(),'rc':p.returncode,'stdout_sha256':sha256(p.stdout).hexdigest(),'stderr':p.stderr.decode(errors='replace'),'calls':[]}
 if (root/'calls.jsonl').exists():q['calls']=[json.loads(l) for l in (root/'calls.jsonl').read_text().splitlines()]
 if p.returncode==0:q['value']=json.loads(p.stdout)
 else:assert not p.stdout,(c['name'],label,'partial failure output',p.stdout)
 q['record']=json.loads((reg/'record.json').read_bytes())
 q['record_raw_sha256']=sha256((reg/'record.json').read_bytes()).hexdigest()
 q['files']=sorted(p.name.split('.tmp-')[0]+'.tmp-PID' if '.tmp-' in p.name else p.name for p in reg.iterdir())
 (root/'result.json').write_text(json.dumps(q,ensure_ascii=True,indent=2)+'\n')
 return q
try:
 for i,c in enumerate(cases):
  o=run(c,'original',oracle);n=run(c,'native',native)
  row={'name':c['name'],'original_rc':o['rc'],'native_rc':n['rc'],'calls':len(o['calls'])}
  checks={'exact_stderr':o['stderr_sha256']==n['stderr_sha256'],'acceptance':(o['rc']==0)==(n['rc']==0),'response':json.dumps(o.get('value'),sort_keys=True)==json.dumps(n.get('value'),sort_keys=True),'commands':o['calls']==n['calls'],'record':o['record']==n['record'],'retained_files':o['files']==n['files']}
  row['checks']=checks;row['pass']=all(checks.values());results.append(row);save()
  if not row['pass']:
   status['phase']='mismatch';save();print('MISMATCH',i,c['name'],checks,str(Q/c['name']),flush=True);raise AssertionError((c['name'],checks))
  if i%20==0:print('PASS',i+1,'/',len(cases),c['name'],flush=True)
 else:
  assert sha256(native.read_bytes()).hexdigest()==args.native_sha256
  assert sha256(oracle.read_bytes()).hexdigest()==args.oracle_sha256
  assert sha256(args.original_source.read_bytes()).hexdigest()==original_sha
  status['phase']='passed';save();print('OBSERVATION PASS',len(cases),flush=True)
except BaseException:
 if status['phase']!='mismatch':status['phase']='failed'
 status['error']=traceback.format_exc();save();raise
finally:unmount('/usr/bin/systemctl')
