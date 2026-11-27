"""Actual stdio and HTTP parallel metadata calls through native private replies.

The observer holds the original legacy exchange byte, observes bounded native
groups read-only, and checks original per-request results. It never edits native
state or substitutes an executable. Setup uses a private retained fixture.
"""
from __future__ import annotations
import argparse,concurrent.futures,fcntl,gzip,json,os,select,signal,threading,time
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from tools.qualify_hia_mcp_request_archive_public import ArchiveSession,audit_child
from tools.qualify_hia_mcp_metadata_http import HTTP,encoded,rpc,events,descendants
from tools.qualify_hia_mcp_request_archive import seed_archive,DEADLINE
from tools.qualify_hia_mcp_request_history import record,snapshot
from tools.qualify_hia_mcp_metadata_batch import page,usage
from tests.hia_metadata_batch_native_support import NativeState

def tool_result(response,ident):
 assert response.get('id')==ident,response
 value=response.get('result',{})
 assert value.get('isError') is False,response
 content=value.get('content');assert len(content)==1 and content[0]['type']=='text',value
 return {'status':0,'value':json.loads(content[0]['text']),'text':content[0]['text']}

def deadline_result(response,ident):
 assert response.get('id')==ident and response['result']['isError'] is True,response
 assert response['result']['content']==[{'type':'text','text':DEADLINE}],response

def stdio_read(session,label):
 connection=session.connection;until=time.monotonic()+8
 while b'\n' not in connection.pending:
  remaining=until-time.monotonic();assert remaining>0
  assert select.select([connection.process.stdout],[],[],remaining)[0]
  raw=os.read(connection.process.stdout.fileno(),65536);assert raw
  connection.pending.extend(raw)
 line,_,tail=connection.pending.partition(b'\n');connection.pending=bytearray(tail)
 (session.directory/(label+'.response.gz')).write_bytes(gzip.compress(line+b'\n',mtime=0))
 return json.loads(line)

def stdio_call(session,tool,args,ident):
 raw=encoded({'jsonrpc':'2.0','id':ident,'method':'tools/call','params':{'name':tool,'arguments':args}})+b'\n'
 (session.directory/(ident+'.input.bin')).write_bytes(raw)
 session.connection.process.stdin.write(raw);session.connection.process.stdin.flush()
 return stdio_read(session,ident)

def private_lease(pid):
 found=[]
 for entry in Path(f'/proc/{pid}/fd').iterdir():
  try:
   if 'memfd:' in os.readlink(entry) and entry.stat().st_size==2<<20:found.append(entry)
  except FileNotFoundError:continue
 assert len(found)==1,found
 fd=os.open(found[0],os.O_RDWR|os.O_CLOEXEC)
 assert fcntl.fcntl(fd,1034)==7
 return fd

def stop(pid):
 os.kill(pid,signal.SIGSTOP);until=time.monotonic()+1
 while 'State:\tT' not in Path(f'/proc/{pid}/status').read_text():
  assert time.monotonic()<until;time.sleep(.001)

class Samples:
 def __init__(self,pid):
  self.view=NativeState(SimpleNamespace(proc=SimpleNamespace(pid=pid)))
  self.ended=threading.Event();self.rows=[];self.errors=[]
  def read():
   try:
    last=None
    while not self.ended.is_set():
     row=self.view.get()
     key=tuple(row[k] for k in ['active','count','kind','frozen','sealed'])
     if row['active'] and key!=last:
      assert 0<=row['count']<=8,row
      if row['count']:
       self.rows.append(row);last=key
     self.ended.wait(.0002)
   except BaseException as e:self.errors.append(repr(e))
  self.thread=threading.Thread(target=read);self.thread.start()
 def close(self,path):
  self.ended.set();self.thread.join();self.view.close()
  path.write_text(json.dumps({'snapshots':self.rows,'errors':self.errors,'atomic_snapshot':False},indent=2)+'\n')
  assert not self.errors,self.errors
  return {'observed_groups':len(self.rows),'maximum_observed_members':max((r['count'] for r in self.rows),default=0)}

def check_queries(results,queries,rows,owner):
 assert set(results)=={q['id'] for q in queries},results.keys()
 for q in queries:
  value=tool_result(results[q['id']],q['id'])
  if q['tool']=='usage_stats':usage(value,rows,owner)
  else:page(value,rows,owner,q['args'].get('limit',32),q['args'].get('after_id'))

def qualify(bundle,http_bundle,output):
 output.mkdir(mode=0o700,parents=True,exist_ok=False)
 report={'schema':'hepta.hia.metadata-batch-public.v1','passed':False,'checks':[],
  'service_sha256':sha256((bundle/'hia-mcp-service').read_bytes()).hexdigest(),
  'http_sha256':sha256((http_bundle/'hia-mcp-http').read_bytes()).hexdigest(),
  'whole_cold_qualified':False,'installed_worker_claimed':False,'query_budget_seconds':3,
  'maximum_members':8,'original_archive_window_ns':2000000,'original_usage_window_ns':1000000}
 session=server=None
 def save():(output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(name,**values):
  report['checks'].append({'case':name,'passed':True,**values});save();print('NATIVE_METADATA_BATCH_PUBLIC_PASS',name,flush=True)
 try:
  session=ArchiveSession(bundle,output/'stdio')
  owner=session.owner()
  for folder in ('request-audit','request-archive-v11'):
   files=list((session.state/folder).glob('*.json'));assert len(files)==1
   current=json.loads(files[0].read_bytes());assert current['owner']==owner and current['state']=='failed'
   files[0].unlink()
  rows=[record(i+1,accepted=i+1,owner=('b'*64 if i%4==0 else owner),
               state=['completed','failed','unknown'][i%3],elapsed=None if i%3==2 else 1) for i in range(16385)]
  seed_archive(session.state,rows)
  (output/'stdio-fixture.json.gz').write_bytes(gzip.compress(encoded(rows),mtime=0))
  page(tool_result(stdio_call(session,'request_archive',{},'stdio-warm-archive'),'stdio-warm-archive'),rows,owner)
  usage(tool_result(stdio_call(session,'usage_stats',{},'stdio-warm-usage'),'stdio-warm-usage'),rows,owner)
  pid=audit_child(session);lease=private_lease(pid);before=snapshot(session.state)
  selected=[r for r in rows if r['owner']==owner]
  for tool in ('request_archive','usage_stats'):
   queries=[{'id':'stdio-'+tool+'-'+str(i),'tool':tool,'args':({'limit':i+1} if tool=='request_archive' else {})} for i in range(8)]
   if tool=='request_archive':queries[2]['args']['after_id']=selected[40]['request_id']
   raw=b''.join(encoded({'jsonrpc':'2.0','id':q['id'],'method':'tools/call','params':{'name':q['tool'],'arguments':q['args']}})+b'\n' for q in queries)
   (session.directory/(tool+'.parallel.input.bin')).write_bytes(raw)
   monitor=Samples(pid);started=time.monotonic()
   fcntl.lockf(lease,fcntl.LOCK_EX|fcntl.LOCK_NB,1,1,os.SEEK_SET)
   try:
    session.connection.process.stdin.write(raw);session.connection.process.stdin.flush()
    results={}
    for i in range(8):
     response=stdio_read(session,tool+'-'+str(i));assert response['id'] not in results
     results[response['id']]=response
    check_queries(results,queries,rows,owner)
   finally:
    fcntl.lockf(lease,fcntl.LOCK_UN,1,1,os.SEEK_SET)
    observed=monitor.close(session.directory/(tool+'.group-samples.json'))
   assert snapshot(session.state)==before
   passed('stdio-eight-'+tool+'-while-legacy-exchange-locked',seconds=time.monotonic()-started,**observed)
  os.close(lease)
  history=stdio_call(session,'request_history',{},'history-after-parallel')
  assert tool_result(history,'history-after-parallel')['value']['requests']==[]
  passed('original-history-exchange-still-independent-after-private-cohorts')
  retained=session.state;session.close();session=None
  # A distinct authenticated HTTP owner opens the same retained originals.
  # Its real failed admission is the only row visible to that owner.
  server=HTTP(http_bundle,output/'http',state=retained);server.initialize()
  response,raw=server.exchange(server.call('hia_describe',{'unexpected':True},'http-owner-probe'),label='owner-probe')
  value=rpc(raw);assert response['status']==200 and value.get('error',{}).get('code')==-32602,value
  hot=list((retained/'request-audit').glob('*.json'));assert len(hot)==1,hot
  admitted=json.loads(hot[0].read_bytes());http_owner=admitted['owner']
  assert http_owner!=owner and http_owner!='b'*64 and admitted['state']=='failed',admitted
  rows.append(admitted)
  pids=[p for p in descendants(server.process.pid) if Path(f'/proc/{p}/cmdline').read_bytes()==b'hia-mcp-request-audit\0']
  assert len(pids)==1,pids
  pid=pids[0];lease=private_lease(pid)
  for tool in ('request_archive','usage_stats'):
   response,raw=server.exchange(server.call(tool,{},'warm-'+tool),label='warm-'+tool)
   check_queries({'warm-'+tool:rpc(raw)},[{'id':'warm-'+tool,'tool':tool,'args':{}}],rows,http_owner)
  before=snapshot(retained)
  def parallel(queries,label):
   barrier=threading.Barrier(len(queries))
   def execute(q):
    body=server.call(q['tool'],q['args'],q['id']);barrier.wait(timeout=5)
    meta,raw=server.exchange(body,label=q['id']);assert meta['status']==200,(meta,raw[:1024])
    return q['id'],rpc(raw)
   with concurrent.futures.ThreadPoolExecutor(max_workers=len(queries)) as pool:
    futures=[pool.submit(execute,q) for q in queries]
    return dict(f.result(timeout=8) for f in futures)
  for tool in ('request_archive','usage_stats'):
   queries=[{'id':'http-'+tool+'-'+str(i),'tool':tool,'args':({'limit':i+1} if tool=='request_archive' else {})} for i in range(8)]
   monitor=Samples(pid);started=time.monotonic()
   fcntl.lockf(lease,fcntl.LOCK_EX|fcntl.LOCK_NB,1,1,os.SEEK_SET)
   try:check_queries(parallel(queries,tool),queries,rows,http_owner)
   finally:
    fcntl.lockf(lease,fcntl.LOCK_UN,1,1,os.SEEK_SET)
    observed=monitor.close(server.directory/(tool+'.group-samples.json'))
   assert snapshot(retained)==before
   passed('http-eight-'+tool+'-private-owner-and-independent-replies',seconds=time.monotonic()-started,**observed)
  # Every expired private peer is closed independently. Resuming the same
  # daemon must consume the old packets without poisoning a new generation.
  queries=[{'id':'http-timeout-'+str(i),'tool':'usage_stats','args':{}} for i in range(8)]
  stop(pid);started=time.monotonic()
  try:
   results=parallel(queries,'timeouts')
   for q in queries:deadline_result(results[q['id']],q['id'])
   elapsed=time.monotonic()-started;assert 2.5<=elapsed<4.5,elapsed
  finally:os.kill(pid,signal.SIGCONT)
  response,raw=server.exchange(server.call('usage_stats',{},'fresh-after-eight-timeouts'),label='fresh-after-eight-timeouts')
  check_queries({'fresh-after-eight-timeouts':rpc(raw)},[{'id':'fresh-after-eight-timeouts','tool':'usage_stats','args':{}}],rows,http_owner)
  assert snapshot(retained)==before
  passed('eight-original-http-deadlines-close-private-peers-and-fresh-generation-recovers',seconds=elapsed)
  os.close(lease);server.close();server=None
  report.update(passed=True,passed_checks=len(report['checks']));save();return report
 finally:
  if session is not None:session.close()
  if server is not None:server.close()
  save()

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('bundle','http-bundle','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();r=qualify(a.bundle.resolve(),a.http_bundle.resolve(),a.output.resolve())
 print(json.dumps({'passed':r['passed'],'checks':len(r['checks'])}))

if __name__=='__main__':main()
