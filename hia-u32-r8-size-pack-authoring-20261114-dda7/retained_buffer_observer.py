from pathlib import Path
import hashlib,json,os,signal,subprocess,sys,time
def sha(raw): return hashlib.sha256(raw).hexdigest()
def dump(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def native(folder,image,source,output,workspace,stdin,mode):
 folder.mkdir();buffers=[];guard=b'\xD3'*64
 for label,value in [('source',source),('output',output),('workspace',workspace)]:
  path=folder/(label+'.shared');raw=guard+value+guard;path.write_bytes(raw);buffers.append({'path':str(path),'bytes':len(raw),'sha256':sha(raw),'extent':len(value)})
 request={'schema':'hia.linux-stdio.native-request.v1','image':str(image),'image_sha256':sha(image.read_bytes()),'buffers':buffers,'mode':mode,'report':str(folder/'CHILD-REPORT.json')}
 raw=(json.dumps(request,sort_keys=True)+'\n').encode();request_path=folder/'request.json';request_path.write_bytes(raw);(folder/'stdin.bin').write_bytes(stdin)
 command=[sys.executable,'-I','-S','-B',str(Path(__file__).with_name('retained_buffer_child.py')),str(request_path),sha(raw)]
 t=time.perf_counter();timed_out=False
 with (folder/'stdin.bin').open('rb') as input_,(folder/'stdout.bin').open('wb') as out,(folder/'stderr.bin').open('wb') as err:
  child=subprocess.Popen(command,stdin=input_,stdout=out,stderr=err,start_new_session=True)
  try:rc=child.wait(timeout=20)
  except subprocess.TimeoutExpired:timed_out=True;os.killpg(child.pid,signal.SIGKILL);rc=child.wait(timeout=3)
  consumed=input_.tell()
 elapsed=time.perf_counter()-t;data=[];canaries=[]
 for row in buffers:
  got=Path(row['path']).read_bytes();assert len(got)==row['bytes'];canaries.append(got[:64]==guard and got[-64:]==guard);data.append(got[64:-64])
 observed={'returncode':rc,'timed_out':timed_out,'wall_seconds':elapsed,'timeout_seconds':20,'cleanup_seconds':3,'stdin_consumed':consumed,'stdout_hex':(folder/'stdout.bin').read_bytes().hex(),'stderr_hex':(folder/'stderr.bin').read_bytes().hex(),'source_hex':data[0].hex(),'output_hex':data[1].hex(),'workspace_hex':data[2].hex(),'canaries':canaries,'child':json.loads((folder/'CHILD-REPORT.json').read_text()) if (folder/'CHILD-REPORT.json').exists() else None}
 dump(folder/'OBSERVATION.json',observed);return observed
