from pathlib import Path
import sys,json,hashlib,io,os,time
payload=json.load(sys.stdin)
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
raw=payload['driver'].encode()
assert {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}==payload['driver_pin']
assert payload['driver_pin']['sha256']=='f4c38c5bebd64a1e1e3f157b40e8500949a8a4e19a7d0ac6b9073aa4260fd4b0'
assert len(payload['all_source_pins'])==102
for name,pin in payload['all_source_pins'].items():
 path=root/name
 assert path.resolve(strict=True)==path and not path.is_symlink()
 content=path.read_bytes()
 assert len(content)==pin['bytes'] and hashlib.sha256(content).hexdigest()==pin['sha256'],name
assert "out=data/'isolated-current-v2-full-unselected';out.mkdir(mode=0o700)" in payload['driver']
record=data/'isolated-current-v2-recovery-link.json'
with record.open('x') as stream:json.dump({'schema':'hepta.hia.bootstrap-unknown-launch-safe-continuation.v1','time_ns':time.time_ns(),'all_102_inputs_matched':True,'original_unknown_preserved':True,'same_output_atomic_gate_preserved':True,'original_payload':payload,'whole_native_stack_qualified':False},stream,sort_keys=True,indent=2);stream.write('\n')
print(json.dumps({'event':'unknown_launch_safe_continuation_verified','original_job_id':payload['original_job_id'],'all_input_count':102,'driver':payload['driver_pin'],'unchanged_atomic_output':'isolated-current-v2-full-unselected'},sort_keys=True),flush=True)
sys.stdin=io.StringIO(payload['original_stdin'])
exec(compile(payload['driver'],'<preserved-original-55fa-driver>','exec'),{'__name__':'__main__'})
