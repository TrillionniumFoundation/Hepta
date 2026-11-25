"""External QA worker for exact-PC transport fault injection; not a runtime role."""
from pathlib import Path
import os,sys,json,hashlib,struct,time
from tools.qualify_hia_multiversion_prepare_process import Process,sealed
D=Path(sys.argv[1]);target=Path(sys.argv[2]);flavor=sys.argv[3] if len(sys.argv)>3 else 'normal'
proc=Process(D/'process-component.so');fd=sealed((D/'child-fixture').read_bytes())
before=set(os.listdir('/proc/self/fd'))
n=4097 if flavor=='short' else 65537
data=struct.pack('<4Q',1,n,513,0)+b'a'*(8192 if flavor=='short' else 131072)
import ctypes as C
os.write(2,('MV_BEGIN '+format(C.c_void_p.from_buffer(proc.f).value,'x')+'\n').encode())
r=proc.run(fd,data,budget=10)
os.write(2,b'MV_END\n')
assert set(os.listdir('/proc/self/fd'))==before,'native transport leaked an owned descriptor'
if r['status']==0:
    assert r['stdout']==bytes(i%251 for i in range(n))
    assert r['stderr']==bytes(i%251 for i in range(513))
os.close(fd)
out={k:v for k,v in r.items() if k not in ('stdout','stderr')}
out['stdout_sha256']=hashlib.sha256(r['stdout']).hexdigest();out['stderr_sha256']=hashlib.sha256(r['stderr']).hexdigest()
target.write_text(json.dumps(out,indent=2)+'\n')

