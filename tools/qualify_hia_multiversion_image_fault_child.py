"""One real native/original loading operation for external syscall injection."""
from pathlib import Path
import sys,ctypes,os,struct,json,hashlib,_ctypes
from tools.qualify_hia_multiversion_image import Fixture
from tools.qualify_hia_multiversion_components import get
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
D=Path(sys.argv[1]);mode=sys.argv[2];path=Path(sys.argv[3]);out=Path(sys.argv[4])
f=Fixture(D,B/'native-multiversion-components-v5',B/'native-multiversion-call-v5',B/'native-multiversion-call-v5')
raw=(f.artifacts/'all-types.core.json').read_bytes();abi=f.make_abi(raw)
data=path.read_bytes();digest=hashlib.sha256(data).digest()
before=set(os.listdir('/proc/self/fd'))
os.write(2,b'IMAGE_BEGIN\n')
if mode=='original':
    ok=f.reference(os.fsencode(path),abi,len(data),digest);row={'accepted':ok}
else:
    packet=struct.pack('<8sQQQ',b'HIAMVI01',len(os.fsencode(path)),len(abi),len(data))+digest+os.fsencode(path)+abi
    source=ctypes.create_string_buffer(packet);rc=f.entry(source,len(packet),f.out,512,f.work,len(f.work))
    row={'accepted':rc==0,'rc':rc,'phase':get(f.work,0),'raw_errno':get(f.out,16),'native_library_held':bool(get(f.out,40))}
    if f.out.raw[:8]==b'HIAMVIR1':
        handle=get(f.out,40);fd=get(f.out,32);pinfd=get(f.out,24)
        if handle:_ctypes.dlclose(handle)
        if fd!=(1<<64)-1:os.close(fd)
        if pinfd!=(1<<64)-1 and get(f.out,128)==0:os.close(pinfd)
os.write(2,b'IMAGE_END\n')
after=set(os.listdir('/proc/self/fd'));row['fd_balanced']=before==after
out.write_text(json.dumps(row,sort_keys=True)+'\n')
assert before==after,(before,after)
