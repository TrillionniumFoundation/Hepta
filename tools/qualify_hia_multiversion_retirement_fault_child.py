from pathlib import Path
import ctypes,os,json,struct,sys
from tools.qualify_hia_multiversion_retirement import Pair,original_summary,native_summary,get,NONE
D=Path(sys.argv[1]);image=Path(sys.argv[2]);mode=sys.argv[3];name=sys.argv[4];out=Path(sys.argv[5])
pair=Pair(D/('fault-'+name),image);pair.load()
rows=[];reused=[]
def attempt():
    if mode=='original':
        pair.reference.attempt();return original_summary(pair.reference)
    raw=struct.pack('<8sQQ',b'HIAMVRT1',1,7);s=ctypes.create_string_buffer(raw)
    rc=pair.ret(s,len(raw),pair.out,768,pair.f.work,len(pair.f.work));assert rc==0,(rc,get(pair.out,64))
    return native_summary(pair.out)
os.write(2,b'RETIRE_BEGIN\n')
row=attempt();rows.append(row)
# Force kernel number reuse only after the actual owner has reported an
# uncertain close. This independent adversarial fixture never grants the
# product a second close right.
if row['fd']=='unknown':
    fd=pair.reference.fd if mode=='original' else get(pair.f.work,48)
    os.close(fd);source=os.open('/dev/null',os.O_RDONLY)
    if source!=fd:os.dup2(source,fd);os.close(source)
    reused.append(fd)
if row['pin_close']=='unknown':
    fd=pair.reference.identity_pin.fd if mode=='original' else get(pair.f.work,32)
    os.close(fd);source=os.open('/dev/null',os.O_RDONLY)
    if source!=fd:os.dup2(source,fd);os.close(source)
    reused.append(fd)
path=pair.original_path if mode=='original' else pair.native_path
if path.exists() or path.is_symlink():path.unlink()
os.write(2,b'RETIRE_RETRY\n')
rows.append(attempt())
for fd in reused:os.fstat(fd)
os.write(2,b'RETIRE_END\n')
out.write_text(json.dumps({'snapshots':rows,'reused_fd_survived':len(reused)},sort_keys=True)+'\n')
