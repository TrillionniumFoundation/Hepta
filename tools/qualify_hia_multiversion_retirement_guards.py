"""Actual same-holder retirement refusal/fork/corrupted-owner guards."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,struct
from tools.qualify_hia_multiversion_probe_owner import Probe
from tools.qualify_hia_multiversion_components import get,put,sha
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--probe-directory',type=Path,required=True);p.add_argument('--retirement-directory',type=Path,required=True);a=p.parse_args();D=a.directory;D.mkdir()
    os.symlink(a.probe_directory/'probe-component.so',D/'probe-component.so');q=Probe(D,B/'native-multiversion-image-v5',a.retirement_directory)
    raw=(q.artifacts/'all-types.core.json').read_bytes();data=(q.artifacts/'all-types.so').read_bytes();abi=q.f.make_abi(raw)
    before=set(os.listdir('/proc/self/fd'));q.loaded('guard-holder',data,abi)
    out=ctypes.create_string_buffer(768);rows=[]
    def call(packet,workspace=None):
        s=ctypes.create_string_buffer(packet);ctypes.memset(out,0xa5,768);w=workspace if workspace is not None else q.f.work
        rc=q.ret(s,len(packet),out,768,w,len(w));assert s.raw==packet+b'\0';return rc
    request=struct.pack('<8sQQ',b'HIAMVRT1',2,7)
    for name,packet in [('magic',b'BADMAGIC'+request[8:]),('short',request[:-1]),('tail',request+b'\0'),('zero-op',request[:8]+bytes(8)+request[16:]),('unknown-op',request[:8]+struct.pack('<Q',3)+request[16:])]:
        prior=q.f.work.raw[:8192];rc=call(packet);assert rc>=0xfffffff0 and out.raw==b'\xa5'*768 and q.f.work.raw[:8192]==prior
        rows.append({'case':name,'refused_before_effect':True})
    assert call(request)==0 and get(out,24)&2 and not get(out,24)&8
    prior=q.f.work.raw[:8192];assert call(request[:16]+struct.pack('<Q',8))>=0xfffffff0 and q.f.work.raw[:8192]==prior
    rows.append({'case':'wrong-generation','refused_before_effect':True})
    fds=(get(q.f.work,32),get(q.f.work,48));identities=[(os.fstat(x).st_dev,os.fstat(x).st_ino) for x in fds]
    rd,wr=os.pipe();pid=os.fork()
    if pid==0:
        os.close(rd);rc=call(struct.pack('<8sQQ',b'HIAMVRT1',1,7));valid=rc==65 and q.path.exists() and identities==[(os.fstat(x).st_dev,os.fstat(x).st_ino) for x in fds]
        os.write(wr,b'PASS' if valid else b'FAIL');os._exit(0 if valid else 1)
    os.close(wr);reply=os.read(rd,16);os.close(rd);_,status=os.waitpid(pid,0);assert reply==b'PASS' and status==0 and q.path.exists()
    rows.append({'case':'actual-fork-owner','refused_without_releasing_parent_holder':True})
    # Fault-injected private state copy shares the held handles but cannot gain
    # new release rights. The real, uncorrupted holder remains the sole owner.
    damaged=ctypes.create_string_buffer(len(q.f.work));ctypes.memmove(damaged,q.f.work,8<<20);damaged[(6<<20)+300]=bytes([damaged[(6<<20)+300][0]^1])
    for i in range(2):
        rc=call(struct.pack('<8sQQ',b'HIAMVRT1',1,7),damaged);assert rc==65 and get(out,56)==1 and get(damaged,4304)==0 and get(damaged,4320)==0
        assert q.path.exists() and identities==[(os.fstat(x).st_dev,os.fstat(x).st_ino) for x in fds]
    rows.append({'case':'bad-state-checksum','persistent_fence_no_release':True})
    q.retire();assert set(os.listdir('/proc/self/fd'))==before
    report={'schema':'hepta.hia.multiversion-retirement-private-guards.v1','passed':len(rows),'failed':0,'whole_native_runtime':False,'image_sha256':sha((a.retirement_directory/'retirement-component.so').read_bytes()),'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_RETIRE_GUARDS_PASS',len(rows),flush=True)
if __name__=='__main__':main()
