"""Actual outer-intake deadline/cancellation and descriptor custody controls."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,threading,time,fcntl
from tools.qualify_hia_multiversion_prepare_intake import Intake,packet,get
from tools.qualify_hia_multiversion_prepare_process import sealed

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);a=p.parse_args();D=a.directory;native=Intake(D/'prepare-intake-component.so');image=a.fixture.read_bytes();fd=sealed(image);rows=[]
    def reap():
        pid,yes=struct.unpack('<2Q',C.string_at(C.addressof(native.w)+56*(1<<20)+88,16))
        assert pid>0 and yes==1,(pid,yes)
        try:os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:pass
        else:raise AssertionError('child not reaped')
        return pid
    raw=struct.pack('<4Q',2,10000,0,0)
    rc,out,_,elapsed=native.run(packet(raw,fd,deadline=time.monotonic_ns()+100_000_000));assert rc==7 and get(out,16)==1 and elapsed<1_000_000_000;pid=reap();rows.append({'case':'deadline-actual-running-normalizer','status':rc,'child_pid':pid,'reaped':True,'elapsed_ns':elapsed})
    token=C.c_uint64(0)
    def later():time.sleep(.06);token.value=1
    t=threading.Thread(target=later);t.start();rc,out,_,elapsed=native.run(packet(raw,fd,cancel=C.addressof(token)));t.join();assert rc==7 and get(out,16)==2;pid=reap();rows.append({'case':'cancel-actual-running-normalizer','status':rc,'child_pid':pid,'reaped':True,'elapsed_ns':elapsed})
    # A complete but untrusted payload cannot bypass the full HIAVCF/primitive checks.
    for label,payload in [('empty',b''),('foreign',b'not-a-verified-Core-frame'),('short',b'HIAVCF01'+bytes(55)),('tail',struct.pack('<8s7Q',b'HIAVCF01',0,0,0,1,1,0,0)+b'{}junk')]:
        raw=struct.pack('<4Q',0,0,0,0)+payload;rc,out,_,_=native.run(packet(raw,fd));assert rc==8 and get(out,248)==2,(label,rc,get(out,248));rows.append({'case':'untrusted-normalizer-'+label,'status':rc})
    os.close(fd)
    for label,body,mode,seal in [('unsealed',image,0o500,0),('nonexec',image,0o600,15),('bad-ELF',b'bad',0o500,15),('empty-image',b'',0o500,15)]:
        other=sealed(body,mode,seal);rc,out,_,_=native.run(packet(b'{}',other));assert rc==7 and get(out,248)==2,(label,rc);os.fstat(other);os.close(other);rows.append({'case':label,'status':rc})
    for label,other in [('regular-file',os.open(a.fixture,os.O_RDONLY)),('directory',os.open(D,os.O_RDONLY|os.O_DIRECTORY))]:
        rc,out,_,_=native.run(packet(b'{}',other));assert rc==7 and get(out,248)==2;os.fstat(other);os.close(other);rows.append({'case':label,'status':rc})
    r,w=os.pipe()
    try:rc,out,_,_=native.run(packet(b'{}',r));assert rc==7
    finally:os.close(r);os.close(w)
    rows.append({'case':'pipe-capability','status':rc})
    report={'schema':'hepta.hia.multiversion-prepare-intake.lifetime.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'image_sha256':hashlib.sha256((D/'prepare-intake-component.so').read_bytes()).hexdigest(),'cases':rows}
    (D/'lifetime-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PREPARE_INTAKE_LIFETIME_PASS',len(rows),flush=True)
if __name__=='__main__':main()
