"""Kernel syscall barriers for the actual native archive observation fence.

ptrace only stops this observer's own daemon at getdents64 after successful
inotify watch installation. No production instructions or responses are changed.
"""
from __future__ import annotations
import argparse
import ctypes
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import time

from tools.qualify_hia_mcp_request_archive import ArchiveAudit, seed_archive, UNAVAILABLE
from tools.qualify_hia_mcp_request_history import record, snapshot
from tests.hia_request_audit_native_support import good


class Barrier:
    def __init__(self,pid):
        self.pid=pid
        self.attached=False
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.ptrace.argtypes=[ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p]
        self.libc.ptrace.restype=ctypes.c_long

    def call(self,op,addr=0,data=0):
        result=self.libc.ptrace(op,self.pid,addr,data)
        if result==-1:
            error=ctypes.get_errno()
            raise OSError(error,os.strerror(error))
        return result

    def attach(self):
        self.call(16)
        self.attached=True
        pid,status=os.waitpid(self.pid,0)
        assert pid==self.pid and os.WIFSTOPPED(status)
        self.call(0x4200,0,1)  # Linux UAPI PTRACE_O_TRACESYSGOOD.

    def ready(self):
        info=ctypes.create_string_buffer(88)
        watches=0
        pending=False
        started=time.monotonic()
        for stops in range(4096):
            self.call(24)
            pid,status=os.waitpid(self.pid,0)
            assert pid==self.pid and os.WIFSTOPPED(status),status
            assert os.WSTOPSIG(status)==signal.SIGTRAP|0x80,status
            size=self.call(0x420e,len(info),ctypes.addressof(info))
            raw=info.raw
            assert size>=33 and struct.unpack_from('<I',raw,4)[0]==0xc000003e
            if raw[0]==1:
                syscall=struct.unpack_from('<Q',raw,24)[0]
                pending=syscall==254
                if syscall==217 and watches==2:
                    return {'syscall':'getdents64','successful_watches':watches,
                            'stops':stops+1,'barrier_seconds':time.monotonic()-started}
            elif raw[0]==2 and pending:
                assert struct.unpack_from('<q',raw,24)[0]>=0
                watches+=1
                pending=False
            assert time.monotonic()-started<2.0
        raise AssertionError('no complete-original scan boundary observed')

    def close(self):
        if self.attached:
            self.call(17)
            self.attached=False


def qualify(image,output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    checks=[]
    for label in ('content-restored-with-mtime','namespace-restored',
                  'foreign-owner-content-restored','unrelated-root-child'):
        directory=output/label
        directory.mkdir(mode=0o700)
        with ArchiveAudit(directory/'state',image,directory/'wire') as audit:
            good(audit.prepare());audit.lease(0)
            rows=[record(1),record(2,owner='b'*64)]
            seed_archive(audit.root,rows)
            before=snapshot(audit.root)
            path=audit.root/'request-archive-v11'/(rows[1 if label.startswith('foreign') else 0]['request_id']+'.json')
            barrier=Barrier(audit.proc.pid)
            barrier.attach()
            try:
                frame=audit.archive_frame()
                fcntl.lockf(audit.fd,fcntl.LOCK_EX,1,1,os.SEEK_SET)
                try:
                    assert audit.client.send(frame)==len(frame)
                    observation=barrier.ready()
                    if label=='namespace-restored':
                        held=path.with_suffix('.held')
                        path.rename(held);held.rename(path)
                    elif label=='unrelated-root-child':
                        unrelated=audit.root/'unrelated-observer-file'
                        unrelated.write_bytes(b'unrelated');unrelated.unlink()
                    else:
                        raw=path.read_bytes();stamp=path.stat()
                        path.write_bytes(b' '*len(raw));path.write_bytes(raw)
                        os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
                    barrier.close()
                    raw=audit.client.recv(64+65536+1)
                finally:
                    fcntl.lockf(audit.fd,fcntl.LOCK_UN,1,1,os.SEEK_SET)
                assert raw[:8]==b'HIARQO01'
                version,size,status,reason,slot,generation,reserved=struct.unpack_from('<7Q',raw,8)
                assert version==1 and size==len(raw) and reserved==0 and (slot,generation)==(0,1)
                if label=='unrelated-root-child':
                    assert status==0 and reason==0 and json.loads(raw[64:])['total']==1
                else:
                    assert status==1 and reason==38 and raw[64:].decode()==UNAVAILABLE
                assert snapshot(audit.root)==before
                (directory/'request.bin').write_bytes(frame)
                (directory/'response.bin').write_bytes(raw)
                checks.append({'case':label,'passed':True,'status':status,**observation})
                print('NATIVE_ARCHIVE_FENCE_PASS',label,flush=True)
            finally:
                barrier.close()
    report={'schema':'hepta.hia.request-archive-kernel-fence.v1','passed':True,'checks':checks,
            'audit_sha256':sha256(image.read_bytes()).hexdigest(),
            'scope':'actual kernel boundary controls; no original instruction or result replacement',
            'whole_cold_qualified':False}
    (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(qualify(args.audit.resolve(),args.output.resolve())))


if __name__=='__main__':
    main()
