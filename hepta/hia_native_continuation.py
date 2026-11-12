"""Explicit native scheduling with a hosted primitive peer.

HIA owns unit selection, internal handoffs, phase and frame extents. This peer
only transports HIA-selected foreign object effects and their results. The
low-level constructor is not installation or cold/source admission; no default
entry selects it. The executable must be an owned ordinary pinned file.
"""
from __future__ import annotations
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import time

from .hia_core_lowering_native import LoweringSession,_decode_pool,MAGIC,FRAME

EVENT=struct.Struct('<8Q')
EVENT_MAGIC=int.from_bytes(b'HIAIPC01','little')
MAX_EXECUTABLE=64<<20


def _identity(value):
    return tuple(getattr(value,n) for n in (
        'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_nlink'))


def _read_file(fd):
    before=os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
            or before.st_uid not in (0,os.getuid()) or before.st_mode&0o022
            or not before.st_mode&0o100 or not 0<before.st_size<=MAX_EXECUTABLE):
        raise ValueError('native continuation needs an owned bounded ordinary executable')
    os.lseek(fd,0,os.SEEK_SET)
    chunks=[];size=0
    while size<=MAX_EXECUTABLE:
        chunk=os.read(fd,min(65536,MAX_EXECUTABLE+1-size))
        if not chunk:break
        chunks.append(chunk);size+=len(chunk)
    after=os.fstat(fd)
    if _identity(before)!=_identity(after) or size!=before.st_size:
        raise ValueError('native continuation executable changed while captured')
    return b''.join(chunks),_identity(after)


class NativeContinuation:
    def __init__(self,path,expected_sha256,*,pool_bytes):
        self.path=Path(path)
        if not self.path.is_absolute():raise ValueError('absolute native continuation executable required')
        if type(expected_sha256) is not str or len(expected_sha256)!=64:
            raise ValueError('exact native continuation executable identity required')
        self.sha256=expected_sha256
        if type(pool_bytes) is not int or not 64<=pool_bytes<=1<<20:
            raise ValueError('bounded exact native continuation pool extent required')
        self.pool_bytes=pool_bytes

    def invoke(self,owner,name,arguments,*,timeout=None):
        mode=owner.modes[name]
        if len(arguments)!=mode['arity']:raise RuntimeError('native lowering bound argument count differs')
        return self.run(LoweringSession(owner,mode['number'],arguments),timeout=timeout)

    def run(self,session,*,timeout=None):
        if timeout is not None and (type(timeout) not in (int,float) or not 0<timeout<=60):
            raise ValueError('explicit native continuation deadline must be in (0,60] seconds')
        if session.finished or getattr(session,'_native_started',False):
            raise RuntimeError('native continuation session is already consumed')
        session._native_started=True
        # Ordinary selected owners retain their existing outer supervision;
        # this mechanical transport does not silently add a shorter wall cap.
        owner=session.owner;deadline=None if timeout is None else time.monotonic()+timeout
        fd=None
        process=None;captured=False;executable_fd=None
        try:
            fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
            raw,identity=_read_file(fd)
            if sha256(raw).hexdigest()!=self.sha256:raise ValueError('native continuation executable identity mismatch')
            captured=True
            # An ordinary inode can still be rewritten after it was checked.
            # Execute a fully sealed copy of exactly the admitted bytes, while
            # retaining all original ordinary-file custody checks before/after.
            executable_fd=os.memfd_create('hia-native-continuation',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            offset=0
            while offset<len(raw):
                written=os.write(executable_fd,raw[offset:])
                if written<=0:raise OSError('native continuation immutable capture write failed')
                offset+=written
            os.fchmod(executable_fd,0o500)
            seals=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
            fcntl.fcntl(executable_fd,fcntl.F_ADD_SEALS,seals)
            if (fcntl.fcntl(executable_fd,fcntl.F_GET_SEALS)&seals!=seals
                    or os.fstat(executable_fd).st_size!=len(raw)
                    or os.pread(executable_fd,len(raw)+1,0)!=raw):
                raise ValueError('native continuation immutable executable capture differs')
            process=subprocess.Popen(['/proc/self/fd/'+str(executable_fd)],pass_fds=(executable_fd,),stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd='/',bufsize=0)

            def read_exact(size):
                result=bytearray()
                while len(result)<size:
                    remaining=None if deadline is None else deadline-time.monotonic()
                    if (remaining is not None and remaining<=0) or not select.select([process.stdout],[],[],remaining)[0]:
                        raise TimeoutError('native continuation peer deadline')
                    chunk=os.read(process.stdout.fileno(),size-len(result))
                    if not chunk:raise RuntimeError('native continuation truncated event')
                    result.extend(chunk)
                return bytes(result)

            def event():
                header=EVENT.unpack(read_exact(EVENT.size))
                if header[0]!=EVENT_MAGIC or header[6:]!=(0,0):
                    raise RuntimeError('native continuation event identity differs')
                return header

            header=event()
            if header[1]!=3 or header[2]!=self.pool_bytes:
                raise RuntimeError('native continuation literal extent differs')
            if _decode_pool(read_exact(header[2]),len(owner.literals))!=owner.literals:
                raise RuntimeError('native continuation literal values differ')
            process.stdin.write(session.initial)
            while True:
                header=event()
                if not 128<=header[2]<=owner.output_bytes:
                    raise RuntimeError('native continuation event extent differs')
                body=read_exact(header[2]);words=FRAME.unpack_from(body)
                if words[0]!=MAGIC:raise RuntimeError('native continuation output identity differs')
                if header[1]==0:
                    if len(body)!=128 or words[2]!=0:raise RuntimeError('native continuation return framing differs')
                    returned=session.value(words[3]);process.stdin.close()
                    process.wait(timeout=None if deadline is None else max(0.001,deadline-time.monotonic()))
                    if process.returncode or process.stdout.read(1) or process.stderr.read(1):
                        raise RuntimeError('native continuation termination differs')
                    session.native_observation=header
                    return returned
                if header[1]!=1:raise RuntimeError('native continuation external event differs')
                opcode,count,vector_count,results=words[2:6]
                if not 1<=opcode<=18 or count>8 or results>3 or len(body)!=128+vector_count*8:
                    raise RuntimeError('native continuation primitive framing differs')
                session.status,session.pending=1,True
                session.request=(words,struct.unpack_from('<'+'Q'*vector_count,body,128))
                process.stdin.write(session.observe())
        finally:
            session._close()
            if process is not None:
                if process.poll() is None:process.kill();process.wait(timeout=3)
                for stream in (process.stdin,process.stdout,process.stderr):stream.close()
            try:
                if captured:
                    after,after_identity=_read_file(fd)
                    if identity!=after_identity or sha256(after).hexdigest()!=self.sha256:
                        raise ValueError('native continuation executable changed during invocation')
            finally:
                if executable_fd is not None:os.close(executable_fd)
                if fd is not None:os.close(fd)
