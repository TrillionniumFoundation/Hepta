"""Explicit development transport for an HIA-owned SQLite transaction process.

This module encodes captured Python values, admits immutable code/dependencies,
and transports frames. It never opens SQLite, supplies SQL, validates a lease
against rows, or chooses COMMIT/ROLLBACK/replay. No ordinary default is changed.
"""
from __future__ import annotations
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import subprocess
import threading

from .hia_agent_store import AgentRejected, _agent_resource_path
from .hia_program_tools import bounded_json_wire

SOURCE = _agent_resource_path('examples/hia_bootstrap/sqlite_store.hepta')
CANONICAL_SOURCE = _agent_resource_path('examples/hia_bootstrap/json_canonical.hepta')
SCHEMA = 'hepta.hia.sqlite-platform-build.v5'
REQUEST_MAGIC = int.from_bytes(b'HIASQRQ1','little')
EVENT_MAGIC = int.from_bytes(b'HIASQEV1','little')
EFFECT_MAGIC = int.from_bytes(b'HIASQFX1','little')
HEADER = struct.Struct('<16Q')
WORD = struct.Struct('<Q')
TRACE = struct.Struct('<QQ')
MAX_INPUT_BYTES = 8 * 1024 * 1024


def _runtime_source_paths():
    return (('examples/hia_bootstrap/sqlite_store.hepta',SOURCE),
            ('examples/hia_bootstrap/json_canonical.hepta',CANONICAL_SOURCE),
            ('examples/hia_bootstrap/sqlite_agent_transaction.hepta',_agent_resource_path('examples/hia_bootstrap/sqlite_agent_transaction.hepta')),
            ('examples/hia_bootstrap/sqlite_rollback_policy.hepta',_agent_resource_path('examples/hia_bootstrap/sqlite_rollback_policy.hepta')),
            ('examples/hia_bootstrap/agent_journal.hepta',_agent_resource_path('examples/hia_bootstrap/agent_journal.hepta')),
            ('examples/hia_bootstrap/sha256_stream.hepta',_agent_resource_path('examples/hia_bootstrap/sha256_stream.hepta')),
            ('examples/hia_bootstrap/json_preflight.hepta',_agent_resource_path('examples/hia_bootstrap/json_preflight.hepta')),
            ('examples/hia_bootstrap/agent_data_json.hepta',_agent_resource_path('examples/hia_bootstrap/agent_data_json.hepta')),
            ('examples/hia_bootstrap/agent_binary64.hepta',_agent_resource_path('examples/hia_bootstrap/agent_binary64.hepta')))


def _hash(raw):
    return sha256(raw).hexdigest()


def _typed(value):
    """Lossless primitive observation, not a SQLite binding/row decision."""
    if value is None:
        return b'\0'
    if type(value) is bool:
        return b'\2' if value else b'\1'
    if type(value) is int:
        magnitude = abs(value)
        raw = magnitude.to_bytes(max(1,(magnitude.bit_length()+7)//8),'little')
        return b'\3'+bytes((int(value<0),))+raw
    if type(value) is float:
        return b'\4'+struct.pack('<d',value)
    if type(value) is str:
        try:
            return b'\5'+value.encode('utf-8')
        except UnicodeEncodeError:
            return b'\11'+value.encode('utf-8','surrogatepass')
    if type(value) in (bytes,bytearray,memoryview):
        return b'\6'+bytes(value)
    if type(value) in (dict,list,tuple):
        try:
            encoded = bounded_json_wire(value,MAX_INPUT_BYTES,ensure_ascii=False,sort_keys=True)
        except (TypeError,ValueError,OverflowError,RecursionError,UnicodeError):
            # Defer rejection until the HIA program reaches this field. In
            # particular an unknown/inactive/wrong-slot lease cannot cause
            # caller-artifact decoding before the original short-circuit.
            return b'\12'
        return b'\7'+encoded
    return b'\10'+type(value).__name__.encode('utf-8','replace')


def packet(operation,fields=(),*,kind=0):
    fields=tuple(bytes(value) for value in fields)
    size=sum(map(len,fields))
    words=[REQUEST_MAGIC,operation,0,0,0,0,0,0,kind,0,0,0,size,len(fields),0,0]
    return HEADER.pack(*words)+b''.join(WORD.pack(len(raw)) for raw in fields)+b''.join(fields)


def capture_lease(value):
    if type(value) is not dict:
        return packet(1,(),kind=0)
    items=tuple(value.items())
    fields=[]
    for key,item in items:
        fields.extend((_typed(key),_typed(item)))
    return packet(1,fields,kind=6)


def decode_packet(raw,magic):
    if type(raw) is not bytes or len(raw)<HEADER.size:
        raise ValueError('short platform packet')
    words=HEADER.unpack_from(raw)
    if words[0]!=magic or words[14:]!=(0,0):
        raise ValueError('platform packet magic/reserved mismatch')
    count=words[13]
    remaining=len(raw)-HEADER.size
    if count>remaining//8:
        raise ValueError('platform packet table exceeds remaining bytes')
    cursor=HEADER.size+count*8
    remaining=len(raw)-cursor
    if words[12]!=remaining:
        raise ValueError('platform packet total differs')
    fields=[]
    for index in range(count):
        size=WORD.unpack_from(raw,HEADER.size+index*8)[0]
        if size>remaining:
            raise ValueError('platform packet field exceeds remaining bytes')
        fields.append(raw[cursor:cursor+size])
        cursor+=size
        remaining-=size
    if remaining:
        raise ValueError('platform packet tail differs')
    return words,tuple(fields)


def trace_records(raw):
    """Read the actual bridge trace without inventing missing operations."""
    cursor=0
    records=[]
    while cursor<len(raw):
        if len(raw)-cursor<TRACE.size:
            raise ValueError('truncated actual platform trace header')
        kind,size=TRACE.unpack_from(raw,cursor)
        cursor+=TRACE.size
        if kind not in (1,2,3,4) or size>len(raw)-cursor:
            raise ValueError('truncated actual platform trace frame')
        payload=raw[cursor:cursor+size]
        cursor+=size
        magic=REQUEST_MAGIC if kind==1 else EVENT_MAGIC if kind==3 else EFFECT_MAGIC
        words,fields=decode_packet(payload,magic)
        records.append({'kind':kind,'size':size,'sha256':_hash(payload),
                        'words':words,'fields':fields,'raw':payload})
    return records


def _pin_file(path,expected):
    path=Path(path)
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode&0o022
            or info.st_uid not in (0,os.geteuid())):
        raise ValueError('unsafe platform code/dependency file')
    raw=path.read_bytes()
    if len(raw)!=expected['bytes'] or _hash(raw)!=expected['sha256']:
        raise ValueError('platform code/dependency differs')
    return raw,{'path':str(path),'sha256':_hash(raw),'bytes':len(raw),
                'device':info.st_dev,'inode':info.st_ino,
                'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid}


def _child_identity(pid):
    raw=Path('/proc')/str(pid)/'stat'
    text=raw.read_text()
    return {'pid':pid,'start_ticks':text.rsplit(')',1)[1].split()[19]}


class NativeSqliteStore:
    """One serial native process, two native-owned SQLite connections.

    The current prototype attaches only to an existing official private DB.
    Development admission must be explicit. It is not a service/env selector.
    """
    def __init__(self,manifest,database,*,evidence,allow_development=False):
        self._lock=threading.RLock()
        self._owner_pid=os.getpid()
        self.process=None
        self._closed=False
        self._manifest=Path(manifest).absolute()
        self._manifest_bytes=self._manifest.read_bytes()
        metadata=json.loads(self._manifest_bytes)
        if metadata.get('schema')!=SCHEMA or metadata.get('closed_platform_effect_abi')!=5:
            raise ValueError('unknown native SQLite store build')
        development=metadata.get('current_source_cold_qualified') is False
        if development:
            if not allow_development or metadata.get('status')!='DEVELOPMENT_NATIVE_SQLITE_STORE_BUILT':
                raise ValueError('development SQLite store is not a qualified distribution')
        elif (metadata.get('current_source_cold_qualified') is not True
              or metadata.get('status')!='SOURCE_QUALIFIED_NATIVE_SQLITE_STORE_BUILT'):
            raise ValueError('platform build has no explicit source admission')
        for name,path in _runtime_source_paths():
            if _hash(path.read_bytes())!=metadata.get('runtime_source_sha256',{}).get(name):
                raise ValueError('platform runtime source differs from build')
        name=metadata.get('executable_path')
        if type(name) is not str or Path(name).name!=name:
            raise ValueError('platform executable is not a local build member')
        expected={'bytes':metadata['executable_bytes'],'sha256':metadata['executable_sha256']}
        binary,self.binary_identity=_pin_file(self._manifest.parent/name,expected)
        dependencies=metadata.get('system_dependencies')
        if type(dependencies) is not dict or not dependencies:
            raise ValueError('platform system dependencies are not bound')
        self.dependency_identities={}
        for path,item in dependencies.items():
            _,identity=_pin_file(path,item)
            self.dependency_identities[path]=identity
        self.metadata=metadata
        # No state-root/DB existence/mode/row check occurs in this host adapter.
        # Those observations and decisions belong to the native protocol.
        self.database=os.fsencode(Path(database).absolute())
        evidence=Path(evidence).absolute()
        evidence.mkdir(mode=0o700)
        self.evidence=evidence
        self._trace=(evidence/'native-trace.bin').open('xb')
        fd=os.memfd_create('hia-sqlite-platform',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            position=0
            while position<len(binary):
                position+=os.write(fd,binary[position:])
            os.fchmod(fd,0o500)
            seals=sum(getattr(fcntl,name,value) for name,value in
                      (('F_SEAL_SEAL',1),('F_SEAL_SHRINK',2),
                       ('F_SEAL_GROW',4),('F_SEAL_WRITE',8)))
            fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),seals)
            if fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))&seals!=seals:
                raise ValueError('platform executable is not completely sealed')
            self.process=subprocess.Popen(['/proc/self/fd/'+str(fd)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self._trace,
                pass_fds=(fd,),cwd=evidence,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
            if self._read_exact(8)!=b'HIASQOK1':
                raise ValueError('native platform loader handshake differs')
            self.child_identity=_child_identity(self.process.pid)
            self._observe_dependencies()
            self._exchange(packet(0,(self.database,)))
        except BaseException as error:
            try:
                if self.process is not None and self.process.poll() is None:
                    self.close()
                else:
                    self._abort()
            except BaseException as cleanup:
                error.add_note('native constructor resource cleanup: '+repr(cleanup))
                self._abort()
            raise
        finally:
            os.close(fd)
        self._sequence=0

    def _observe_dependencies(self):
        # Observe the actual waiting child before the first SQL request. No
        # mapped filename or hash by itself grants an untrusted image authority.
        rows=Path('/proc')/str(self.process.pid)/'maps'
        mapped={}
        raw=rows.read_bytes()
        for row in raw.decode().splitlines():
            parts=row.split(maxsplit=5)
            if len(parts)<6 or not parts[5].startswith('/'):
                continue
            major,minor=(int(part,16) for part in parts[3].split(':'))
            mapped.setdefault(parts[5],set()).add((os.makedev(major,minor),int(parts[4])))
        for path,identity in self.dependency_identities.items():
            actual=mapped.get(path)
            if actual is None or (identity['device'],identity['inode']) not in actual:
                raise ValueError('actual native child dependency identity differs')
            _pin_file(path,identity)
        if _child_identity(self.process.pid)!=self.child_identity:
            raise ValueError('native child identity changed')
        (self.evidence/'startup-maps.txt').write_bytes(raw)
        (self.evidence/'startup.json').write_text(json.dumps({
            'pid_identity':self.child_identity,'dependencies':self.dependency_identities,
            'executable':self.binary_identity,
            'current_source_cold_qualified':self.metadata['current_source_cold_qualified'],
        },indent=2,sort_keys=True)+'\n')

    def _check(self):
        if self._closed or os.getpid()!=self._owner_pid:
            raise ValueError('native store authority is closed or crossed a process boundary')
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('native store process is unavailable')
        if self._manifest.read_bytes()!=self._manifest_bytes:
            raise ValueError('native store manifest changed')

    def _read_exact(self,size):
        output=bytearray()
        while len(output)<size:
            part=self.process.stdout.read(size-len(output))
            if not part:
                raise RuntimeError('native store exited without a complete response')
            output.extend(part)
        return bytes(output)

    def _write(self,raw):
        self.process.stdin.write(WORD.pack(len(raw))+raw)
        self.process.stdin.flush()

    def _exchange(self,raw):
        self._check()
        self._write(raw)
        size=WORD.unpack(self._read_exact(8))[0]
        returned=self._read_exact(size)
        words,fields=decode_packet(returned,EFFECT_MAGIC)
        if words[1]!=0 or words[4:8]!=(0,0,0,0) or len(fields)!=1:
            raise ValueError('unexpected native store response')
        status,code=words[8],words[9]
        if status==1:
            raise AgentRejected('E_HIA_FIELDS','generation lease has missing or unknown fields')
        if status==2:
            raise AgentRejected('E_HIA_LEASE','lease is released, unknown or modified')
        if status==3:
            raise AgentRejected('E_HIA_JSON','retained lease artifact failed native JSON admission')
        if status==4:
            raise AgentRejected('E_HIA_STORE','native journal identity or private-file admission failed')
        if status==5:
            # Preserve the actual primary SQLite return code in the exception.
            error=sqlite3.IntegrityError if code&255==19 else sqlite3.OperationalError
            exception=error('native SQLite operation returned '+str(code))
            exception.sqlite_errorcode=code
            raise exception
        if status==6:
            raise AgentRejected('E_HIA_SLOT_NATIVE_CUSTODY','native SQLite state is fenced or malformed')
        if status==7:
            raise OverflowError('Python int too large to convert to SQLite INTEGER')
        if status in (8,9):
            raise sqlite3.ProgrammingError('native lease binding rejected the captured value type')
        if status!=0:
            raise ValueError('unknown native store response status')
        return fields[0],returned

    def release_slot(self,lease):
        captured=capture_lease(lease)
        with self._lock:
            result,raw=self._exchange(captured)
            self._sequence+=1
            (self.evidence/('release-%06d.request.bin'%self._sequence)).write_bytes(captured)
            (self.evidence/('release-%06d.response.bin'%self._sequence)).write_bytes(raw)
        return {'released':True,'generation':result.decode('utf-8'),'artifact_retained':True}

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._check()
            self._write(packet(2))
            if self.process.stdout.read(1)!=b'':
                raise ValueError('unexpected platform close output')
            code=self.process.wait()
            self._trace.close()
            self._closed=True
            if code!=0:
                raise RuntimeError('native platform close failed with '+str(code))
            records=trace_records((self.evidence/'native-trace.bin').read_bytes())
            if not records or records[-1]['kind']!=2 or records[-1]['words'][1]!=12:
                raise ValueError('native process lacks orderly resource-exit evidence')
            for path,identity in self.dependency_identities.items():
                _pin_file(path,identity)

    def _abort(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if hasattr(self,'_trace'):
            self._trace.close()
        self._closed=True

    def __enter__(self):
        return self

    def __exit__(self,*error):
        if error[0] is None:
            self.close()
        else:
            self._abort()
