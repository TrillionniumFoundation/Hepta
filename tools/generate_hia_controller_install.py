"""Author the HIA v25 controller installation owner; Python is build-time only."""
from pathlib import Path
import ast, hashlib, json, re, struct, subprocess, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_owner import POLICY as RELEASE_HELPERS
from tools.generate_hia_native_filter import LINK_SOURCE

ROLES=tuple(sorted(('HIA_AGENT_NATIVE_TOOL_CATALOG.json','hia-worker-prepare',
 'hia-agent-mcp-request','hia-agent-mcp-reply','hia-agent-mcp-terminal',
 'hia-agent-mcp-negotiation','hia-agent-mcp-catalog','hia-agent-mcp-uri',
 'hia-agent-mcp-input-schema','hia-agent-mcp-response-schema','hia-agent-mcp-proof-schema',
 'hia-job-receipt','hia-agent-job-terminal-receipt','hia-job-supervisor')))
def q(m,*words): return struct.pack('<8s'+'Q'*len(words),m,*words)
def compact(v): return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def spaced(v,newline=True): return (json.dumps(v,sort_keys=True)+('\n' if newline else '')).encode()
PURE=[]
def probe(role,frame,out,code=0):
    PURE.append((ROLES.index(role),frame,code,out,b''))
prepare='hia-worker-prepare'
job=b'controller-package-probe'; nonce=b'0123456789abcdef'*2; raw=b'{"exit_code":0}'
for decision,digest in ((0,hashlib.sha256(raw).hexdigest().encode()),(3,b'0'*64)):
    fields=(job,job,job,nonce,nonce,nonce,digest,raw)
    probe(prepare,q(b'HIAJWC01',1,1,1,*map(len,fields))+b''.join(fields),q(b'HIAJWR01',decision))
job=b'controller-owner-probe'
probe(prepare,q(b'HIAJOQ01',0,1,0,1,len(job),*([0]*12))+job,q(b'HIAJOR01',0,0,2))
job=b'controller-publisher-probe';nonce=b'0'*32;raw=b'{}\n'
probe(prepare,struct.pack('<8sQ32s',b'HIAJWE01',len(job),nonce)+job+raw,
      spaced({'exit_sha256':hashlib.sha256(raw).hexdigest(),'job_id':job.decode(),'launch_nonce':nonce.decode(),'terminal_publication_protocol':1}))
probe(prepare,q(b'HIAJSQ01',15,3,3,0,0,3),struct.pack('<8s2q3Q',b'HIAJSO01',-15,125,125,0,0))
root=b'/workdir/probe'
for path,allowed in ((root+b'/nested',1),(root+b'-sibling',0)):
    probe(prepare,q(b'HIAJCQ01',len(path),1,0,0)+path+struct.pack('<Q',len(root))+root,q(b'HIAJCO01',allowed))
job=b'cancel-probe';nonce=b'0123456789abcdef'*2;kind=b'proc_start_ticks';identity=b'boot:123'
for phase,uid,sample,decision in ((0,0,b'',1),(1,1000,identity,4),(1,1001,identity,2),(1,1000,b'boot:124',2)):
    fields=(job,job,job,nonce,nonce,kind,identity,nonce,kind if phase else b'',sample)
    probe(prepare,q(b'HIAJCX01',phase,1000,1000,42,uid,1,*map(len,fields))+b''.join(fields),q(b'HIAJCY01',decision))
for phase,facts,decision in ((0,8,9),(0,21,2),(1,11,2),(2,104,7),(2,5,4)):
    probe(prepare,q(b'HIAJLQ01',phase,facts),q(b'HIAJLO01',decision))
uri=rb'"hia:\/\/artifact\/controller-\u0072ead"'; rid=rb'"session\u0031"';params=b'{"uri":'+uri+b'}'
frame=b'{"jsonrpc":"2.0","method":"resources/read","id":'+rid+b',"params":'+params+b'}'
probe('hia-agent-mcp-request',frame,struct.pack('<Q8s10Q',88,b'HIAMCP01',8,4,
      frame.index(rid),len(rid),frame.index(params),len(params),0,frame.index(uri),len(uri),0))
for phase,mode,uid,links,existing,expected in ((0,0o100600,1000,1,0,1),(0,0o100640,1000,1,0,0),
      (0,0o100600,1001,1,0,0),(0,0o100600,1000,2,0,0),(1,0o100600,1000,1,0,1),(1,0o100600,1000,1,16,0)):
    probe(prepare,q(b'HIAJLK01',phase,mode,uid,1000,links,existing),q(b'HIAJLR01',expected))
job=b'job-42';nonce=b'0123456789abcdef'*2;ticks=b'12345678-1234-4abc-9def-123456789abc:42'
for invocation in (None,'','unit"\u2603'):
    count=(1<<64)-1 if invocation is None else len(invocation)
    units=b'' if invocation is None else invocation.encode('utf-32le')
    request=q(b'HIAJBE01',123456789,42,1000,len(job),len(ticks),count)+job+nonce+ticks+units
    expected={'at_unix_ms':123456789,'job_id':job.decode(),'launch_nonce':nonce.decode(),
              'supervisor_identity':{'kind':'proc_start_ticks','value':ticks.decode()},
              'supervisor_pid':42,'supervisor_uid':1000,'invocation_id':invocation}
    probe(prepare,request,spaced(expected,False))
probe(prepare,request[:-1],b'',2)
# Same reference workload used by the existing native job-owner admission.
probe(prepare,b'native-job-owner-admission-probe',b'',2)

TEXT={'EMPTY':b'','DOT':b'.','MEMFD':b'hia-controller-install','RUNNER':b'hia-subprocess',
      'CHILD':b'hia-controller-probe','ENV':b'PATH=','FD':b'fd:',
      'STAGE':b'controller-stage','PROBE':b'controller-probe','MANIFEST':b'hia-controller.json',
      'INSTALL':b'install','VERIFY':b'verify','OWNER_LOCK':b'owner.lock',
      'EXIT':b'exit.json','WITNESS':b'exit.witness.json','INTENT':b'owner-intent.json',
      'STARTED':b'started.json','CHILD_FILE':b'child.json','CANCEL':b'cancel-request.json',
      'TEMP_WITNESS':b'exit.witness.json.tmp','ABSENT':b'absent-original',
      'STDOUT':b'stdout.log','STDERR':b'stderr.log','RECEIPT':b'native-exit.bin',
      'JOB_ID':b'native-owner-admission','NONCE':b'5'*32,
      'OWNER_SAMPLE':b'native-job-owner-admission-probe','OWNER_ARG':b'hia-worker-prepare',
      'MANIFEST_PREFIX':b'{"files":{','MANIFEST_SUFFIX':b'},"schema":"hepta.hia.mcp.controller.v25"}\n',
      'INSTALL_PREFIX':b'{"bytes":','INSTALL_MIDDLE':b',"files":15,"published":',
      'INSTALL_SUFFIX':b',"schema":"hepta.hia.release-install.v1","sha256":"'}
MAGICS={'REQUEST':b'HIACTI01','OUTPUT':b'HIACTO01','SUB':b'HIASUB01',
        'SUBRECEIPT':b'HIASBR01','PASS':b'HIAPFD01','JOB':b'HIAJOB01'}

COMMON = r"""
def start_exec(o:mutbuf, w:mutbuf, image:u64, source:u64, cwd:u64, mode:u64, authority:u64, expected:u64, resume_phase:u64) -> u32:
    put(w, 1510000, mode)
    put(w, 1510008, image)
    put(w, 1510016, source)
    put(w, 1510024, cwd)
    put(w, 1510032, authority)
    put(w, 1510040, expected)
    put(w, 1510072, resume_phase)
    put(w, 1510104, 0)
    put(w, 1510160, 0)
    return call(o, w, 109, 8, source, 0, 0, 0, 0, 0, 0)

def exec_args(w:mutbuf, name:u64, size:u64) -> u64:
    put(w, 1510048, 1)
    put(w, 1510056, arg(w, 1600000, name, size) - 1600000)
    put(w, 1510064, 0)
    put(w, 1510152, 5000000000)
    return 0

def exec_add_arg(w:mutbuf, name:u64, size:u64) -> u64:
    at = 1600000 + get(w, 1510056)
    put(w, 1510056, arg(w, at, name, size) - 1600000)
    put(w, 1510048, get(w, 1510048) + 1)
    return 0

def exec_pass(w:mutbuf, fd:u64) -> u64:
    put(w, 1510400 + get(w, 1510064) * 8, fd)
    put(w, 1510064, get(w, 1510064) + 1)
    return 0

def exec_request(s:readbuf, w:mutbuf) -> u64:
    at = 458752
    put(w, at, MAGIC_SUB)
    put(w, at + 8, get(w, 16))
    put(w, at + 16, get(w, 1510080))
    put(w, at + 24, get(w, 1510008))
    put(w, at + 32, get(w, 1510016))
    put(w, at + 40, get(w, 1510112))
    put(w, at + 48, get(w, 1510120))
    put(w, at + 56, get(w, 1510024))
    put(w, at + 64, get(w, 1510128))
    put(w, at + 72, get(w, 1510048))
    put(w, at + 80, 1)
    put(w, at + 88, 67108864)
    put(w, at + 96, 65536)
    put(w, at + 104, 100000000)
    put(w, at + 112, 2147483648)
    put(w, at + 120, 0)
    copyw(w, at + 128, 1600000, get(w, 1510056))
    at = arg(w, at + 128 + get(w, 1510056), C_ENV, 5)
    if get(w, 1510064) != 0:
        put(w, at, MAGIC_PASS)
        put(w, at + 8, get(w, 1510064))
        copyw(w, at + 16, 1510400, get(w, 1510064) * 8)
        at = at + 16 + get(w, 1510064) * 8
    return at - 458752

def execution(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 150:
        return exec_child(s, o, w, phase, r)
    if phase == 113 and r == 18446744073709551612:
        return call(o, w, 113, 61, get(w, 1510088), 1510096, 1, 0, 0, 0, 12)
    if phase == 115:
        if failed(r) and r != 18446744073709551612:
            return finish(o, w, 74)
        return call(o, w, 113, 61, get(w, 1510088), 1510096, 1, 0, 0, 0, 12)
    if failed(r):
        return finish(o, w, 74)
    if phase == 109:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 100, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 100:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1510112 + get(w, 1510104) * 8, r)
        return call(o, w, 101, 91, r, 384, 0, 0, 0, 0, 0)
    if phase == 101:
        put(w, 1510104, get(w, 1510104) + 1)
        if get(w, 1510104) < 4:
            return call(o, w, 100, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
        return call(o, w, 102, 228, 1, 3000, 0, 0, 0, 0, 12)
    if phase == 102:
        now = get(w, 3000) * 1000000000 + get(w, 3008)
        deadline = minimum(uint(s, 16), now + get(w, 1510152))
        if deadline <= now:
            return finish(o, w, 65)
        put(w, 1510080, deadline)
        if get(w, 1510000) == 1:
            return resume(s, o, w, 106)
        size = exec_request(s, w)
        return writing(o, w, get(w, 1510136), 458752, size, 104)
    if phase == 104:
        return call(o, w, 105, 72, get(w, 1510136), 1033, 15, 0, 0, 0, 0)
    if phase == 105:
        return call(o, w, 106, 8, get(w, 1510136), 0, 0, 0, 0, 0, 0)
    if phase == 106:
        put(w, 3904, choose(get(w, 1510000) == 0, C_RUNNER, C_CHILD))
        put(w, 3912, 18446744073709551615)
        put(w, 4056, 0)
        put(w, 0, 110)
        put(o, 0, 3904)
        put(o, 8, 2)
        put(o, 16, 4000)
        return 2
    if phase == 110:
        return call(o, w, 111, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 111:
        if r == 0:
            return call(o, w, 150, 157, 1, 9, 0, 0, 0, 0, 0)
        if r < 2:
            return finish(o, w, 74)
        put(w, 1510088, r)
        return call(o, w, 113, 61, r, 1510096, 1, 0, 0, 0, 12)
    if phase == 113:
        if r == 0:
            return call(o, w, 114, 228, 1, 3000, 0, 0, 0, 0, 12)
        if r != get(w, 1510088) or get(w, 1510160) != 0:
            return finish(o, w, 74)
        status = getn(w, 1510096, 4)
        expected_owner_status = choose(get(w, 1510000) == 0, 0, get(w, 1510040))
        if status & 127 != 0 or (status >> 8) != expected_owner_status:
            return finish(o, w, 65)
        if get(w, 1510000) == 0:
            return call(o, w, 120, 17, get(w, 1510128), 5376, 128, 0, 0, 0, 12)
        return resume(s, o, w, 121)
    if phase == 114:
        now = get(w, 3000) * 1000000000 + get(w, 3008)
        if now > get(w, 1510080) + 2000000000:
            if get(w, 1510160) != 0:
                return finish(o, w, 74)
            put(w, 1510160, 1)
            return call(o, w, 116, 62, get(w, 1510088), 9, 0, 0, 0, 0, 0)
        put(w, 3000, 0)
        put(w, 3008, 1000000)
        return call(o, w, 115, 35, 3000, 0, 0, 0, 0, 0, 3)
    if phase == 116:
        return call(o, w, 113, 61, get(w, 1510088), 1510096, 1, 0, 0, 0, 12)
    if phase == 120:
        if r != 128 or exec_receipt(w) == 0:
            return finish(o, w, 65)
        return resume(s, o, w, 121)
    if phase == 121:
        put(w, 144, get(w, 1510112))
        put(w, 160, get(w, 1510120))
        return call(o, w, 122, 5, get(w, 144), 1200, 0, 0, 0, 0, 12)
    if phase == 122:
        if get(w, 1216) != 0 or getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) > 67108864:
            return finish(o, w, 74)
        put(w, 152, get(w, 1248))
        if get(w, 1510000) == 0 and get(w, 152) != get(w, 5424):
            return finish(o, w, 65)
        return call(o, w, 123, 72, get(w, 144), 1033, 15, 0, 0, 0, 0)
    if phase == 123:
        return call(o, w, 124, 5, get(w, 160), 1200, 0, 0, 0, 0, 12)
    if phase == 124:
        if get(w, 1216) != 0 or getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) > 65536:
            return finish(o, w, 74)
        put(w, 168, get(w, 1248))
        if get(w, 1510000) == 0 and get(w, 168) != get(w, 5440):
            return finish(o, w, 65)
        return call(o, w, 125, 72, get(w, 160), 1033, 15, 0, 0, 0, 0)
    if phase == 125:
        return call(o, w, 126, 3, get(w, 1510128), 0, 0, 0, 0, 0, 0)
    if phase == 126:
        return call(o, w, 127, 3, get(w, 1510136), 0, 0, 0, 0, 0, 0)
    if phase == 127:
        return resume(s, o, w, get(w, 1510072))
    return finish(o, w, 65)

def exec_receipt(w:mutbuf) -> u64:
    if get(w, 5376) != MAGIC_SUBRECEIPT or get(w, 5384) != get(w, 1510040) or get(w, 5392) != 0:
        return 0
    if get(w, 5400) != get(w, 1510040) * 256 or get(w, 5408) < 2:
        return 0
    if get(w, 5416) != get(w, 5424) or get(w, 5424) > 67108864:
        return 0
    if get(w, 5432) != get(w, 5440) or get(w, 5440) > 65536:
        return 0
    if get(w, 5448) != 0 or get(w, 5456) != 0 or get(w, 5464) != 0:
        return 0
    return choose(get(w, 5472) == 1 and get(w, 5480) == 1 and get(w, 5496) == 1, 1, 0)

def exec_child(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r) or phase == 159:
        return finish(o, w, 127)
    if phase == 150:
        return call(o, w, 151, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 151:
        if r != get(w, 16):
            return finish(o, w, 127)
        return call(o, w, 152, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 152:
        put(w, 1510176, 0)
        return resume(s, o, w, 153)
    if phase == 153:
        index = get(w, 1510176)
        if get(w, 1510000) == 0:
            if index < 6:
                fd = get(w, 1510008)
                if index == 1:
                    fd = get(w, 1510016)
                if index == 2:
                    fd = get(w, 1510112)
                if index == 3:
                    fd = get(w, 1510120)
                if index == 4:
                    fd = get(w, 1510024)
                if index == 5:
                    fd = get(w, 1510128)
                put(w, 1510176, index + 1)
                return call(o, w, 153, 72, fd, 2, 0, 0, 0, 0, 0)
            if index < get(w, 1510064) + 6:
                put(w, 1510176, index + 1)
                return call(o, w, 153, 72, get(w, 1510400 + (index - 6) * 8), 2, 0, 0, 0, 0, 0)
            return call(o, w, 158, 33, get(w, 1510136), 0, 0, 0, 0, 0, 0)
        if index < get(w, 1510064):
            put(w, 1510176, index + 1)
            return call(o, w, 153, 72, get(w, 1510400 + index * 8), 2, 0, 0, 0, 0, 0)
        return call(o, w, 154, 33, get(w, 1510016), 0, 0, 0, 0, 0, 0)
    if phase == 154:
        return call(o, w, 155, 33, get(w, 1510032), 1, 0, 0, 0, 0, 0)
    if phase == 155:
        return call(o, w, 156, 33, get(w, 1510120), 2, 0, 0, 0, 0, 0)
    if phase == 156:
        return call(o, w, 158, 81, get(w, 1510024), 0, 0, 0, 0, 0, 0)
    image = choose(get(w, 1510000) == 0, uint(s, 48), get(w, 1510008))
    return call(o, w, 159, 322, image, C_EMPTY, 4000, 4056, 4096, 0, 252)

def bytes_frame(o:mutbuf, w:mutbuf, buffer:u64, size:u64, next:u64) -> u32:
    put(w, 1530000, buffer)
    put(w, 1530008, size)
    put(w, 1530016, next)
    return call(o, w, 180, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)

def make_frame(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 180:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1530024, r)
        return call(o, w, 181, 91, r, 256, 0, 0, 0, 0, 0)
    if phase == 181:
        return writing(o, w, get(w, 1530024), get(w, 1530000), get(w, 1530008), 182)
    if phase == 182:
        return call(o, w, 183, 72, get(w, 1530024), 1033, 15, 0, 0, 0, 0)
    if phase == 183:
        return resume(s, o, w, get(w, 1530016))
    return finish(o, w, 65)

def copy_input(s:readbuf, w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def hex_bytes(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        value = byte(w, source + i)
        high = value >> 4
        low = value & 15
        store(w, target + i * 2, choose(high < 10, 48 + high, 87 + high))
        store(w, target + i * 2 + 1, choose(low < 10, 48 + low, 87 + low))
        i = i + 1
    return target + count * 2

def simple_read(o:mutbuf, w:mutbuf, fd:u64, buffer:u64, count:u64, resume_phase:u64) -> u32:
    if count == 0:
        put(w, 0, resume_phase)
        put(w, 8, 0)
        return 4
    return reading(o, w, fd, buffer, count, 0, resume_phase)

def role_fd(w:mutbuf, index:u64) -> u64:
    return get(w, 1501000 + index * 64)

def role_size(w:mutbuf, index:u64) -> u64:
    return get(w, 1501008 + index * 64)

def role_name(w:mutbuf, index:u64) -> u64:
    return get(w, C_ROLES + index * 16)

def role_length(w:mutbuf, index:u64) -> u64:
    return get(w, C_ROLES + index * 16 + 8)

def pointer(o:mutbuf, w:mutbuf, target:u64, source:u64, resume_phase:u64) -> u32:
    put(w, 3904, source)
    put(w, 0, resume_phase)
    put(o, 0, 3904)
    put(o, 8, 1)
    put(o, 16, target)
    return 2
"""

POLICY = r"""
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    r = get(w, 8)
    if phase < 100:
        return admission(s, o, w, phase, r)
    if phase >= 180 and phase <= 183:
        return make_frame(s, o, w, phase, r)
    if phase < 180:
        return execution(s, o, w, phase, r)
    if phase < 250:
        return transfer(s, o, w, phase, r)
    if phase < 300:
        return hashing(s, o, w, phase, r)
    if phase >= 2000:
        return 5
    return installation(s, o, w, phase, r)

def admit(s:readbuf) -> u64:
    if length(s) != 672 or uint(s, 0) != MAGIC_REQUEST or uint(s, 72) != 14:
        return 0
    if uint(s, 8) == 1 or uint(s, 8) > 2147483647 or uint(s, 16) == 0:
        return 0
    i = 80
    while i < 128:
        if uint(s, i) != 0:
            return 0
        i = i + 8
    i = 0
    while i < 6:
        fd = uint(s, 24 + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < i:
            if fd == uint(s, 24 + j * 8):
                return 0
            j = j + 1
        i = i + 1
    return 1

def admission(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 0:
        constants(w)
        if admit(s) == 0:
            return finish(o, w, 65)
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        if r < 2 or (uint(s, 8) != 0 and r != uint(s, 8)):
            return finish(o, w, 65)
        put(w, 1500200, r)
        return call(o, w, 2, 157, 1, 9, 0, 0, 0, 0, 0)
    if failed(r):
        return finish(o, w, 74)
    if phase == 2:
        return call(o, w, 3, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if r != get(w, 1500200):
            return finish(o, w, 65)
        return call(o, w, 4, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 4:
        if r < 2:
            return finish(o, w, 65)
        put(w, 16, r)
        return call(o, w, 5, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        put(w, 24, r)
        put(w, 1500000, 0)
        return call(o, w, 6, 5, uint(s, 24), 1200, 0, 0, 0, 0, 12)
    if phase == 6:
        index = get(w, 1500000)
        if getn(w, 1224, 4) & 61440 != 16384:
            return finish(o, w, 65)
        if index != 0 and (getn(w, 1224, 4) & 63 != 0 or getn(w, 1228, 4) != get(w, 24)):
            return finish(o, w, 65)
        copyw(w, 2048 + index * 144, 1200, 144)
        index = index + 1
        put(w, 1500000, index)
        if index < 3:
            return call(o, w, 6, 5, uint(s, 24 + index * 8), 1200, 0, 0, 0, 0, 12)
        if same(w, 2048, 2192, 16) == 1 or same(w, 2048, 2336, 16) == 1 or same(w, 2192, 2336, 16) == 1:
            return finish(o, w, 65)
        return call(o, w, 7, 8, uint(s, 40), 0, 0, 0, 0, 0, 0)
    if phase == 7:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 8, 217, uint(s, 40), 49152, 16384, 0, 0, 0, 12)
    if phase == 8:
        if r != 0:
            if r > 16384 or only_dots(w, r) == 0:
                return finish(o, w, 65)
            return call(o, w, 8, 217, uint(s, 40), 49152, 16384, 0, 0, 0, 12)
        put(w, 1500000, 0)
        return call(o, w, 10, 5, uint(s, 48), 1200, 0, 0, 0, 0, 12)
    if phase == 10:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) == 0 or get(w, 1248) > 67108864:
            return finish(o, w, 65)
        put(w, 1500064, get(w, 1248))
        return call(o, w, 11, 72, uint(s, 48 + get(w, 1500000) * 8), 1034, 0, 0, 0, 0, 0)
    if phase == 11:
        if r & 15 != 15:
            return finish(o, w, 65)
        return hash_view(o, w, uint(s, 48 + get(w, 1500000) * 8), 0, get(w, 1500064), 12)
    if phase == 12:
        index = get(w, 1500000)
        if same_input(s, w, 128 + index * 32, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 1500000, index + 1)
        if index < 2:
            return call(o, w, 10, 5, uint(s, 56 + index * 8), 1200, 0, 0, 0, 0, 12)
        return call(o, w, 20, 258, uint(s, 40), C_STAGE, 448, 0, 0, 0, 12)
    if phase == 20:
        return open_dir(o, w, uint(s, 40), C_STAGE, 21)
    if phase == 21:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500016, r)
        return call(o, w, 22, 258, uint(s, 40), C_PROBE, 448, 0, 0, 0, 12)
    if phase == 22:
        return open_dir(o, w, uint(s, 40), C_PROBE, 23)
    if phase == 23:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500024, r)
        put(w, 1500000, 0)
        return next_role(s, o, w)
    if phase >= 30 and phase <= 46:
        return capture_role(s, o, w, phase, r)
    return finish(o, w, 65)

def open_dir(o:mutbuf, w:mutbuf, dir:u64, path:u64, next:u64) -> u32:
    put(w, 3088, 720896)
    put(w, 3096, 0)
    put(w, 3104, 14)
    return call(o, w, next, 437, dir, path, 3088, 24, 0, 0, 60)

def next_role(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 1500000)
    if index == 14:
        return resume(s, o, w, 2000)
    put(w, 3088, 657408)
    put(w, 3096, 0)
    put(w, 3104, 14)
    return call(o, w, 30, 437, uint(s, 24), role_name(w, index), 3088, 24, 0, 0, 60)

def capture_role(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    index = get(w, 1500000)
    if phase == 30:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500048, r)
        return call(o, w, 31, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 31:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1216) != 1 or getn(w, 1224, 4) & 18 != 0:
            return finish(o, w, 65)
        size = get(w, 1248)
        if size == 0 or size > 67108864:
            return finish(o, w, 65)
        put(w, 1500064, size)
        copyw(w, 20000, 1200, 144)
        return call(o, w, 32, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 32:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500056, r)
        return call(o, w, 33, 91, r, choose(index == 0, 256, 320), 0, 0, 0, 0, 0)
    if phase == 33:
        return copying(o, w, get(w, 1500048), get(w, 1500056), 0, get(w, 1500064), 34)
    if phase == 34:
        return call(o, w, 35, 5, get(w, 1500048), 1200, 0, 0, 0, 0, 12)
    if phase == 35:
        if same(w, 20000, 1200, 72) == 0 or same(w, 20088, 1288, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 36, 72, get(w, 1500056), 1033, 15, 0, 0, 0, 0)
    if phase == 36:
        return hash_view(o, w, get(w, 1500056), 0, get(w, 1500064), 37)
    if phase == 37:
        if same_input(s, w, 224 + index * 32, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 1501000 + index * 64, get(w, 1500056))
        put(w, 1501008 + index * 64, get(w, 1500064))
        copyw(w, 1501016 + index * 64, 4096, 32)
        if index != 0:
            return call(o, w, 38, 17, get(w, 1500056), 6144, 8, 0, 0, 0, 12)
        return resume(s, o, w, 39)
    if phase == 38:
        if r != 8 or get(w, 6144) != 282579962709375:
            return finish(o, w, 65)
        return resume(s, o, w, 39)
    if phase == 39:
        put(w, 3088, 655553)
        put(w, 3096, choose(index == 0, 256, 320))
        put(w, 3104, 14)
        return call(o, w, 40, 437, get(w, 1500016), role_name(w, index), 3088, 24, 0, 0, 60)
    if phase == 40:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500072, r)
        return copying(o, w, get(w, 1500056), r, 0, get(w, 1500064), 41)
    if phase == 41:
        return call(o, w, 42, 75, get(w, 1500072), 0, 0, 0, 0, 0, 0)
    if phase == 42:
        return call(o, w, 43, 3, get(w, 1500072), 0, 0, 0, 0, 0, 0)
    if phase == 43:
        return call(o, w, 44, 3, get(w, 1500048), 0, 0, 0, 0, 0, 0)
    if phase == 44:
        put(w, 1500000, index + 1)
        return next_role(s, o, w)
    return finish(o, w, 65)

def installation(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r) and (phase != 1700 or r != 18446744073709551612):
        return finish(o, w, 74)
    return publication(s, o, w, phase, r)
"""

WRITERS=[]
def writer_case(frame,parent_at,code,observed,records):
    WRITERS.append((frame,parent_at,code,observed,tuple(sorted(records.items()))))
def writer_response(action,result=0): return struct.pack('<8sQq',b'HIAJRW01',action,result)
name=b'exit.witness';raw=b'{}\n'
writer_case(q(b'HIAJRQ02',len(raw),0,len(name))+name+raw,16,0,writer_response(6),{'exit.witness.json':raw})
raw=b'{"supervisor_pid": 17}'
writer_case(q(b'HIAJRO01',len(raw),0,0)+raw,16,0,writer_response(6),{'owner-intent.json':raw,'started.json':raw})
name=b'controller-cancel-probe';nonce=b'0'*32
writer_case(struct.pack('<8s5Q32s',b'HIAJRC01',0,2147483647,17,len(name),0,nonce)+name,
    8,0,writer_response(7,-9),{'cancel-request.json':spaced({'at_unix_ms':17,'job_id':name.decode(),'launch_nonce':nonce.decode()})})
writer_case(q(b'HIASGQ01',0,0,0,0),8,0,writer_response(0),{})
writer_case(q(b'HIAJCH01',3,0,0)+b'{}\n',16,0,writer_response(0),{})
name=b'child';raw=b'{"identity": null, "pid": 17}\n'
writer_case(q(b'HIAJCH01',len(raw),0,len(name))+name+raw,16,0,writer_response(6),{'child.json':raw})
MARKERS=(b'HIAWABI1',b'HIAWEND1',b'HIAKABI1',b'HIAKEND1',b'HIAJPOL1',b'HIASPAWN',b'HIAOWNID')
PROBES = r"""
def stage(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    r = get(w, 8)
    if phase >= 2300 and phase < 2600:
        return lock_probes(s, o, w, phase, r)
    if failed(r):
        return finish(o, w, 74)
    if phase < 2100:
        return pure_probes(s, o, w, phase, r)
    if phase < 2300:
        return writer_probes(s, o, w, phase, r)
    if phase < 2600:
        return lock_probes(s, o, w, phase, r)
    if phase < 2900:
        return native_owner_probe(s, o, w, phase, r)
    return finish(o, w, 65)

def pure_probes(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2000:
        size = role_size(w, ROLE_WRITER)
        if size < 256 or size > 2097152:
            return finish(o, w, 65)
        return reading(o, w, role_fd(w, ROLE_WRITER), 2097152, size, 0, 2001)
    if phase == 2001:
        if check_markers(w, role_size(w, ROLE_WRITER)) == 0:
            return finish(o, w, 65)
        put(w, 1540000, 0)
        return resume(s, o, w, 2010)
    if phase == 2010:
        index = get(w, 1540000)
        if index == N_PURE:
            put(w, 1540000, 0)
            return resume(s, o, w, 2100)
        row = C_PURE + index * 40
        return bytes_frame(o, w, get(w, row + 8), get(w, row + 16), 2011)
    if phase == 2011:
        row = C_PURE + get(w, 1540000) * 40
        exec_args(w, C_CHILD, L_CHILD)
        return start_exec(o, w, role_fd(w, get(w, row)), get(w, 1530024),
                          get(w, 1500024), 0, 0, get(w, row + 24), 2012)
    if phase == 2012:
        row = C_PURE + get(w, 1540000) * 40
        expected = get(w, row + 32)
        if get(w, 152) != get(w, expected) or get(w, 168) != 0:
            return finish(o, w, 65)
        return simple_read(o, w, get(w, 144), 16384, get(w, 152), 2013)
    if phase == 2013:
        row = C_PURE + get(w, 1540000) * 40
        if same(w, 16384, get(w, row + 32) + 8, get(w, 152)) == 0:
            return finish(o, w, 65)
        return call(o, w, 2014, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2014:
        return call(o, w, 2015, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2015:
        return call(o, w, 2016, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 2016:
        put(w, 1540000, get(w, 1540000) + 1)
        return resume(s, o, w, 2010)
    return finish(o, w, 65)

def check_markers(w:mutbuf, size:u64) -> u64:
    index = 0
    while index < 7:
        value = get(w, C_MARKERS + index * 8)
        at = 0
        count = 0
        found = 0
        while at + 8 <= size:
            if get(w, 2097152 + at) == value:
                count = count + 1
                found = at
            at = at + 1
        if count != 1:
            return 0
        put(w, 1540100 + index * 8, found)
        index = index + 1
    first = get(w, 1540100)
    last = get(w, 1540108)
    begin_capture = get(w, 1540116)
    end_capture = get(w, 1540124)
    policy = get(w, 1540132)
    if last < first + 40 or last > first + 264:
        return 0
    if end_capture < begin_capture + 40 or end_capture > begin_capture + 264:
        return 0
    if policy != end_capture + 8 or size < policy + 40 or size > policy + 1048584:
        return 0
    if get(w, 1540140) != last + 8 or begin_capture != last + 16:
        return 0
    return choose(get(w, 1540148) + 8 == first, 1, 0)

def writer_probes(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2100:
        index = get(w, 1540000)
        if index == N_WRITERS:
            return resume(s, o, w, 2300)
        row = C_WRITERS + index * 64
        return call(o, w, 2101, 258, get(w, 1500024), get(w, row), 448, 0, 0, 0, 12)
    if phase == 2101:
        row = C_WRITERS + get(w, 1540000) * 64
        return open_dir(o, w, get(w, 1500024), get(w, row), 2102)
    if phase == 2102:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1540024, r)
        row = C_WRITERS + get(w, 1540000) * 64
        copyw(w, 32768, get(w, row + 8), get(w, row + 16))
        put(w, 32768 + get(w, row + 24), get(w, 16))
        return bytes_frame(o, w, 32768, get(w, row + 16), 2103)
    if phase == 2103:
        row = C_WRITERS + get(w, 1540000) * 64
        exec_args(w, C_CHILD, L_CHILD)
        return start_exec(o, w, role_fd(w, ROLE_WRITER), get(w, 1530024),
                          get(w, 1540024), 1, get(w, 1540024), get(w, row + 32), 2104)
    if phase == 2104:
        if get(w, 152) != 0 or get(w, 168) != 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, 160), 16384, 24, 0, 2105)
    if phase == 2105:
        row = C_WRITERS + get(w, 1540000) * 64
        if same(w, 16384, get(w, row + 40), 24) == 0:
            return finish(o, w, 65)
        put(w, 1540032, 0)
        return writer_file(s, o, w)
    if phase == 2110:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1540040, r)
        return call(o, w, 2111, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 2111:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1216) != 1 or getn(w, 1228, 4) != get(w, 24):
            return finish(o, w, 65)
        file = writer_file_row(w)
        if get(w, 1248) != get(w, file + 24):
            return finish(o, w, 65)
        return simple_read(o, w, get(w, 1540040), 16384, get(w, 1248), 2112)
    if phase == 2112:
        file = writer_file_row(w)
        if same(w, 16384, get(w, file + 16), get(w, file + 24)) == 0:
            return finish(o, w, 65)
        return call(o, w, 2113, 3, get(w, 1540040), 0, 0, 0, 0, 0, 0)
    if phase == 2113:
        put(w, 1540032, get(w, 1540032) + 1)
        return writer_file(s, o, w)
    if phase == 2120:
        put(w, 1540048, 0)
        return call(o, w, 2121, 217, get(w, 1540024), 49152, 16384, 0, 0, 0, 12)
    if phase == 2121:
        row = C_WRITERS + get(w, 1540000) * 64
        if r != 0:
            if r > 16384 or directory_members(w, r, get(w, row + 56), get(w, row + 48)) == 0:
                return finish(o, w, 65)
            return call(o, w, 2121, 217, get(w, 1540024), 49152, 16384, 0, 0, 0, 12)
        if get(w, 1540048) != (1 << get(w, row + 48)) - 1:
            return finish(o, w, 65)
        return call(o, w, 2122, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2122:
        return call(o, w, 2123, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2123:
        return call(o, w, 2124, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 2124:
        return call(o, w, 2125, 3, get(w, 1540024), 0, 0, 0, 0, 0, 0)
    if phase == 2125:
        put(w, 1540000, get(w, 1540000) + 1)
        return resume(s, o, w, 2100)
    return finish(o, w, 65)

def writer_file_row(w:mutbuf) -> u64:
    row = C_WRITERS + get(w, 1540000) * 64
    return get(w, row + 56) + get(w, 1540032) * 32

def writer_file(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    row = C_WRITERS + get(w, 1540000) * 64
    if get(w, 1540032) == get(w, row + 48):
        return call(o, w, 2120, 8, get(w, 1540024), 0, 0, 0, 0, 0, 0)
    file = writer_file_row(w)
    put(w, 3088, 657408)
    put(w, 3096, 0)
    put(w, 3104, 14)
    return call(o, w, 2110, 437, get(w, 1540024), get(w, file), 3088, 24, 0, 0, 60)

def directory_members(w:mutbuf, size:u64, table:u64, count:u64) -> u64:
    at = 0
    while at < size:
        if at + 20 > size:
            return 0
        length = getn(w, 49152 + at + 16, 2)
        if length < 21 or length > size - at:
            return 0
        name = 49152 + at + 19
        dot = byte(w, name) == 46 and byte(w, name + 1) == 0
        dots = byte(w, name) == 46 and byte(w, name + 1) == 46 and byte(w, name + 2) == 0
        if choose(dot, 1, 0) == 0 and choose(dots, 1, 0) == 0:
            index = 0
            found = 0
            while index < count:
                size_name = get(w, table + index * 32 + 8)
                if size_name + 20 <= length and same(w, name, get(w, table + index * 32), size_name) == 1 and byte(w, name + size_name) == 0:
                    if get(w, 1540048) & (1 << index) != 0:
                        return 0
                    put(w, 1540048, get(w, 1540048) | (1 << index))
                    found = 1
                index = index + 1
            if found == 0:
                return 0
        at = at + length
    return 1
"""

LOCKS = r"""def lock_probes(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r) and phase != 2309 and phase != 2515:
        return finish(o, w, 74)
    if phase >= 2400 and phase < 2500:
        return marker_probes(s, o, w, phase, r)
    if phase >= 2500:
        return custody_probe(s, o, w, phase, r)
    if phase == 2300:
        return call(o, w, 2301, 258, get(w, 1500024), C_LOCK_CASE, 448, 0, 0, 0, 12)
    if phase == 2301:
        return open_dir(o, w, get(w, 1500024), C_LOCK_CASE, 2302)
    if phase == 2302:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541000, r)
        return open_case_file(o, w, r, C_OWNER_LOCK, 1, 2303)
    if phase == 2303:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541008, r)
        return open_case_file(o, w, get(w, 1541000), C_OWNER_LOCK, 0, 2304)
    if phase == 2304:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541016, r)
        return call(o, w, 2305, 5, get(w, 1541008), 1200, 0, 0, 0, 0, 12)
    if phase == 2305:
        put(w, 32768, MAGIC_LOCK_FILE)
        put(w, 32776, get(w, 16))
        put(w, 32784, get(w, 1200))
        put(w, 32792, get(w, 1208))
        put(w, 32800, 0)
        return bytes_frame(o, w, 32768, 40, 2306)
    if phase == 2306:
        exec_args(w, C_CHILD, L_CHILD)
        return start_exec(o, w, role_fd(w, ROLE_WRITER), get(w, 1530024),
                          get(w, 1541000), 1, get(w, 1541008), 0, 2307)
    if phase == 2307:
        if get(w, 152) != 0 or get(w, 168) != 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, 160), 16384, 24, 0, 2308)
    if phase == 2308:
        if writer_reply(w, 2, 0) == 0:
            return finish(o, w, 65)
        return call(o, w, 2309, 73, get(w, 1541016), 6, 0, 0, 0, 0, 0)
    if phase == 2309:
        if r != 18446744073709551605:
            return finish(o, w, 65)
        return call(o, w, 2310, 3, get(w, 1541008), 0, 0, 0, 0, 0, 0)
    if phase == 2310:
        return call(o, w, 2311, 73, get(w, 1541016), 6, 0, 0, 0, 0, 0)
    if phase == 2311:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 2312, 3, get(w, 1541016), 0, 0, 0, 0, 0, 0)
    if phase == 2312:
        return call(o, w, 2313, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2313:
        return call(o, w, 2314, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2314:
        return call(o, w, 2315, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 2315:
        return call(o, w, 2316, 3, get(w, 1541000), 0, 0, 0, 0, 0, 0)
    if phase == 2316:
        return resume(s, o, w, 2400)
    return finish(o, w, 65)

def open_case_file(o:mutbuf, w:mutbuf, dir:u64, name:u64, create:u64, phase:u64) -> u32:
    put(w, 3088, choose(create == 1, 655554, 655362))
    put(w, 3096, choose(create == 1, 384, 0))
    put(w, 3104, 14)
    return call(o, w, phase, 437, dir, name, 3088, 24, 0, 0, 60)

def writer_reply(w:mutbuf, action:u64, value:u64) -> u64:
    return choose(get(w, 16384) == MAGIC_WRITER_REPLY and get(w, 16392) == action and get(w, 16400) == value, 1, 0)

def marker_probes(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2400:
        return call(o, w, 2401, 258, get(w, 1500024), C_MARKER_CASE, 448, 0, 0, 0, 12)
    if phase == 2401:
        return open_dir(o, w, get(w, 1500024), C_MARKER_CASE, 2402)
    if phase == 2402:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541000, r)
        put(w, 1541032, 0)
        return call(o, w, 2403, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 2403:
        put(w, 1541040, get(w, 1200))
        put(w, 1541048, get(w, 1208))
        return marker_frame(o, w)
    if phase == 2404:
        exec_args(w, C_CHILD, L_CHILD)
        return start_exec(o, w, role_fd(w, ROLE_WRITER), get(w, 1530024),
                          get(w, 1541000), 1, get(w, 1541000), 0, 2405)
    if phase == 2405:
        if get(w, 152) != 0 or get(w, 168) != 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, 160), 16384, 24, 0, 2406)
    if phase == 2406:
        index = get(w, 1541032)
        if writer_reply(w, 3, choose(index == 0, 0, choose(index == 1, 5, 21))) == 0:
            return finish(o, w, 65)
        return call(o, w, 2407, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2407:
        return call(o, w, 2408, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2408:
        return call(o, w, 2409, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 2409:
        index = get(w, 1541032)
        if index == 0:
            return open_case_file(o, w, get(w, 1541000), C_INTENT, 1, 2410)
        if index == 1:
            return call(o, w, 2414, 266, C_ABSENT, get(w, 1541000), C_TEMP_WITNESS, 0, 0, 0, 51)
        return call(o, w, 2415, 3, get(w, 1541000), 0, 0, 0, 0, 0, 0)
    if phase == 2410:
        if r < 3:
            return finish(o, w, 74)
        return call(o, w, 2411, 3, r, 0, 0, 0, 0, 0, 0)
    if phase == 2411:
        return open_case_file(o, w, get(w, 1541000), C_EXIT, 1, 2412)
    if phase == 2412:
        if r < 3:
            return finish(o, w, 74)
        return call(o, w, 2413, 3, r, 0, 0, 0, 0, 0, 0)
    if phase == 2413 or phase == 2414:
        put(w, 1541032, get(w, 1541032) + 1)
        return marker_frame(o, w)
    if phase == 2415:
        return resume(s, o, w, 2500)
    return finish(o, w, 65)

def marker_frame(o:mutbuf, w:mutbuf) -> u32:
    put(w, 32768, MAGIC_MARKER)
    put(w, 32776, get(w, 16))
    put(w, 32784, get(w, 1541040))
    put(w, 32792, get(w, 1541048))
    put(w, 32800, 0)
    return bytes_frame(o, w, 32768, 40, 2404)

def custody_probe(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2500:
        return call(o, w, 2501, 258, get(w, 1500024), C_CUSTODY_CASE, 448, 0, 0, 0, 12)
    if phase == 2501:
        return open_dir(o, w, get(w, 1500024), C_CUSTODY_CASE, 2502)
    if phase == 2502:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541000, r)
        return call(o, w, 2503, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 2503:
        put(w, 1541040, get(w, 1200))
        put(w, 1541048, get(w, 1208))
        return call(o, w, 2504, 53, 1, 524290, 0, 3504, 0, 0, 192)
    if phase == 2504:
        first = getn(w, 3504, 4)
        second = getn(w, 3508, 4)
        if first < 3 or second < 3 or first == second:
            return finish(o, w, 74)
        put(w, 1541080, first)
        put(w, 1541088, second)
        put(w, 32768, MAGIC_CUSTODY)
        put(w, 32776, get(w, 16))
        put(w, 32784, get(w, 1541040))
        put(w, 32792, get(w, 1541048))
        put(w, 32800, second)
        put(w, 32808, 0)
        return bytes_frame(o, w, 32768, 48, 2505)
    if phase == 2505:
        exec_args(w, C_CHILD, L_CHILD)
        exec_pass(w, get(w, 1541088))
        return start_exec(o, w, role_fd(w, ROLE_WRITER), get(w, 1530024),
                          get(w, 1541000), 1, get(w, 1541000), 0, 2506)
    if phase == 2506:
        if get(w, 152) != 0 or get(w, 168) != 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, 160), 16384, 24, 0, 2507)
    if phase == 2507:
        if writer_reply(w, 12, 0) == 0:
            return finish(o, w, 65)
        i = 0
        while i < 56:
            store(w, 24100 + i, 0)
            i = i + 1
        put(w, 24008, 1)
        put(w, 24124, 1)
        put(w, 24140, 24)
        put(w, 24288, 0)
        put(w, 24296, 0)
        put(w, 24304, 0)
        return pointer(o, w, 24000, 24256, 2508)
    if phase == 2508:
        return pointer(o, w, 24116, 24000, 2509)
    if phase == 2509:
        return pointer(o, w, 24132, 24288, 2510)
    if phase == 2510:
        return call(o, w, 2511, 47, get(w, 1541080), 24100, 1073741888, 0, 0, 0, 12)
    if phase == 2511:
        if r != 1 or byte(w, 24256) != 76 or getn(w, 24148, 4) & 40 != 0:
            return finish(o, w, 65)
        if get(w, 24140) != 24 or get(w, 24288) != 20 or getn(w, 24296, 4) != 1 or getn(w, 24300, 4) != 1:
            return finish(o, w, 65)
        fd = getn(w, 24304, 4)
        if fd < 3:
            return finish(o, w, 65)
        put(w, 1541104, fd)
        return call(o, w, 2512, 72, fd, 1, 0, 0, 0, 0, 0)
    if phase == 2512:
        if r & 1 != 1:
            return finish(o, w, 65)
        return call(o, w, 2530, 5, get(w, 1541104), 1200, 0, 0, 0, 0, 12)
    if phase == 2530:
        put(w, 1541112, get(w, 1200))
        put(w, 1541120, get(w, 1208))
        return open_case_file(o, w, get(w, 1541000), C_OWNER_LOCK, 0, 2513)
    if phase == 2513:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1541016, r)
        return call(o, w, 2514, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 2514:
        if get(w, 1200) != get(w, 1541112) or get(w, 1208) != get(w, 1541120):
            return finish(o, w, 65)
        return call(o, w, 2515, 73, get(w, 1541016), 6, 0, 0, 0, 0, 0)
    if phase == 2515:
        if r != 18446744073709551605:
            return finish(o, w, 65)
        return call(o, w, 2516, 3, get(w, 1541104), 0, 0, 0, 0, 0, 0)
    if phase == 2516:
        return call(o, w, 2517, 73, get(w, 1541016), 6, 0, 0, 0, 0, 0)
    if phase == 2517:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 2518, 3, get(w, 1541016), 0, 0, 0, 0, 0, 0)
    if phase == 2518:
        return call(o, w, 2519, 3, get(w, 1541080), 0, 0, 0, 0, 0, 0)
    if phase == 2519:
        return call(o, w, 2520, 3, get(w, 1541088), 0, 0, 0, 0, 0, 0)
    if phase == 2520:
        return call(o, w, 2521, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2521:
        return call(o, w, 2522, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2522:
        return call(o, w, 2523, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 2523:
        return call(o, w, 2524, 3, get(w, 1541000), 0, 0, 0, 0, 0, 0)
    if phase == 2524:
        return resume(s, o, w, 2600)
    return finish(o, w, 65)

"""
OWNERS = r"""def native_owner_probe(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 2800:
        return read_probe_file(s, o, w, phase, r)
    if phase == 2600:
        return call(o, w, 2601, 258, get(w, 1500024), C_JOB_CASE, 448, 0, 0, 0, 12)
    if phase == 2601:
        return open_dir(o, w, get(w, 1500024), C_JOB_CASE, 2602)
    if phase == 2602:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1542000, r)
        put(w, 1542008, 0)
        return open_case_file(o, w, r, C_STDOUT, 1, 2603)
    if phase == 2603:
        if r < 3:
            return finish(o, w, 74)
        index = get(w, 1542008)
        put(w, 1542016 + index * 8, r)
        put(w, 1542008, index + 1)
        if index < 2:
            return open_case_file(o, w, get(w, 1542000), choose(index == 0, C_STDERR, C_RECEIPT), 1, 2603)
        return bytes_frame(o, w, C_OWNER_SAMPLE, L_OWNER_SAMPLE, 2604)
    if phase == 2604:
        put(w, 1542040, get(w, 1530024))
        return call(o, w, 2605, 228, 1, 3000, 0, 0, 0, 0, 12)
    if phase == 2605:
        deadline = minimum(uint(s, 16), get(w, 3000) * 1000000000 + get(w, 3008) + 3000000000)
        put(w, 32768, MAGIC_JOB)
        put(w, 32776, 0)
        put(w, 32784, deadline)
        put(w, 32792, role_fd(w, ROLE_PREPARE))
        put(w, 32800, get(w, 1542040))
        put(w, 32808, get(w, 1542016))
        put(w, 32816, get(w, 1542024))
        put(w, 32824, get(w, 1542000))
        put(w, 32832, get(w, 1542032))
        put(w, 32840, 1)
        put(w, 32848, 0)
        put(w, 32856, 1048576)
        put(w, 32864, 1048576)
        put(w, 32872, 100000000)
        put(w, 32880, 0)
        put(w, 32888, 0)
        put(w, 32896, get(w, 1542000))
        put(w, 32904, L_JOB_ID)
        copyw(w, 32912, C_NONCE, 32)
        put(w, 32944, 0)
        i = 0
        while i < 32:
            store(w, 32952 + i, 0)
            i = i + 1
        copyw(w, 32984, C_JOB_ID, L_JOB_ID)
        at = arg(w, 32984 + L_JOB_ID, C_OWNER_ARG, L_OWNER_ARG)
        return bytes_frame(o, w, 32768, at - 32768, 2606)
    if phase == 2606:
        put(w, 1542048, get(w, 1530024))
        exec_args(w, C_CHILD, L_CHILD)
        exec_pass(w, role_fd(w, ROLE_PREPARE))
        exec_pass(w, get(w, 1542040))
        exec_pass(w, get(w, 1542016))
        exec_pass(w, get(w, 1542024))
        exec_pass(w, get(w, 1542032))
        exec_pass(w, get(w, 1542000))
        return start_exec(o, w, role_fd(w, ROLE_OWNER), get(w, 1542048),
                          get(w, 1542000), 0, 0, 2, 2607)
    if phase == 2607:
        if get(w, 152) != 0 or get(w, 168) != 0:
            return finish(o, w, 65)
        put(w, 1542056, get(w, 5408))
        return call(o, w, 2608, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 2608:
        return call(o, w, 2609, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 2609:
        return call(o, w, 2610, 3, get(w, 1542048), 0, 0, 0, 0, 0, 0)
    if phase == 2610:
        return call(o, w, 2611, 5, get(w, 1542032), 1200, 0, 0, 0, 0, 12)
    if phase == 2611:
        if get(w, 1248) != 128:
            return finish(o, w, 65)
        return reading(o, w, get(w, 1542032), 16384, 128, 0, 2612)
    if phase == 2612:
        if inner_receipt(w) == 0:
            return finish(o, w, 65)
        put(w, 1542064, get(w, 16416))
        return call(o, w, 2613, 5, get(w, 1542016), 1200, 0, 0, 0, 0, 12)
    if phase == 2613:
        if get(w, 1248) != 0:
            return finish(o, w, 65)
        return call(o, w, 2614, 5, get(w, 1542024), 1200, 0, 0, 0, 0, 12)
    if phase == 2614:
        if get(w, 1248) != 0:
            return finish(o, w, 65)
        return open_record(o, w, get(w, 1542000), C_EXIT, 32768, 4096, 2615)
    if phase == 2615:
        if terminal_record(w, get(w, 1550040)) == 0:
            return finish(o, w, 65)
        copyw(w, 1542072, 1550080, 32)
        return open_record(o, w, get(w, 1542000), C_WITNESS, 40960, 4096, 2616)
    if phase == 2616:
        if witness_record(w, get(w, 1550040)) == 0:
            return finish(o, w, 65)
        return open_record(o, w, get(w, 1542000), C_STARTED, 45056, 4096, 2617)
    if phase == 2617:
        if started_record(w, get(w, 1550040)) == 0:
            return finish(o, w, 65)
        put(w, 1542112, get(w, 1550040))
        return open_record(o, w, get(w, 1542000), C_INTENT, 49152, 4096, 2618)
    if phase == 2618:
        if get(w, 1550040) != get(w, 1542112) or same(w, 45056, 49152, get(w, 1550040)) == 0:
            return finish(o, w, 65)
        return open_record(o, w, get(w, 1542000), C_CHILD_FILE, 57344, 4096, 2619)
    if phase == 2619:
        if child_record(w, get(w, 1550040)) == 0:
            return finish(o, w, 65)
        put(w, 1540048, 0)
        return call(o, w, 2620, 8, get(w, 1542000), 0, 0, 0, 0, 0, 0)
    if phase == 2620:
        return call(o, w, 2621, 217, get(w, 1542000), 49152, 16384, 0, 0, 0, 12)
    if phase == 2621:
        if r != 0:
            if r > 16384 or directory_members(w, r, C_OWNER_FILES, 9) == 0:
                return finish(o, w, 65)
            return call(o, w, 2621, 217, get(w, 1542000), 49152, 16384, 0, 0, 0, 12)
        if get(w, 1540048) != 511:
            return finish(o, w, 65)
        return call(o, w, 2622, 3, get(w, 1542040), 0, 0, 0, 0, 0, 0)
    if phase == 2622:
        put(w, 1542008, 0)
        return call(o, w, 2623, 3, get(w, 1542016), 0, 0, 0, 0, 0, 0)
    if phase == 2623:
        index = get(w, 1542008) + 1
        put(w, 1542008, index)
        if index < 3:
            return call(o, w, 2623, 3, get(w, 1542016 + index * 8), 0, 0, 0, 0, 0, 0)
        return call(o, w, 2624, 3, get(w, 1542000), 0, 0, 0, 0, 0, 0)
    if phase == 2624:
        return resume(s, o, w, 1500)
    return finish(o, w, 65)

def inner_receipt(w:mutbuf) -> u64:
    if get(w, 16384) != MAGIC_SUBRECEIPT or get(w, 16392) != 2 or get(w, 16400) != 0 or get(w, 16408) != 512:
        return 0
    if get(w, 16416) < 2 or get(w, 16416) == get(w, 1542056):
        return 0
    i = 40
    while i <= 88:
        if get(w, 16384 + i) != 0:
            return 0
        i = i + 8
    return choose(get(w, 16480) == 1 and get(w, 16488) == 1 and get(w, 16504) == 1, 1, 0)

def open_record(o:mutbuf, w:mutbuf, dir:u64, name:u64, buffer:u64, cap:u64, next:u64) -> u32:
    put(w, 1550000, buffer)
    put(w, 1550008, cap)
    put(w, 1550016, next)
    put(w, 3088, 657408)
    put(w, 3096, 0)
    put(w, 3104, 14)
    return call(o, w, 2800, 437, dir, name, 3088, 24, 0, 0, 60)

def read_probe_file(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2800:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1550032, r)
        return call(o, w, 2801, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 2801:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1216) != 1 or getn(w, 1228, 4) != get(w, 24):
            return finish(o, w, 65)
        size = get(w, 1248)
        if size == 0 or size > get(w, 1550008):
            return finish(o, w, 65)
        put(w, 1550040, size)
        return reading(o, w, get(w, 1550032), get(w, 1550000), size, 0, 2802)
    if phase == 2802:
        return hash_view(o, w, get(w, 1550032), 0, get(w, 1550040), 2803)
    if phase == 2803:
        copyw(w, 1550080, 4096, 32)
        return call(o, w, 2804, 3, get(w, 1550032), 0, 0, 0, 0, 0, 0)
    if phase == 2804:
        return resume(s, o, w, get(w, 1550016))
    return finish(o, w, 65)

def number(w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end or byte(w, at) < 48 or byte(w, at) > 57:
        return 0
    start = at
    value = 0
    while at < end and byte(w, at) >= 48 and byte(w, at) <= 57:
        if at != start and byte(w, start) == 48:
            return 0
        digit = byte(w, at) - 48
        if value > divide(18446744073709551615 - digit, 10):
            return 0
        value = value * 10 + digit
        at = at + 1
    put(w, 1542200, value)
    return at

def terminal_record(w:mutbuf, size:u64) -> u64:
    if size < L_TIME_PREFIX + L_TERMINAL_SUFFIX + 1 or same(w, 32768, C_TIME_PREFIX, L_TIME_PREFIX) == 0:
        return 0
    at = number(w, 32768 + L_TIME_PREFIX, 32768 + size)
    if at == 0 or get(w, 1542200) == 0 or at + L_TERMINAL_SUFFIX != 32768 + size:
        return 0
    return same(w, at, C_TERMINAL_SUFFIX, L_TERMINAL_SUFFIX)

def witness_record(w:mutbuf, size:u64) -> u64:
    if size != L_WITNESS_PREFIX + 64 + L_WITNESS_SUFFIX:
        return 0
    copyw(w, 6144, C_WITNESS_PREFIX, L_WITNESS_PREFIX)
    at = hex_bytes(w, 6144 + L_WITNESS_PREFIX, 1542072, 32)
    copyw(w, at, C_WITNESS_SUFFIX, L_WITNESS_SUFFIX)
    return same(w, 40960, 6144, size)

def proc_identity(w:mutbuf, at:u64, end:u64) -> u64:
    if end < at + 38:
        return 0
    i = 0
    while i < 36:
        ch = byte(w, at + i)
        if i == 8 or i == 13 or i == 18 or i == 23:
            if ch != 45:
                return 0
        else:
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                return 0
        i = i + 1
    if byte(w, at + 36) != 58:
        return 0
    return number(w, at + 37, end)

def started_record(w:mutbuf, size:u64) -> u64:
    end = 45056 + size
    if size < L_TIME_PREFIX + L_STARTED_BODY + L_PID + L_UID + 44 or same(w, 45056, C_TIME_PREFIX, L_TIME_PREFIX) == 0:
        return 0
    at = number(w, 45056 + L_TIME_PREFIX, end)
    if at == 0 or get(w, 1542200) == 0 or at + L_STARTED_BODY > end:
        return 0
    if same(w, at, C_STARTED_BODY, L_STARTED_BODY) == 0:
        return 0
    at = proc_identity(w, at + L_STARTED_BODY, end)
    if at == 0 or at + L_PID > end or same(w, at, C_PID, L_PID) == 0:
        return 0
    at = number(w, at + L_PID, end)
    if at == 0 or get(w, 1542200) != get(w, 1542056) or at + L_UID > end or same(w, at, C_UID, L_UID) == 0:
        return 0
    at = number(w, at + L_UID, end)
    if at == 0 or get(w, 1542200) != get(w, 24) or at + 2 != end:
        return 0
    return choose(byte(w, at) == 125 and byte(w, at + 1) == 10, 1, 0)

def child_record(w:mutbuf, size:u64) -> u64:
    end = 57344 + size
    if size < L_CHILD_PREFIX + L_CHILD_PID + 42 or same(w, 57344, C_CHILD_PREFIX, L_CHILD_PREFIX) == 0:
        return 0
    at = proc_identity(w, 57344 + L_CHILD_PREFIX, end)
    if at == 0 or at + L_CHILD_PID > end or same(w, at, C_CHILD_PID, L_CHILD_PID) == 0:
        return 0
    at = number(w, at + L_CHILD_PID, end)
    if at == 0 or get(w, 1542200) != get(w, 1542064) or at + 2 != end:
        return 0
    return choose(byte(w, at) == 125 and byte(w, at + 1) == 10, 1, 0)
"""
PUBLISH = r"""def publication(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 1600:
        return cleanup(s, o, w, phase, r)
    if phase == 1500:
        put(w, 1500104, manifest(w))
        put(w, 3088, 655554)
        put(w, 3096, 256)
        put(w, 3104, 14)
        return call(o, w, 1501, 437, get(w, 1500016), C_MANIFEST, 3088, 24, 0, 0, 60)
    if phase == 1501:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500112, r)
        return writing(o, w, r, 400000, get(w, 1500104), 1502)
    if phase == 1502:
        return call(o, w, 1503, 75, get(w, 1500112), 0, 0, 0, 0, 0, 0)
    if phase == 1503:
        return hash_view(o, w, get(w, 1500112), 0, get(w, 1500104), 1504)
    if phase == 1504:
        copyw(w, 1500120, 4096, 32)
        return call(o, w, 1505, 3, get(w, 1500112), 0, 0, 0, 0, 0, 0)
    if phase == 1505:
        return call(o, w, 1506, 74, get(w, 1500016), 0, 0, 0, 0, 0, 0)
    if phase == 1506:
        return bytes_frame(o, w, C_EMPTY, 0, 1510)
    if phase == 1510:
        exec_args(w, C_CHILD, L_CHILD)
        put(w, 1510152, 60000000000)
        size = fd_text(w, 62000, get(w, 1500016))
        exec_add_arg(w, 62000, size)
        exec_pass(w, get(w, 1500016))
        return start_exec(o, w, uint(s, 56), get(w, 1530024), uint(s, 40), 0, 0, 0, 1511)
    if phase == 1511:
        if get(w, 152) == 0 or get(w, 168) != 65:
            return finish(o, w, 65)
        put(w, 1500160, get(w, 144))
        put(w, 1500168, get(w, 152))
        put(w, 1500176, get(w, 160))
        return reading(o, w, get(w, 160), 6144, 65, 0, 1512)
    if phase == 1512:
        if byte(w, 6208) != 10:
            return finish(o, w, 65)
        return hash_view(o, w, get(w, 1500160), 0, get(w, 1500168), 1513)
    if phase == 1513:
        hex_bytes(w, 7000, 4096, 32)
        if same(w, 7000, 6144, 64) == 0:
            return finish(o, w, 65)
        copyw(w, 1500184, 4096, 32)
        return call(o, w, 1514, 3, get(w, 1500176), 0, 0, 0, 0, 0, 0)
    if phase == 1514:
        return call(o, w, 1515, 3, get(w, 1530024), 0, 0, 0, 0, 0, 0)
    if phase == 1515:
        put(w, 1500224, 0)
        return install_package(s, o, w)
    if phase == 1520:
        if get(w, 168) != 0 or get(w, 152) == 0 or get(w, 152) > 4096:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 16384, get(w, 152), 0, 1521)
    if phase == 1521:
        if installer_receipt(w, get(w, 152)) == 0:
            return finish(o, w, 65)
        return call(o, w, 1522, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 1522:
        return call(o, w, 1523, 3, get(w, 160), 0, 0, 0, 0, 0, 0)
    if phase == 1523:
        if get(w, 1500224) == 0:
            put(w, 1500224, 1)
            return install_package(s, o, w)
        hex_bytes(w, 62000, 1500184, 32)
        store(w, 62064, 0)
        return open_dir(o, w, uint(s, 32), 62000, 1530)
    if phase == 1530:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500232, r)
        put(w, 3088, 657408)
        put(w, 3096, 0)
        put(w, 3104, 14)
        return call(o, w, 1531, 437, r, C_MANIFEST, 3088, 24, 0, 0, 60)
    if phase == 1531:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500240, r)
        return call(o, w, 1532, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 1532:
        if get(w, 1248) != get(w, 1500104) or get(w, 1216) != 1 or getn(w, 1224, 4) & 61440 != 32768:
            return finish(o, w, 65)
        return reading(o, w, get(w, 1500240), 16384, get(w, 1500104), 0, 1533)
    if phase == 1533:
        if same(w, 16384, 400000, get(w, 1500104)) == 0:
            return finish(o, w, 65)
        return call(o, w, 1534, 3, get(w, 1500240), 0, 0, 0, 0, 0, 0)
    if phase == 1534:
        return call(o, w, 1535, 3, get(w, 1500232), 0, 0, 0, 0, 0, 0)
    if phase == 1535:
        put(w, 1500300, 0)
        return resume(s, o, w, 1600)
    return finish(o, w, 65)

def manifest(w:mutbuf) -> u64:
    at = 400000
    copyw(w, at, C_MANIFEST_PREFIX, L_MANIFEST_PREFIX)
    at = at + L_MANIFEST_PREFIX
    i = 0
    while i < 14:
        if i != 0:
            store(w, at, 44)
            at = at + 1
        store(w, at, 34)
        at = at + 1
        copyw(w, at, role_name(w, i), role_length(w, i))
        at = at + role_length(w, i)
        store(w, at, 34)
        store(w, at + 1, 58)
        store(w, at + 2, 34)
        at = hex_bytes(w, at + 3, 1501016 + i * 64, 32)
        store(w, at, 34)
        at = at + 1
        i = i + 1
    copyw(w, at, C_MANIFEST_SUFFIX, L_MANIFEST_SUFFIX)
    return at + L_MANIFEST_SUFFIX - 400000

def fd_text(w:mutbuf, at:u64, fd:u64) -> u64:
    copyw(w, at, C_FD, 3)
    end = decimal(w, at + 3, fd)
    store(w, end, 0)
    return end - at

def install_package(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    exec_args(w, C_CHILD, L_CHILD)
    put(w, 1510152, 60000000000)
    if get(w, 1500224) == 0:
        exec_add_arg(w, C_INSTALL, L_INSTALL)
    else:
        exec_add_arg(w, C_VERIFY, L_VERIFY)
    size = fd_text(w, 62000, uint(s, 32))
    exec_add_arg(w, 62000, size)
    hex_bytes(w, 7000, 1500184, 32)
    exec_add_arg(w, 7000, 64)
    exec_pass(w, uint(s, 32))
    return start_exec(o, w, uint(s, 64), get(w, 1500160), uint(s, 40), 0, 0, 0, 1520)

def whitespace(w:mutbuf, at:u64, end:u64) -> u64:
    while at < end:
        ch = byte(w, at)
        if ch != 9 and ch != 10 and ch != 13 and ch != 32:
            return at
        at = at + 1
    return at

def installer_receipt(w:mutbuf, size:u64) -> u64:
    end = 16384 + size
    at = whitespace(w, 16384, end)
    if at >= end or byte(w, at) != 123:
        return 0
    at = at + 1
    mask = 0
    count = 0
    while count < 5:
        at = whitespace(w, at, end)
        if at >= end or byte(w, at) != 34:
            return 0
        start = at + 1
        at = start
        while at < end and byte(w, at) != 34:
            at = at + 1
        if at >= end:
            return 0
        key = receipt_key(w, start, at - start)
        if key > 4 or mask & (1 << key) != 0:
            return 0
        mask = mask | (1 << key)
        at = whitespace(w, at + 1, end)
        if at >= end or byte(w, at) != 58:
            return 0
        at = whitespace(w, at + 1, end)
        if key == 0 or key == 1:
            at = number(w, at, end)
            expected = choose(key == 0, get(w, 1500168), 15)
            if at == 0 or get(w, 1542200) != expected:
                return 0
        if key == 2:
            if at + 4 <= end and same(w, at, C_TRUE, 4) == 1:
                if get(w, 1500224) != 0:
                    return 0
                at = at + 4
            else:
                if at + 5 > end or same(w, at, C_FALSE, 5) == 0:
                    return 0
                at = at + 5
        if key == 3:
            if at + L_INSTALL_SCHEMA + 2 > end or byte(w, at) != 34 or same(w, at + 1, C_INSTALL_SCHEMA, L_INSTALL_SCHEMA) == 0 or byte(w, at + L_INSTALL_SCHEMA + 1) != 34:
                return 0
            at = at + L_INSTALL_SCHEMA + 2
        if key == 4:
            if at + 66 > end or byte(w, at) != 34 or same(w, at + 1, 7000, 64) == 0 or byte(w, at + 65) != 34:
                return 0
            at = at + 66
        at = whitespace(w, at, end)
        count = count + 1
        if count < 5:
            if at >= end or byte(w, at) != 44:
                return 0
            at = at + 1
    if at >= end or byte(w, at) != 125 or mask != 31:
        return 0
    return choose(whitespace(w, at + 1, end) == end, 1, 0)

def receipt_key(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 5 and same(w, at, C_KEY_BYTES, 5) == 1:
        return 0
    if size == 5 and same(w, at, C_KEY_FILES, 5) == 1:
        return 1
    if size == 9 and same(w, at, C_KEY_PUBLISHED, 9) == 1:
        return 2
    if size == 6 and same(w, at, C_KEY_SCHEMA, 6) == 1:
        return 3
    if size == 6 and same(w, at, C_KEY_SHA, 6) == 1:
        return 4
    return 5

def cleanup(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1600:
        index = get(w, 1500300)
        if index == N_CLEAN_CASES:
            return call(o, w, 1610, 3, get(w, 1500024), 0, 0, 0, 0, 0, 0)
        row = C_CLEAN_CASES + index * 24
        return open_dir(o, w, get(w, 1500024), get(w, row), 1601)
    if phase == 1601:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500316, r)
        put(w, 1500324, 0)
        return cleanup_file(s, o, w)
    if phase == 1602:
        put(w, 1500324, get(w, 1500324) + 1)
        return cleanup_file(s, o, w)
    if phase == 1603:
        row = C_CLEAN_CASES + get(w, 1500300) * 24
        return call(o, w, 1604, 263, get(w, 1500024), get(w, row), 512, 0, 0, 0, 12)
    if phase == 1604:
        put(w, 1500300, get(w, 1500300) + 1)
        return resume(s, o, w, 1600)
    if phase == 1610:
        return call(o, w, 1611, 263, uint(s, 40), C_PROBE, 512, 0, 0, 0, 12)
    if phase == 1611:
        put(w, 1500300, 0)
        return resume(s, o, w, 1612)
    if phase == 1612:
        index = get(w, 1500300)
        if index == 15:
            return call(o, w, 1614, 3, get(w, 1500016), 0, 0, 0, 0, 0, 0)
        name = choose(index == 14, C_MANIFEST, role_name(w, index))
        return call(o, w, 1613, 263, get(w, 1500016), name, 0, 0, 0, 0, 12)
    if phase == 1613:
        put(w, 1500300, get(w, 1500300) + 1)
        return resume(s, o, w, 1612)
    if phase == 1614:
        return call(o, w, 1615, 263, uint(s, 40), C_STAGE, 512, 0, 0, 0, 12)
    if phase == 1615:
        return call(o, w, 1616, 74, uint(s, 40), 0, 0, 0, 0, 0, 0)
    if phase == 1616:
        return call(o, w, 1617, 74, uint(s, 32), 0, 0, 0, 0, 0, 0)
    if phase == 1617:
        put(w, 16384, MAGIC_OUTPUT)
        put(w, 16392, 25)
        put(w, 16400, 15)
        copyw(w, 16408, 1500184, 32)
        copyw(w, 16440, 1500120, 32)
        put(w, 16472, 0)
        put(w, 1500332, 0)
        return call(o, w, 1700, 1, 1, 16384, 96, 0, 0, 0, 12)
    if phase == 1700:
        if r == 18446744073709551612:
            return call(o, w, 1700, 1, 1, 16384 + get(w, 1500332), 96 - get(w, 1500332), 0, 0, 0, 12)
        if r == 0 or r > 96 - get(w, 1500332):
            return finish(o, w, 74)
        put(w, 1500332, get(w, 1500332) + r)
        if get(w, 1500332) != 96:
            return call(o, w, 1700, 1, 1, 16384 + get(w, 1500332), 96 - get(w, 1500332), 0, 0, 0, 12)
        return finish(o, w, 0)
    return finish(o, w, 65)

def cleanup_file(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    row = C_CLEAN_CASES + get(w, 1500300) * 24
    index = get(w, 1500324)
    if index == get(w, row + 8):
        return call(o, w, 1603, 3, get(w, 1500316), 0, 0, 0, 0, 0, 0)
    return call(o, w, 1602, 263, get(w, 1500316), get(w, get(w, row + 16) + index * 8), 0, 0, 0, 0, 12)
"""
TEXT.update({'LOCK_CASE':b'file-lock','MARKER_CASE':b'markers','CUSTODY_CASE':b'custody','JOB_CASE':b'native-job'})
MAGICS.update({'LOCK_FILE':b'HIAJLF01','MARKER':b'HIAJMK01','CUSTODY':b'HIAJLH01','WRITER_REPLY':b'HIAJRW01'})
MAGICS['ELF']=b'\x7fELF\x02\x01\x01\0'
POLICY=POLICY.replace('282579962709375','MAGIC_ELF')


TEXT.update({'TIME_PREFIX':b'{"at_unix_ms":',
 'WITNESS_PREFIX':b'{"exit_sha256":"',
 'WITNESS_SUFFIX':b'","job_id":"native-owner-admission","launch_nonce":"'+b'5'*32+b'","terminal_publication_protocol":1}\n',
 'STARTED_BODY':b',"invocation_id":null,"job_id":"native-owner-admission","launch_nonce":"'+b'5'*32+b'","supervisor_identity":{"kind":"proc_start_ticks","value":"',
 'PID':b'"},"supervisor_pid":','UID':b',"supervisor_uid":',
 'CHILD_PREFIX':b'{"identity":{"kind":"proc_start_ticks","value":"','CHILD_PID':b'"},"pid":'})
_terminal={'at_unix_ms':0,'cancelled':False,'exit_code':2,'job_id':'native-owner-admission','launch_nonce':'5'*32,
 'log_bytes':{'stderr':{'seen':0,'stored':0},'stdout':{'seen':0,'stored':0}},
 'log_eof':{'stderr':True,'stdout':True},'log_errors':{'stderr':None,'stdout':None},
 'log_synced':{'stderr':True,'stdout':True},'log_truncated':{'stderr':False,'stdout':False},
 'output_complete':True,'output_durable':True,'terminal_publication_protocol':1,'timed_out':False}
TEXT['TERMINAL_SUFFIX']=compact(_terminal)[len(TEXT['TIME_PREFIX'])+1:]
OWNER_FILES=('child.json','exit.json','exit.witness.json','native-exit.bin','owner-intent.json','owner.lock','started.json','stderr.log','stdout.log')

TEXT.update({'KEY_BYTES':b'bytes','KEY_FILES':b'files','KEY_PUBLISHED':b'published','KEY_SCHEMA':b'schema','KEY_SHA':b'sha256','TRUE':b'true','FALSE':b'false','INSTALL_SCHEMA':b'hepta.hia.release-install.v1'})

def constants():
    words={}; lines=[]; cursor=600000
    def word(at,value): lines.append(f'    put(w, {at}, {value})')
    def data(name,raw):
        nonlocal cursor
        start=cursor
        words['C_'+name]=start;words['L_'+name]=len(raw)
        for offset in range(0,len(raw)+1,8):
            word(start+offset,int.from_bytes((raw+b'\0')[offset:offset+8].ljust(8,b'\0'),'little'))
        cursor=(cursor+len(raw)+16)&~7
        return start
    for name,raw in TEXT.items(): data(name,raw)
    rows=[]
    for i,role in enumerate(ROLES):
        raw=role.encode(); rows.append((data('ROLE_'+str(i),raw),len(raw)))
    words['C_ROLES']=cursor
    for row in rows:
        for v in row: word(cursor,v);cursor+=8
    rows=[]
    for i,(role,frame,code,out,err) in enumerate(PURE):
        assert not err
        rows.append((role,data('PURE_FRAME_'+str(i),frame),len(frame),code,
                     data('PURE_EXPECT_'+str(i),struct.pack('<Q',len(out))+out)))
    words['C_PURE']=cursor;words['N_PURE']=len(rows)
    for row in rows:
        for v in row:word(cursor,v);cursor+=8
    rows=[]
    for i,(frame,parent_at,code,err,records) in enumerate(WRITERS):
        name=data('WRITER_CASE_'+str(i),('writer-'+str(i)).encode())
        source=data('WRITER_FRAME_'+str(i),frame)
        expected=data('WRITER_EXPECT_'+str(i),err)
        files=[]
        for j,(filename,raw) in enumerate(records):
            files.append((data('WRITER_FILE_'+str(i)+'_'+str(j),filename.encode()),len(filename),
                          data('WRITER_BODY_'+str(i)+'_'+str(j),raw),len(raw)))
        table=cursor
        for row in files:
            for value in row:word(cursor,value);cursor+=8
        rows.append((name,source,len(frame),parent_at,code,expected,len(records),table))
    words['C_WRITERS']=cursor;words['N_WRITERS']=len(rows)
    for row in rows:
        for value in row:word(cursor,value);cursor+=8
    owner_files=[]
    for i,name in enumerate(OWNER_FILES):
        owner_files.append((data('OWNER_FILE_'+str(i),name.encode()),len(name),0,0))
    words['C_OWNER_FILES']=cursor
    for row in owner_files:
        for value in row:word(cursor,value);cursor+=8
    clean=[]
    for i,(_,_,_,_,records) in enumerate(WRITERS):
        clean.append(('writer-'+str(i),tuple(name for name,_ in records)))
    clean.extend((('file-lock',('owner.lock',)),('markers',('owner-intent.json','exit.json','exit.witness.json.tmp')),('custody',('owner.lock',)),('native-job',OWNER_FILES)))
    clean_rows=[]
    for i,(name,files) in enumerate(clean):
        name_at=data('CLEAN_CASE_'+str(i),name.encode())
        file_names=[data('CLEAN_FILE_'+str(i)+'_'+str(j),n.encode()) for j,n in enumerate(files)]
        at=cursor
        for value in file_names:word(cursor,value);cursor+=8
        clean_rows.append((name_at,len(files),at))
    words['C_CLEAN_CASES']=cursor;words['N_CLEAN_CASES']=len(clean_rows)
    for row in clean_rows:
        for value in row:word(cursor,value);cursor+=8
    words['C_MARKERS']=cursor
    for marker in MARKERS:word(cursor,int.from_bytes(marker,'little'));cursor+=8
    words.update({'MAGIC_'+k:int.from_bytes(v,'little') for k,v in MAGICS.items()})
    words.update({'ROLE_WRITER':ROLES.index('hia-job-receipt'),
                  'ROLE_PREPARE':ROLES.index('hia-worker-prepare'),
                  'ROLE_OWNER':ROLES.index('hia-job-supervisor')})
    assert cursor<700000,cursor
    groups=[lines[i:i+384] for i in range(0,len(lines),384)]
    init='def constants(w:mutbuf) -> u64:\n'+'\n'.join(f'    constants_{i}(w)' for i in range(len(groups)))+'\n    return 0\n'
    for i,group in enumerate(groups):
        init+=f'\ndef constants_{i}(w:mutbuf) -> u64:\n'+'\n'.join(group)+'\n    return 0\n'
    return words,init

def policy_source(stage=False):
    words,init=constants()
    own=(PROBES+'\n'+LOCKS+'\n'+OWNERS) if stage else (POLICY+'\n'+PUBLISH+'\n'+init)
    available={}
    for raw in (RELEASE_HELPERS,COMMON,POLICY,PROBES,LOCKS,OWNERS):
        t=ast.parse(raw)
        available.update({n.name:ast.get_source_segment(raw,n) for n in t.body if isinstance(n,ast.FunctionDef)})
    own_names={n.name for n in ast.parse(own).body if isinstance(n,ast.FunctionDef)}
    needed=set();pending=[own]
    while pending:
        code=pending.pop()
        for n in ast.walk(ast.parse(code)):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):
                name=n.func.id
                if name in available and name not in own_names and name not in needed:
                    needed.add(name);pending.append(available[name])
    code=own+'\n'+'\n\n'.join(available[n] for n in available if n in needed)
    for key,value in words.items():code=re.sub(r'\b'+key+r'\b',str(value),code)
    unknown=re.findall(r'\b(?:C|L|N|MAGIC|ROLE)_[A-Z_0-9]+\b',code)
    assert not unknown,sorted(set(unknown))
    return code

def template():
    with tempfile.TemporaryDirectory(prefix='hia-controller-author-') as tmp:
        obj=Path(tmp)/'abi.o';raw=Path(tmp)/'abi.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_controller_install_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(at,16) for at,_,name in (row.split() for row in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
        code=raw.read_bytes()
    head=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
          +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
          +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return head+code,{n:176+symbols[n] for n in ('policy_hole','stage_hole','sha_hole')}

def packer_source():
    prefix,holes=template()
    magic=int.from_bytes(b'HIACTIK1','little')
    code=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or uint(s, 0, 8) != {magic}:
        return 4294967295
    policy = uint(s, 8, 8)
    probe = uint(s, 16, 8)
    sha = uint(s, 24, 8)
    if policy == 0 or probe == 0 or sha == 0 or policy > 1048576 or probe > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 32 + policy + probe + sha:
        return 4294967295
    size = {len(prefix)} + policy + probe + sha
    if size > 2097152 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        part=prefix[at:at+8];code+=f'    write(o, {at}, {int.from_bytes(part,"little")}, {len(part)})\n'
    code+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name,at in holes.items():
        target=str(len(prefix))+(' + policy + probe' if name=='sha_hole' else ' + policy' if name=='stage_hole' else '')
        code+=f'    write(o, {at}, {target} - {at+4}, 4)\n'
    code+=f'    copy_bytes(s, o, 32, {len(prefix)}, policy + probe + sha)\n    return size\n'
    return code+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def main():
    for name,code in (('controller_install',policy_source()),('controller_probe',policy_source(True)),
                      ('controller_install_packer',packer_source())):
        doc=document(code,name)
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        path.write_text(render_assembly(doc))
        print(name,path.stat().st_size,'blocks',sum(len(f['blocks']) for f in doc['functions']),
              'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
