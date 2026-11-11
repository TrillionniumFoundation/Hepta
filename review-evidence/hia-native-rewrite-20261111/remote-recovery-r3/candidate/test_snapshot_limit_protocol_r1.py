"""Replay a real role-59 continuation and corrupt only the new private witness."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
sys.dont_write_bytecode = True
REFERENCE = BASE.parent / "reference-0ef-r2"
sys.path[:0] = [str(REFERENCE), str(BASE / "native-edit-controller-next/tools")]
import ctypes,mmap
class Buffer:
    def __init__(self,size,raw=b"",readonly=False):
        assert type(size) is int and 0<=size<=128<<20
        assert type(raw) is bytes and len(raw)<=size
        self.size=size
        page=mmap.PAGESIZE
        payload_pages=((max(1,size)+64+page-1)//page)*page
        self._map=mmap.mmap(-1,payload_pages+2*page,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        start=ctypes.addressof(ctypes.c_char.from_buffer(self._map))
        self.address=start+page+32
        self._prefix=b"\xa5"*32;self._suffix=b"\x5a"*32
        ctypes.memmove(self.address-32,self._prefix,32)
        ctypes.memmove(self.address+size,self._suffix,32)
        if raw:ctypes.memmove(self.address,raw,len(raw))
        libc=ctypes.CDLL(None,use_errno=True)
        libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        libc.mprotect.restype=ctypes.c_int
        for address,extent,protection in [(start,page,0),(start+page+payload_pages,page,0)]:
            if libc.mprotect(address,extent,protection):
                raise OSError(ctypes.get_errno(),"guard native packing buffer")
        if readonly and libc.mprotect(start+page,payload_pages,mmap.PROT_READ):
            raise OSError(ctypes.get_errno(),"protect native packing input")
    def check(self):
        assert ctypes.string_at(self.address-32,32)==self._prefix
        assert ctypes.string_at(self.address+self.size,32)==self._suffix
    def read(self,offset,size):
        assert type(offset) is int and type(size) is int and 0<=offset<=self.size and 0<=size<=self.size-offset
        return ctypes.string_at(self.address+offset,size)
    def close(self):
        self._map.close()

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hia_edit_controller_common import CONSTANTS as C
OUT = ROOT / 'development/snapshot-limit-protocol-r1'
OUT.mkdir(exist_ok=False)
CAS = OUT / 'cas'
CAS.mkdir()
capture = BASE / 'native-edit-candidate-next/development/captured-candidate-continuation-r1/source.json'
capture_raw = capture.read_bytes()
captured = json.loads(capture_raw)
data = {}
for row in captured['payloads']:
    old_path = row['compressed_path']
    prefix = "/workspace/scratch/9acdfa9f5639/"
    compressed_path = BASE / old_path[len(prefix):] if old_path.startswith(prefix) else Path(old_path)
    compressed = compressed_path.read_bytes()
    assert sha256(compressed).hexdigest() == row['compressed_sha256']
    raw = zlib.decompress(compressed)
    assert (len(raw), sha256(raw).hexdigest()) == (row['full_bytes'], row['full_sha256'])
    data[row['label']] = raw
compile_raw = (ROOT / 'development/compile-r1/summary.json').read_bytes()
component = json.loads(compile_raw)['components']['59']
source = Path(component['source_path']).read_bytes()
image_raw = Path(component['image_path']).read_bytes()
assert sha256(source).hexdigest() == component['source_sha256']
assert sha256(image_raw).hexdigest() == component['image_sha256']
image = NativeHiaJsonImage(image_raw, component['image_sha256'])
MAGIC = int.from_bytes(b'HIAPLB01', 'little')
MESSAGE = b'E_HIA_LIMIT: program exceeds byte budget before encoding'
GENERIC = b'E_HIA_EDIT: patch input, node, depth or output capacity exceeded'
entries, rows = [], []
started = time.monotonic_ns()
summary = dict(status='INCOMPLETE', scope='PRIVATE_CANDIDATE_BYTE_AND_SNAPSHOT_WITNESSES_NOT_PUBLIC_REACHABILITY', whole_stack_closed=False)


def saved(raw):
    digest = sha256(raw).hexdigest()
    path = CAS / (digest + '.zlib')
    if path.exists():
        assert zlib.decompress(path.read_bytes()) == raw
    else:
        path.write_bytes(zlib.compress(raw, 9))
        assert zlib.decompress(path.read_bytes()) == raw
    return dict(bytes=len(raw), sha256=digest, path=str(path))


def q(raw, field):
    return struct.unpack_from('<Q', raw, C[field])[0]


def call(label, command, before):
    a, o, w = Buffer(len(command), command, True), Buffer(128), Buffer(len(before), before)
    try:
        result = int(image._entry(a.address, a.size, o.address, o.size, w.address, w.size))
        for item in (a, o, w):
            item.check()
        assert a.read(0, a.size) == command
        after, event = w.read(0, w.size), o.read(0, o.size)
        entries.append(dict(label=label, result=result, input=saved(command), before=saved(before), after=saved(after), event=saved(event)))
        return result, after, event
    finally:
        a.close(); o.close(); w.close()


def change(command, fields):
    raw = bytearray(command)
    for at, value in fields.items():
        struct.pack_into('<Q', raw, at, value)
    return bytes(raw)


try:
    result, _, event = call('unchanged-real-success-continuation', data['command'], data['before'])
    assert result == 128 and event == data['event']
    rows.append(dict(case='unchanged-real-success-continuation', status='PASS'))
    witness = change(data['command'], {40: 0xfffffffe, 64: MAGIC, 72: 1, 80: (8 << 20) + 1, 88: 1})
    for label, command, domain, stage, message in (
        ('valid-byte-limit-witness', witness, 2, 205, MESSAGE),
        ('unmarked-capacity-status-stays-generic', change(witness, {64: 0}), 1, 202, GENERIC)):
        result, after, event = call(label, command, data['before'])
        assert result == 128
        frame = struct.unpack('<16Q', event)
        assert frame[1] == 2 and frame[4:6] == (30, len(message))
        assert q(after, 'PUBLISH_DOMAIN') == domain and q(after, 'PUBLISH_STAGE') == stage and q(after, 'PUBLISH_CODE') == 0xfffffffe
        assert q(after, 'PUBLISH_ERROR_SOURCE') == 2 and q(after, 'PUBLISH_ERROR_BYTES') == len(message)
        at = q(after, 'PUBLISH_ERROR_AT')
        assert after[at:at+len(message)] == message
        rows.append(dict(case=label, status='PASS', actual_text=message.decode(), domain=domain))
    changes = [('wrong-native-return', {40: 0}), ('wrong-limit-code', {40: 0xffffffff}),
               ('wrong-ABI-zero', {72: 0}), ('wrong-ABI-two', {72: 2}),
               ('wrong-cause-zero', {88: 0}), ('wrong-cause-two', {88: 2}),
               ('zero-size', {80: 0}), ('legal-size-not-a-limit', {80: 8 << 20}),
               ('outside-owned-output', {80: (16 << 20) + 1}), ('overflow-size', {80: (1 << 64)-1}),
               ('wrong-lease', {8: 0}), ('wrong-sequence', {16: 0}), ('failed-native-ACK', {32: 1})]
    for label, fields in changes:
        result, after, _ = call(label, change(witness, fields), data['before'])
        assert result == 0xfffffffd, (label, result)
        result, _, _ = call(label+'-after-poison', witness, after)
        assert result == 0xfffffffd, (label, result)
        rows.append(dict(case=label, status='PASS', permanently_refused=True))
    result, after, _ = call('truncated-witness', witness[:-1], data['before'])
    assert result == 0xfffffffd
    result, _, _ = call('truncated-witness-after-poison', witness, after)
    assert result == 0xfffffffd
    rows.append(dict(case='truncated-witness', status='PASS', permanently_refused=True))

    assert len(rows) == 17 and len(entries) == 31
    snapshot_magic = int.from_bytes(b'HIAPLS01','little')
    snapshot_message = b'E_HIA_LIMIT: caller-owned tree exceeds snapshot budget'
    queued_message = b'E_HIA_LIMIT: caller-owned tree exceeds queued-node budget'
    def snapshot(reason=1,seen=80,depth=65,queued=4,children=0):
        return change(data['command'],{40:0xfffffffe,64:snapshot_magic,
            72:1 | (reason << 32),80:seen | (depth << 32),88:queued | (children << 32)})
    depth_witness = snapshot()
    count_witness = snapshot(seen=262145,depth=1,queued=0)
    queued_witness = snapshot(reason=2,seen=262140,depth=9,queued=2,children=3)
    for label,command,stage,message in (
        ('valid-depth65-snapshot-witness',depth_witness,206,snapshot_message),
        ('valid-count262145-defensive-witness',count_witness,206,snapshot_message),
        ('valid-queued-node-witness',queued_witness,207,queued_message)):
        result,after,event = call(label,command,data['before'])
        assert result == 128, (label,result)
        frame=struct.unpack('<16Q',event)
        assert frame[1] == 2 and frame[4:6] == (30,len(message))
        assert q(after,'PUBLISH_DOMAIN') == 2 and q(after,'PUBLISH_STAGE') == stage and q(after,'PUBLISH_CODE') == 0xfffffffe
        assert q(after,'PUBLISH_ERROR_SOURCE') == 2 and q(after,'PUBLISH_ERROR_BYTES') == len(message)
        at=q(after,'PUBLISH_ERROR_AT')
        assert after[at:at+len(message)] == message
        rows.append(dict(case=label,status='PASS',domain=2,actual_text=message.decode(),private_only=True))
    invalid = [
      ('snapshot-wrong-native-return',change(depth_witness,{40:0})),
      ('snapshot-wrong-limit-code',change(depth_witness,{40:0xffffffff})),
      ('snapshot-ABI-zero',change(depth_witness,{72:1 << 32})),
      ('snapshot-ABI-two',change(depth_witness,{72:2 | (1 << 32)})),
      ('snapshot-cause-zero',change(depth_witness,{72:1})),
      ('snapshot-cause-three',change(depth_witness,{72:1 | (3 << 32)})),
      ('snapshot-seen-zero',snapshot(seen=0)),
      ('snapshot-seen-above-maximum',snapshot(seen=262146)),
      ('snapshot-depth66',snapshot(depth=66)),
      ('snapshot-queued-above-maximum',snapshot(queued=262145)),
      ('snapshot-children-above-maximum',snapshot(children=262145)),
      ('snapshot-not-actually-exceeded',snapshot(depth=64)),
      ('snapshot-children-present',snapshot(children=1)),
      ('snapshot-count-exceeded-with-queue',snapshot(seen=262145,depth=1,queued=1)),
      ('snapshot-depth-exceeded-invalid-queue',snapshot(seen=262140,queued=5)),
      ('queued-witness-seen-exceeded',snapshot(reason=2,seen=262145,depth=9,queued=0,children=1)),
      ('queued-witness-depth-exceeded',snapshot(reason=2,seen=80,depth=65,queued=4,children=262061)),
      ('queued-witness-invalid-queue',snapshot(reason=2,seen=262140,depth=9,queued=5,children=1)),
      ('queued-witness-children-fit-exactly',snapshot(reason=2,seen=262140,depth=9,queued=2,children=2)),
      ('queued-witness-children-zero',snapshot(reason=2,seen=262140,depth=9,queued=2,children=0)),
      ('snapshot-wrong-lease',change(depth_witness,{8:0})),
      ('snapshot-wrong-sequence',change(depth_witness,{16:0})),
      ('snapshot-failed-native-ACK',change(depth_witness,{32:1})),
      ('snapshot-truncated-frame',depth_witness[:-1]),
    ]
    for label,command in invalid:
        result,after,_ = call(label,command,data['before'])
        assert result == 0xfffffffd,(label,result)
        result,_,_ = call(label+'-after-poison',depth_witness,after)
        assert result == 0xfffffffd,(label,result)
        rows.append(dict(case=label,status='PASS',permanently_refused=True))
    assert len(rows) == 44 and len(entries) == 82
    summary.update(status='PASS', cases=len(rows), actual_entries=len(entries), results=rows)
except BaseException as exc:
    summary.update(status='FAIL', completed_cases=rows, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    image._mapping.close()
    (OUT / 'entries.json').write_text(json.dumps(entries, indent=2, sort_keys=True) + '\n')
    summary.update(elapsed_ns=time.monotonic_ns()-started,
                   production_source_and_image_unchanged=Path(component['source_path']).read_bytes() == source and Path(component['image_path']).read_bytes() == image_raw,
                   captured_original_metadata_unchanged=capture.read_bytes() == capture_raw)
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('results', 'completed_cases')}, sort_keys=True), flush=True)
