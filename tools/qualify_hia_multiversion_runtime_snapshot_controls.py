from pathlib import Path
import importlib.util,json,struct,concurrent.futures,ctypes
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');Q=T/'multiversion-runtime-snapshot-qa'
from tools import qualify_hia_multiversion_runtime_snapshot as h
Q=h.Q;T=h.T
D=Q/'controls-v1';D.mkdir();n=h.Native(Q/'native-v4/snapshot.flat');rows=[]
def fields(raw):
 kind,flags,count,size=struct.unpack_from('<4Q',raw)
 return kind,flags,[raw[a:a+b]for a,b in [struct.unpack_from('<2Q',raw,32+16*i)for i in range(count)]]
def replace(raw,index,data):
 kind,flags,parts=fields(raw);parts[index]=data;return h.frame(kind,parts,flags)
def changed_word(raw,at,value):
 b=bytearray(raw);struct.pack_into('<Q',b,at,value);return bytes(b)
def bad(label,record):
 status,o,w,_=n.run(h.packet(record),4096,1048576);assert status==h.U,(label,status);rows.append({'case':label})
base=h.pin().wire
for i in [0,8,16,24,32,40,64,80]:
 for x in [h.U,h.U-7]:
  bad('frame-u64-'+str(i)+'-'+str(x),changed_word(base,i,x))
kind,flags,parts=fields(base)
for index in [3,4,5,7,10,11,22,40,43]:
 b=changed_word(parts[1],index*8,2);bad('state-bool-'+str(index),replace(base,1,b))
for index,cap in [(12,4),(23,4),(24,4),(29,7)]:
 bad('state-enum-'+str(index),replace(base,1,changed_word(parts[1],index*8,cap)))
bad('state-magic',replace(base,1,changed_word(parts[1],0,0)))
for size in [0,1,511,4607,4609]:
 bad('state-size-'+str(size),replace(base,1,parts[1][:size]+(b'x'if size>4608 else b'')))
bad('foreign-without-fence',replace(base,6,h.jbytes({'stage':2})))
for text in [b'\x80',b'\xc0\x80',b'\xc1\x80',b'\xf5\x80\x80\x80',b'\xe0\x80\x80',b'\xf0\x80\x80\x80',b'\xf4\x90\x80\x80',b'\xc2',b'\xe2\x82',b'\xf0\x90\x80',b'\xc2a']:
 bad('text-invalid-'+text.hex(),h.frame(7,[text,b'',b'message']))
for dec in [b'',b'+1',b'-1',b'00',b'01',b'1.0',b'1e2',b'NaN',b' 1',b'1 ',b'1\0']:
 bad('clock-decimal-'+dec.hex(),replace(h.observation().wire,1,dec))
for dec in [b'-0',b'-01',b'+1',b'01',b'--1']:
 bad('errno-noncanonical-'+dec.hex(),h.frame(7,[b'OSError',dec,b'error']))
for flags in [7,8,15,24,h.U]:
 bad('observation-flags-'+str(flags),changed_word(h.observation().wire,8,flags))
for flags in [2,6,7,8,24,h.U]:
 bad('directory-flags-'+str(flags),changed_word(h.directory(status=1).wire,8,flags))
bad('directory-notattempted-has-path',replace(h.directory().wire,0,b'/actual'))
bad('task-bad-native-error',replace(h.task(attempted=False,disk_attempts=0).wire,6,h.error(OSError(5,'Input/output error'))[0]))
bad('task-unattempted-disk-before',replace(h.task(disk_attempts=0).wire,8,h.observation().wire))
for size in [1,8,15,17]:
 bad('inode-size-'+str(size),replace(h.observation().wire,2,b'\0'*size))
bad('error-unknown-kind',h.frame(13,[]))
bad('error-opaque-empty',h.frame(11,[b'']))
bad('error-opaque-nonobject',h.frame(11,[b'[]']))
bad('error-no-filename-has-bytes',h.frame(12,[b'13',b'/actual']))
# Threaded use of the same code mapping with disjoint private work/output.
cases=[h.pin(bound=True,held=True,attempted=True),h.task(),h.observation(),h.directory(status=4),h.Item(*h.oserror(13,b'/abc'))]
def call(pair):
 i,item=pair;raw=h.packet(item.wire);ex=h.jbytes(item.expected)
 status,out,w,_=n.run(raw,len(ex),65536,offset=i%8,poison=(i%255)+1)
 assert status==len(ex)and out==ex
 return h.sha(out)
pairs=[(i,cases[i%len(cases)])for i in range(64)]
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as ex:results=list(ex.map(call,pairs))
rows.append({'case':'four-thread-64-calls','observed':len(results),'digest':h.sha(''.join(results).encode())})
(D/'report.json').write_text(json.dumps({'status':'PASS','cases':len(rows),'native_sha256':h.sha(n.raw),'rows':rows},indent=2)+'\n');print('SNAPSHOT_CONTROLS_PASS',len(rows),flush=True)
