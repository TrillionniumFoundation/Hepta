"""Encode only an oversized metadata original; leave the frozen request and first draft intact."""
from pathlib import Path
import base64,gzip,hashlib,json,os,stat
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3')
OLD=ROOT/'publication/payload';PUB=ROOT/'publication-r2';PREFIX='experiments/hia_sqlite_varint_20261113/native-finite-ai395-r3'
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path):
    s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    ident=lambda t:[t.st_dev,t.st_ino,t.st_mode,t.st_uid,t.st_gid,t.st_nlink,t.st_size,t.st_mtime_ns,t.st_ctime_ns]
    try:
        assert ident(s)==ident(os.fstat(fd));parts=[];count=0
        while True:
            b=os.read(fd,1<<20)
            if not b:break
            parts.append(b);count+=len(b);assert count<=s.st_size
        assert count==s.st_size and ident(s)==ident(os.fstat(fd))==ident(path.lstat())
    finally:os.close(fd)
    b=b''.join(parts)
    return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'identity':ident(s)},b
def write(path,b):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o600);p,raw=read(path);assert raw==b;return p
assert not PUB.exists()
PUB.mkdir(mode=0o700);payload=PUB/'payload';payload.mkdir(mode=0o700)
files=[];oversized=[]
def add(path,name):
    p,b=read(path);b.decode('utf-8');assert p['bytes']<1<<20
    files.append({'path':PREFIX+'/'+name,'relative_path':name,'local_path':str(path),'mode':'100644','type':'blob','sha':p['git_blob'],'sha256':p['sha256'],'size':p['bytes']})
for path in sorted(OLD.rglob('*')):
    if not path.is_file():continue
    p,b=read(path);name=str(path.relative_to(OLD))
    if p['bytes']>=1<<20:
        oversized.append(name);assert name=='SOURCE-BASE.json'
        actualpin,actual=read(ROOT/name);assert actual==b
        compressed=gzip.compress(b,compresslevel=9,mtime=0)
        encoded=base64.b64encode(compressed)
        carrier=payload/'source-base.original.json.gz.b64';cp=write(carrier,encoded)
        assert gzip.decompress(base64.b64decode(read(carrier)[1],validate=True))==b
        proof={'schema':'hia.sqlite.varint.r3.source-manifest-lossless-carrier.v1','original_relative_path':name,
          'original':actualpin,'gzip_bytes':len(compressed),'gzip_sha256':hashlib.sha256(compressed).hexdigest(),
          'carrier':{k:cp[k] for k in ('bytes','sha256','git_blob')},'carrier_path':carrier.name,
          'whole_original_independent_recovery_equal':True,'input_original_unchanged':True,
          'recovery':'base64 decode carrier, verify gzip SHA, gzip decompress, verify original byte count/SHA256/Git blob. Restore original exact SOURCE-BASE.json bytes; this does not recreate historical inode/ctime.'}
        mp=payload/'SOURCE-BASE-CARRIER.json';write(mp,wire(proof));add(carrier,carrier.name);add(mp,mp.name)
    else:add(path,name)
assert oversized==['SOURCE-BASE.json']
for name,text in {"PUBLICATION-R1-ACK.json":"{\n  \"content\": [\n    {\n      \"type\": \"text\",\n      \"text\": \"{\\n  \\\"audit_recorded\\\": true,\\n  \\\"job\\\": {\\n    \\\"args\\\": [\\n      \\\"-c\\\",\\n      \\\"/usr/bin/python3.14 -I -S -B /home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3/proof/prepare_publication.py\\\"\\n    ],\\n    \\\"created_unix_ms\\\": 1794550924722,\\n    \\\"cwd\\\": \\\"/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3\\\",\\n    \\\"env_keys\\\": [],\\n    \\\"executable\\\": \\\"/bin/sh\\\",\\n    \\\"execution_mode\\\": \\\"operator\\\",\\n    \\\"host\\\": \\\"ai395\\\",\\n    \\\"id\\\": \\\"1a1d39205b2-392-16a\\\",\\n    \\\"idempotency_key\\\": \\\"cold-varint-r3-static-delta-package-r1\\\",\\n    \\\"launch_error\\\": null,\\n    \\\"launch_state\\\": \\\"launched\\\",\\n    \\\"remote_job_dir\\\": \\\"/home/qq/.local/state/hepta-runtime-mac-worker/jobs/1a1d39205b2-392-16a\\\",\\n    \\\"request_digest\\\": \\\"4e50115483b89426ed98ac8ed5ba7e51b613c3971b95232dcdb85642a5520109\\\",\\n    \\\"request_fingerprint\\\": 5643029387780068390,\\n    \\\"ssh_target\\\": \\\"ai395-lan\\\",\\n    \\\"system_jobctl\\\": false,\\n    \\\"unit\\\": \\\"hepta-runtime-job-1a1d39205b2-392-16a\\\"\\n  },\\n  \\\"launch\\\": {\\n    \\\"backend\\\": \\\"systemd\\\",\\n    \\\"launcher_pid\\\": null,\\n    \\\"ok\\\": true,\\n    \\\"unit\\\": \\\"hepta-runtime-job-1a1d39205b2-392-16a\\\"\\n  },\\n  \\\"local_record_pending\\\": false,\\n  \\\"reused\\\": false\\n}\"\n    }\n  ],\n  \"structuredContent\": null,\n  \"isError\": false\n}\n","PUBLICATION-R1-STATUS.json":"{\n  \"status\": \"fulfilled\",\n  \"value\": {\n    \"content\": [\n      {\n        \"type\": \"text\",\n        \"text\": \"{\\n  \\\"at_unix_ms\\\": 1794550925718,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 1,\\n  \\\"job_id\\\": \\\"1a1d39205b2-392-16a\\\",\\n  \\\"launch_nonce\\\": \\\"227508a0fcc014b9b8976dab1b1f1b76\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 221,\\n      \\\"stored\\\": 221\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"failed\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\"\n      }\n    ],\n    \"structuredContent\": null,\n    \"isError\": false\n  }\n}\n","PUBLICATION-R1-OUTPUT.json":"{\n  \"status\": \"fulfilled\",\n  \"value\": {\n    \"content\": [\n      {\n        \"type\": \"text\",\n        \"text\": \"{\\n  \\\"audit_recorded\\\": true,\\n  \\\"job_id\\\": \\\"1a1d39205b2-392-16a\\\",\\n  \\\"stderr\\\": {\\n    \\\"bytes_hex\\\": \\\"54726163656261636b20286d6f737420726563656e742063616c6c206c617374293a0a202046696c6520222f686f6d652f71712f6869612d726577726974652d32303236313131332d653236652d72312f766172696e742d6e61746976652d72332f70726f6f662f707265706172655f7075626c69636174696f6e2e7079222c206c696e652037322c20696e203c6d6f64756c653e0a2020202061737365727420705b276279746573275d3c313c3c32300a20202020202020202020205e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0a417373657274696f6e4572726f720a\\\",\\n    \\\"eof\\\": true,\\n    \\\"next_offset\\\": 221,\\n    \\\"offset\\\": 0,\\n    \\\"size\\\": 221,\\n    \\\"text\\\": \\\"Traceback (most recent call last):\\\\n  File \\\\\\\"/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r3/proof/prepare_publication.py\\\\\\\", line 72, in <module>\\\\n    assert p['bytes']<1<<20\\\\n           ^^^^^^^^^^^^^^^^\\\\nAssertionError\\\\n\\\"\\n  },\\n  \\\"stdout\\\": {\\n    \\\"bytes_hex\\\": \\\"\\\",\\n    \\\"eof\\\": true,\\n    \\\"next_offset\\\": 0,\\n    \\\"offset\\\": 0,\\n    \\\"size\\\": 0,\\n    \\\"text\\\": \\\"\\\"\\n  }\\n}\"\n      }\n    ],\n    \"structuredContent\": null,\n    \"isError\": false\n  }\n}\n"}.items():
    path=payload/'history'/name;write(path,text.encode());add(path,'history/'+name)
path=payload/'publication-carrier-author.py';write(path,read(Path(__file__))[1]);add(path,path.name)
plan={'schema':'hia.sqlite.varint.r3.delta-publication-plan.v2','status':'LOCAL_DELTA_FROZEN_UNEXECUTED',
 'parent_commit':'307708ebd56803dad5b52f3986988313a9765429','parent_tree':'7928280c3c6dfd24217afac0c9d9047386ab7569',
 'repository':'TrillionniumFoundation/Hepta','prefix':PREFIX,'files':sorted(files,key=lambda x:x['path']),
 'oversized_originals_losslessly_encoded':oversized,'runtime_input_files_unchanged':94,
 'first_publication_draft_status':'Closed static authoring assertion at >1MiB metadata, 0 Git mutation, no qualification execution.'}
write(PUB/'PLAN.json',wire(plan))
print(json.dumps({'files':len(files),'bytes':sum(x['size'] for x in files),'plan':read(PUB/'PLAN.json')[0],
                  'native_or_source_controls_executed':False}))
