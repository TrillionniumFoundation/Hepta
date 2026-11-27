#!/usr/bin/env python3
"""Preserve complete root static readers, failures, records, and execution receipts."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
BASE=Path("/tmp/hia-progress-v148-20261114-dda7")
OUT=BASE/"root-readback-custody-r1"
OUT.mkdir(exist_ok=False)
(OUT/"parts").mkdir()
FILES=["root_io.py","admit_op13_preparation.py","OP13-PREPARATION-AUTHORIZATION.json","op13-preparation-admission-r1/FULL-FRESH-READBACK.json","op13-preparation-admission-r1/RESULT.json","review_r4_author.py","R4-ROOT-STATIC-REVIEW.json","R6-ROOT-STATIC-REVIEW.json","retire_verified_source_download.py","source-download-cache-retirement-r1/RESULT.json","preparation-received/ROOT-FULL-GET-RESULT.json","oracle-received/ROOT-FULL-GET-RESULT.json","op13-received/ROOT-FULL-GET-RESULT.json","r3-failure-received/ROOT-FULL-GET-RESULT.json","r6-author-received/ROOT-FULL-GET-RESULT.json","op13-parent-received/ROOT-FULL-GET-RESULT.json","r4-author-received/ROOT-FULL-GET-RESULT.json","metadata-errors/OP13-PART008-FIRST-GET-ERROR.json","ROOT-EXECUTION-RECEIPTS.json","ROOT-FULL-GET-RECEIPTS.json","seal_root_readbacks.py"]
def pin(b):
    return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
rows=[];total=0
for name in FILES:
    path=BASE/name;s=path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    raw=path.read_bytes();assert seven(path.lstat())==seven(s)
    rows.append({"path":name,"identity":pin(raw),"mode":stat.S_IMODE(s.st_mode),"current_seven_stats":seven(s),"data_base64":base64.b64encode(raw).decode("ascii")});total+=len(raw)
payload=(json.dumps({"schema":"hia.root.v148.complete-static-readbacks.v1","files":rows},sort_keys=True,indent=2)+"\n").encode()
archive=zlib.compress(payload,9)
parts=[]
for number,offset in enumerate(range(0,len(archive),98304)):
    chunk=archive[offset:offset+98304]
    wrapper={"schema":"hia.root.v148.complete-static-part.v1","number":number,"offset":offset,"decoded":pin(chunk),"payload":base64.b64encode(chunk).decode("ascii")}
    raw=(json.dumps(wrapper,sort_keys=True,indent=2)+"\n").encode()
    name="parts/%03d.json"%number;(OUT/name).write_bytes(raw)
    parts.append({"path":name,"identity":pin(raw),"offset":offset,"decoded":pin(chunk)})
index={"schema":"hia.root.v148.complete-static-transport.v1","archive":pin(archive),"payload":pin(payload),"files":len(rows),"logical_bytes":total,"members":[{k:r[k] for k in ("path","identity","mode","current_seven_stats")} for r in rows],"parts":parts,"products":0}
(OUT/"INDEX.json").write_bytes((json.dumps(index,sort_keys=True,indent=2)+"\n").encode())
joined=b"".join(base64.b64decode(json.loads((OUT/r["path"]).read_bytes())["payload"],validate=True) for r in parts)
assert joined==archive
z=zlib.decompressobj();decoded=z.decompress(joined)+z.flush()
assert z.eof and not z.unused_data and not z.unconsumed_tail and decoded==payload
restored=json.loads(decoded)["files"];assert len(restored)==len(rows)
for row in restored:
    data=base64.b64decode(row["data_base64"],validate=True)
    assert pin(data)==row["identity"]
    p=BASE/row["path"];assert p.read_bytes()==data and seven(p.lstat())==row["current_seven_stats"] and stat.S_IMODE(p.lstat().st_mode)==row["mode"]
result={"schema":"hia.root.v148.complete-static-local-readback.v1","status":"PASS_COMPLETE_CAPSULE_AND_CURRENT_ORIGINS","files":len(rows),"logical_bytes":total,"parts":len(parts),"archive":pin(archive),"payload":pin(payload),"full_zlib_EOF_checksum":True,"all_bytes_modes_stats_complete":True,"products":0}
(OUT/"LOCAL-CAPSULE-READBACK.json").write_bytes((json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(result,sort_keys=True))
