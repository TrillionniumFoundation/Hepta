"""Independent, read-only inspection of the already produced 970 CI custody ZIP."""
import binascii, hashlib, io, json, os, stat, struct, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent
SOURCE = Path("/workspace/scratch/e26ed3e2edcf/root/custody-13913382201.original.zip")
OUT = ROOT / "container-readback-r1"
OUT.mkdir(mode=0o700, exist_ok=False)
def digest(b):
    return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob_sha":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
def put(path,b):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,"wb") as f:
        f.write(b);f.flush();os.fsync(f.fileno())
    if path.read_bytes()!=b:raise ValueError("independent copy differs")
    return digest(b)
def same(b,size,sha):
    if len(b)!=size or hashlib.sha256(b).hexdigest()!=sha:raise ValueError("external seal differs")
def info(i):
    return {"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size,"crc32":i.CRC,"mode":i.external_attr>>16,"flags":i.flag_bits,"method":i.compress_type,"header_offset":i.header_offset}
original=SOURCE.read_bytes()
same(original,22390611,"58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d")
outer_before=digest(original)
with zipfile.ZipFile(io.BytesIO(original)) as outer:
    infos=outer.infolist();expected={f"{n:03}.original" for n in range(15)}|{"FINAL.json","FRAME-RESULT.json"}
    if len(infos)!=17 or {i.filename for i in infos}!=expected:raise ValueError("outer inventory differs")
    if any(not stat.S_ISREG(i.external_attr>>16) or i.flag_bits&1 or i.is_dir() for i in infos):raise ValueError("outer member type differs")
    data={i.filename:outer.read(i) for i in infos}
    for i in infos:
        if len(data[i.filename])!=i.file_size or binascii.crc32(data[i.filename])&0xffffffff!=i.CRC:raise ValueError("outer CRC differs")
    final=data["FINAL.json"];same(final,12465,"afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345")
    f=json.loads(final)
    if f["status"]!="CUSTODY_HOLD" or len(f["captured"])!=15:raise ValueError("historical status or capture count differs")
    if {x["retained_file"] for x in f["captured"]}!={f"{n:03}.original" for n in range(15)}:raise ValueError("captured names differ")
    captured=[]
    for r in f["captured"]:
        b=data[r["retained_file"]];same(b,r["bytes"],r["sha256"])
        if r["independent_copy_readback"] is not True or r["source_identity"][6]!=r["bytes"]:raise ValueError("capture identity differs")
        captured.append({"retained_file":r["retained_file"],"source_relative_path":r["source_relative_path"],**digest(b)})
    for name,b in data.items():
        if name!="014.original":put(OUT/"outer-originals"/name,b)
inner=data["014.original"]
same(inner,8316154,"d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e")
put(OUT/"selected-originals.zip",inner)
selected_raw=data["012.original"]
same(selected_raw,317307,"b0760d77746721d441067b63c8442dafbf0ad3e2bc6f9c79f26770b448965fff")
s=json.loads(selected_raw)
if s["schema"]!="hia.ci-selected-original-members.v1" or len(s["selected_members"])!=354:raise ValueError("selected inventory differs")
rows=s["selected_members"]
if [r["retained_file"] for r in rows]!=[f"{n:04}.raw" for n in range(354)] or len({r["original_name"] for r in rows})!=354:raise ValueError("selected names/order differ")
expected_map={r["retained_file"]:r for r in rows}
expected_map["DIRECTORY.json"]={"bytes":13678084,"sha256":"9aeb1fb0ce400ef7e1d0e7a58bba55f7b5c3a80cdccbfb63ebbde3e814221e66"}
expected_map["SELECTED.json"]={"bytes":317307,"sha256":"b0760d77746721d441067b63c8442dafbf0ad3e2bc6f9c79f26770b448965fff"}
verified=[]
with zipfile.ZipFile(io.BytesIO(inner)) as z:
    infos=z.infolist()
    if len(infos)!=356 or {i.filename for i in infos}!=set(expected_map):raise ValueError("inner complete inventory differs")
    if sum(i.file_size for i in infos)!=126634528:raise ValueError("inner total differs")
    cursor=0
    for i in infos:
        if i.external_attr>>16!=0o100400 or i.flag_bits!=0 or i.compress_type!=8 or i.header_offset!=cursor:raise ValueError("inner type, encoding or contiguous layout differs")
        h=struct.unpack_from("<IHHHHHIIIHH",inner,i.header_offset)
        sig,version,flags,method,mtime,mdate,crc,cs,us,nl,el=h
        if sig!=0x04034b50 or flags!=i.flag_bits or method!=8 or crc!=i.CRC:raise ValueError("inner local header differs")
        name=inner[i.header_offset+30:i.header_offset+30+nl]
        if name.decode("ascii")!=i.filename:raise ValueError("inner local name differs")
        extra=inner[i.header_offset+30+nl:i.header_offset+30+nl+el]
        if cs==0xffffffff or us==0xffffffff:
            if len(extra)!=20 or struct.unpack_from("<HH",extra,0)!=(1,16):raise ValueError("local ZIP64 differs")
            eu,ec=struct.unpack_from("<QQ",extra,4)
            if eu!=i.file_size or ec!=i.compress_size:raise ValueError("local ZIP64 sizes differ")
        elif cs!=i.compress_size or us!=i.file_size:raise ValueError("local sizes differ")
        cursor=i.header_offset+30+nl+el+i.compress_size
        b=z.read(i);r=expected_map[i.filename]
        same(b,r["bytes"],r["sha256"])
        if binascii.crc32(b)&0xffffffff!=i.CRC or ("crc32" in r and r["crc32"]!=i.CRC):raise ValueError("inner full CRC differs")
        if i.filename=="SELECTED.json" and b!=data["012.original"]:raise ValueError("selected raw differs")
        if i.filename=="DIRECTORY.json" and b!=data["011.original"]:raise ValueError("directory raw differs")
        if i.filename.endswith(".raw"):
            if r["actual_entire_member_read"] is not True or r["original_CRC_checked"] is not True:raise ValueError("old member flags differ")
            rr=r["independent_retained_file_readback"]
            if rr["bytes"]!=len(b) or rr["sha256"]!=r["sha256"] or rr["actual_bytes_independently_read"]!=len(b):raise ValueError("old member identity differs")
        rec=put(OUT/"inner-originals"/i.filename,b)
        verified.append({**info(i),**rec,"original_name":r.get("original_name",i.filename)})
    if cursor!=z.start_dir:raise ValueError("local records do not end at central directory")
    if z.testzip() is not None:raise ValueError("independent final CRC pass differs")
after=SOURCE.read_bytes()
if after!=original:raise ValueError("outer source changed")
report={"schema":"hia.970-original-custody-independent-container-readback.v1","status":"ALL_356_ORIGINAL_MEMBERS_VERIFIED_NOT_PRODUCT_REEXECUTION","source_path":str(SOURCE),"source_before":outer_before,"source_after":digest(after),"outer_inventory":[info(i) for i in zipfile.ZipFile(io.BytesIO(original)).infolist()],"historical_final":digest(final),"historical_status":f["status"],"historical_errors":f["errors"],"historical_missing_capture_paths":f["missing_capture_paths"],"captured_verified":captured,"inner_archive":digest(inner),"selected_raw":digest(selected_raw),"original_member_count":354,"all_member_count":356,"original_member_bytes":sum(r["bytes"] for r in rows),"all_member_bytes":sum(r["bytes"] for r in verified),"members":verified,"all_members_full_SHA256_and_CRC32":True,"all_local_headers_and_contiguous_layout_verified":True,"no_project_code_imported":True,"qualification_executed":False,"original_statuses_reclassified":False}
rb=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode()
put(OUT/"CONTAINER-READBACK.json",rb)
print(json.dumps({k:report[k] for k in ("status","inner_archive","original_member_count","all_member_count","original_member_bytes","all_member_bytes","historical_status")}));print(str(OUT/"CONTAINER-READBACK.json"))
