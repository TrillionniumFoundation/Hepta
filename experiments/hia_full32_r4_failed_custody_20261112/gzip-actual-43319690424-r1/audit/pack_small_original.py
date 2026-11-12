#!/usr/bin/env python3
"""Preserve the exact official SMALL ZIP, never the unavailable 3 GB original."""
import base64, gzip, hashlib, json, os, sys, time
from pathlib import Path
ROOT=Path("/tmp/hia-full32-r4-gzip-actual-43319690424-r1")
SOURCE=ROOT/"downloads/artifact-13991170182.original.zip"
EXPECTED_SIZE=34570252
EXPECTED_SHA="7201ffb609a82d4666321960ff0a5bdb5e3db7b52d4068aadd07eda78e643f7b"
DEST=ROOT/"small-zip-preservation"
CHUNK=512*1024
def digest(path):
    h=hashlib.sha256();n=0
    with path.open("rb") as f:
        while b:=f.read(1<<20):h.update(b);n+=len(b)
    return n,h.hexdigest()
def pin(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
            "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def write(path,raw):
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
    started=time.monotonic_ns()
    assert digest(SOURCE)==(EXPECTED_SIZE,EXPECTED_SHA)
    original_identity=SOURCE.stat()
    DEST.mkdir(mode=0o700)
    compressed=DEST/"artifact-13991170182.original.zip.gz"
    with compressed.open("xb") as rawout:
        with gzip.GzipFile(filename="",mode="wb",compresslevel=1,mtime=0,fileobj=rawout) as out:
            with SOURCE.open("rb") as inp:
                while b:=inp.read(1<<20):out.write(b)
        rawout.flush();os.fsync(rawout.fileno())
    ch=hashlib.sha256();n=0
    with gzip.open(compressed,"rb") as inp:
        while b:=inp.read(1<<20):ch.update(b);n+=len(b)
    assert (n,ch.hexdigest())==(EXPECTED_SIZE,EXPECTED_SHA)
    gz_size,gz_sha=digest(compressed)
    parts=[];assembled=hashlib.sha256();assembled_bytes=0
    with compressed.open("rb") as inp:
        ordinal=0
        while raw:=inp.read(CHUNK):
            text=base64.b64encode(raw)+b"\n"
            name="part-%03d.base64"%ordinal
            write(DEST/name,text)
            reread=(DEST/name).read_bytes()
            assert reread==text and len(text)<1<<20
            restored=base64.b64decode(reread.rstrip(b"\n"),validate=True)
            assert restored==raw and base64.b64encode(restored)+b"\n"==reread
            parts.append({"ordinal":ordinal,"path":name,"offset":assembled_bytes,
                          "raw":pin(raw),"text":pin(text)})
            assembled.update(restored);assembled_bytes+=len(restored);ordinal+=1
    assert (assembled_bytes,assembled.hexdigest())==(gz_size,gz_sha)
    assert SOURCE.stat()==original_identity and digest(SOURCE)==(EXPECTED_SIZE,EXPECTED_SHA)
    manifest={"schema":"hia.original-small-artifact-lossless-preservation.v1",
              "artifact_id":13991170182,"run_id":43319690424,"encoding":"independent original ZIP compressed with one gzip member, level1, mtime0; exact byte restoration",
              "original":{"bytes":EXPECTED_SIZE,"sha256":EXPECTED_SHA},
              "gzip":{"bytes":gz_size,"sha256":gz_sha},"chunk_bytes":CHUNK,"parts":parts,
              "parts_readback_complete":True,"full_gzip_decompression_verified":True,
              "source_after_complete_read_verified":True,"producer_files_repacked_or_modified":False,
              "recovery_original_HOLD_unchanged":True,
              "larger_original_artifact_id":13982129929,"larger_original_zip_locally_verified":False,
              "elapsed_ns":time.monotonic_ns()-started,"packer":pin(Path(__file__).read_bytes())}
    raw=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
    write(DEST/"MANIFEST.json",raw)
    print(json.dumps({"status":"EXACT_SMALL_ZIP_GZIP_AND_ALL_TEXT_PARTS_VERIFIED",
                      "original_bytes":EXPECTED_SIZE,"gzip_bytes":gz_size,"parts":len(parts),
                      "manifest":str(DEST/"MANIFEST.json"),"manifest_pin":pin(raw)}))
if __name__=="__main__":main()
