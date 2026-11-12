#!/usr/bin/env python3
"""Restore the exact official 34,570,252-byte small ZIP from 13 fixed text parts."""
import argparse, base64, gzip, hashlib, json, os, zlib
from pathlib import Path
EXPECTED_BYTES=34570252
EXPECTED_SHA="7201ffb609a82d4666321960ff0a5bdb5e3db7b52d4068aadd07eda78e643f7b"
def pin(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
            "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",required=True)
    ns=ap.parse_args()
    root=Path(__file__).resolve().parent
    m=json.loads((root/"MANIFEST.json").read_bytes())
    assert m["artifact_id"]==13991170182 and m["run_id"]==43319690424
    assert m["original"]=={"bytes":EXPECTED_BYTES,"sha256":EXPECTED_SHA}
    assert len(m["parts"])==13 and m["chunk_bytes"]==524288
    destination=Path(ns.output)
    partial=Path(str(destination)+".partial")
    assert not destination.exists() and not partial.exists()
    gz_sha=hashlib.sha256();zip_sha=hashlib.sha256();gz_bytes=zip_bytes=0
    inflater=zlib.decompressobj(16+zlib.MAX_WBITS)
    with partial.open("xb") as out:
        for ordinal,row in enumerate(m["parts"]):
            assert row["ordinal"]==ordinal and row["offset"]==gz_bytes
            assert row["path"]=="part-%03d.base64"%ordinal
            text=(root/row["path"]).read_bytes()
            assert pin(text)==row["text"] and text.endswith(b"\n")
            compressed=base64.b64decode(text[:-1],validate=True)
            assert base64.b64encode(compressed)+b"\n"==text and pin(compressed)==row["raw"]
            gz_sha.update(compressed);gz_bytes+=len(compressed)
            pending=compressed
            while pending:
                raw=inflater.decompress(pending,1<<20)
                pending=inflater.unconsumed_tail
                assert not inflater.unused_data
                zip_bytes+=len(raw)
                assert zip_bytes<=EXPECTED_BYTES
                zip_sha.update(raw);out.write(raw)
        assert inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail
        assert (gz_bytes,gz_sha.hexdigest())==(m["gzip"]["bytes"],m["gzip"]["sha256"])
        assert (zip_bytes,zip_sha.hexdigest())==(EXPECTED_BYTES,EXPECTED_SHA)
        out.flush();os.fsync(out.fileno())
    verify=hashlib.sha256();n=0
    with partial.open("rb") as inp:
        while raw:=inp.read(1<<20):verify.update(raw);n+=len(raw)
    assert (n,verify.hexdigest())==(EXPECTED_BYTES,EXPECTED_SHA)
    os.link(partial,destination);os.unlink(partial)
    print(json.dumps({"status":"EXACT_OFFICIAL_SMALL_ZIP_RESTORED","bytes":n,
                      "sha256":verify.hexdigest(),"larger_3GB_original_zip_verified":False}))
if __name__=="__main__":main()
