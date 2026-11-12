"""Lossless transport encoding of four already sealed complete member ledgers; zero target execution."""
from pathlib import Path
from hashlib import sha256
import importlib.util,json,lzma,os,stat,sys
ROOT=Path("/workspace/scratch/9acdfa9f5639/native-checker-development/physical-after-r1")
BASE=Path("/dev/shm/hia-native-checker-physical-seals-r1")
OUT=Path("/dev/shm/hia-native-checker-member-transports-r1")
def identity(path):
    b=path.lstat();assert stat.S_ISREG(b.st_mode) and not path.is_symlink()
    h=sha256();n=0
    with path.open("rb") as f:
        while v:=f.read(1<<18):h.update(v);n+=len(v)
    a=path.lstat();assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns,a.st_mode)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns,b.st_mode)
    assert n==b.st_size
    return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(b.st_mode))
def main():
    assert sys.version_info[:3]==(3,12,14);os.sched_setaffinity(0,{6})
    helper=ROOT/"tools/bounded_physical_subject.py"
    assert sha256(helper.read_bytes()).hexdigest()=="386c110c77ef3b89a5f3e72c54737dff60c8b8625f3e544b0cc2acb242e7a3b3"
    spec=importlib.util.spec_from_file_location("member_transport_subject",helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    s=m.Subject(OUT,"LOCAL_MEMBER_LEDGER_LOSSLESS_ENCODING_ONLY");before={};rows=[]
    s.report.update(native_entries_executed=0,VM_entries_executed=0,new_semantic_qualification=False)
    try:
        s.capture(__file__);s.capture(helper)
        for name in ("build","cases-cross","cases-ordinary","cases-private"):
            source=BASE/name/"sealed/members.jsonl";old=identity(source);before[name]=old
            target=s.out/(name+".members.jsonl.xz")
            with source.open("rb") as f,lzma.open(target,"xb",preset=6) as z:
                while v:=f.read(1<<18):z.write(v)
            target.chmod(old["mode"])
            n=0;h=sha256()
            with source.open("rb") as original,lzma.open(target,"rb") as z:
                while v:=z.read(1<<18):
                    assert original.read(len(v))==v;n+=len(v);h.update(v)
                assert original.read(1)==b""
            assert (n,h.hexdigest())==(old["bytes"],old["sha256"])
            assert identity(source)==old
            rows.append(dict(name=name,source_path=str(source),source=old,encoded_path=str(target),encoded=identity(target),complete_original_decode_bytes_equal=True))
        s.report.update(status="PASS",ledgers=rows,all_complete_member_lists_encoded=True,raw_member_lists_retained=True)
    except BaseException as e:s.failure(e)
    finally:
        for name,old in before.items():
            def check(name=name,old=old):assert identity(BASE/name/"sealed/members.jsonl")==old
            s.attempt("input-after:"+name,check)
        s.finish("PASS")
if __name__=="__main__":main()
