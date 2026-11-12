"""Bounded local evidence sealing, zero target execution; complete streamed byte/mode readback."""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,importlib.util,json,os,stat,sys,tarfile
ROOT=Path("/workspace/scratch/9acdfa9f5639/native-checker-development/physical-after-r1")
def identity(path):
    p=Path(path);st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink() and st.st_nlink==1
    h=sha256();n=0
    with p.open("rb") as f:
        a=os.fstat(f.fileno())
        assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        while b:=f.read(1<<18):h.update(b);n+=len(b)
        z=os.fstat(f.fileno())
    end=p.lstat()
    assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns,a.st_mode)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns,z.st_mode)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns,end.st_mode)
    assert n==st.st_size
    return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def walk(root):
    info=root.lstat();assert not root.is_symlink()
    if stat.S_ISREG(info.st_mode):yield root
    else:
        assert stat.S_ISDIR(info.st_mode)
        for p in sorted(root.iterdir(),key=lambda p:p.name):yield from walk(p)
def entries(roots):
    for label,root in sorted(roots.items()):
        one=root.is_file()
        for path in walk(root):
            relative=path.name if one else path.relative_to(root).as_posix()
            yield label+"/"+relative,path
def same_stream(stream,path,row):
    h=sha256();n=0
    with path.open("rb") as source:
        for block in iter(lambda:stream.read(1<<18),b""):
            assert source.read(len(block))==block
            h.update(block);n+=len(block)
        assert source.read(1)==b""
    assert (n,h.hexdigest())==(row["bytes"],row["sha256"])
def main():
    p=argparse.ArgumentParser();p.add_argument("--root",action="append",required=True);p.add_argument("--out",type=Path,required=True);args=p.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    assert 6 in os.sched_getaffinity(0);os.sched_setaffinity(0,{6})
    helper=ROOT/"tools/bounded_physical_subject.py"
    assert sha256(helper.read_bytes()).hexdigest()=="386c110c77ef3b89a5f3e72c54737dff60c8b8625f3e544b0cc2acb242e7a3b3"
    spec=importlib.util.spec_from_file_location("local_seal_subject",helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    s=m.Subject(args.out,"LOCAL_BOUNDED_EVIDENCE_SEAL_ONLY")
    s.report.update(native_entries_executed=0,VM_entries_executed=0,new_semantic_qualification=False)
    try:
        s.capture(__file__);s.capture(helper)
        roots={}
        for item in args.root:
            label,raw=item.split("=",1);assert label not in roots and label.isascii() and label.replace("-","").replace("_","").isalnum()
            root=Path(raw).absolute();assert root.exists() and not root.is_symlink()
            assert str(root).startswith(("/workspace/scratch/9acdfa9f5639/native-checker-development/","/dev/shm/hia-native-checker-"))
            assert s.out!=root and not s.out.is_relative_to(root)
            roots[label]=root
        archive=s.out/"evidence.tar.xz";index=s.out/"members.jsonl";count=total=0
        with index.open("x",encoding="utf-8") as ledger,tarfile.open(archive,"w:xz",preset=1) as tf:
            for name,path in entries(roots):
                row=dict(name=name,path=str(path),**identity(path))
                member=tarfile.TarInfo(name);member.size=row["bytes"];member.mode=row["mode"];member.mtime=0;member.uid=member.gid=0
                with path.open("rb") as f:tf.addfile(member,f)
                tf.members.clear()
                ledger.write(json.dumps(row,sort_keys=True)+"\n");count+=1;total+=row["bytes"]
            ledger.flush();os.fsync(ledger.fileno())
        checked=0
        with index.open("r",encoding="utf-8") as ledger,tarfile.open(archive,"r|xz") as tf:
            for member in tf:
                raw=ledger.readline();assert raw;row=json.loads(raw)
                assert member.isfile() and (member.name,member.size,member.mode)==(row["name"],row["bytes"],row["mode"])
                with tf.extractfile(member) as stream:same_stream(stream,Path(row["path"]),row)
                checked+=1;tf.members.clear()
            assert not ledger.readline() and checked==count
        with index.open("r",encoding="utf-8") as ledger:
            for name,path in entries(roots):
                raw=ledger.readline();assert raw;row=json.loads(raw)
                assert (name,str(path))==(row["name"],row["path"])
                assert identity(path)=={k:row[k] for k in ("bytes","sha256","mode")}
            assert not ledger.readline()
        s.report.update(status="PASS",members=count,original_bytes=total,roots={k:str(v) for k,v in roots.items()},
            archive=dict(path=str(archive),**identity(archive)),member_index=dict(path=str(index),**identity(index)),
            every_original_and_tar_member_complete_bytes_modes_equal=True,final_tree_complete_no_added_omitted_files=True,
            tar_member_cache_cleared=True,all_input_expanded_sources_retained=True)
    except BaseException as error:s.failure(error)
    finally:s.finish("PASS")
if __name__=="__main__":main()
