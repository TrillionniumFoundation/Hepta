"""Export the current captured source using the actual installed native exporter."""
from pathlib import Path
from hashlib import sha256
import argparse,fcntl,json,os,struct,subprocess,time,traceback

def pin(raw):
    return {"bytes":len(raw),"sha256":sha256(raw).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","build","preparation","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    source=a.source.resolve(strict=True)
    build=json.loads((a.build/"qualification.json").read_bytes())
    prep=json.loads((a.preparation/"report.json").read_bytes())
    assert build["passed"] and prep["passed"]
    assert build["preparation"]["sha256"]==sha256((a.preparation/"report.json").read_bytes()).hexdigest()
    tc=a.build/"toolchain";exporter=tc/"hia-cold-source-export"
    assert pin(exporter.read_bytes())==build["installed"]["hia-cold-source-export"]
    packet=(tc/"source.manifest.hiasxm").read_bytes()
    assert pin(packet)==build["source_manifest"]
    assert packet==(a.preparation/"source-manifest.hiasxm").read_bytes()
    files=json.loads((a.preparation/"source-manifest.json").read_bytes())
    for name,digest in files.items():
        assert sha256((source/name).read_bytes()).hexdigest()==digest,name
    d=a.output;d.mkdir(mode=0o700,parents=True,exist_ok=False)
    run=d/"run";run.mkdir(mode=0o700)
    report={"schema":"hepta.hia.native-production-source-export.v1","passed":False,
        "source":str(source),"source_head":build["source_head"],"native_only_copy":str(run/"source"),
        "current_source_count":len(files),"whole_cold_qualified":False,
        "whole_native_delivery_qualified":False,"cases":[],
        "build":{"path":str(a.build/"qualification.json"),**pin((a.build/"qualification.json").read_bytes())},
        "driver":{"path":__file__,**pin(Path(__file__).read_bytes())}}
    def save():(d/"qualification.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    def mem(raw):
        fd=os.memfd_create("hia-native-source-export-input",os.MFD_ALLOW_SEALING)
        os.fchmod(fd,0o600);view=memoryview(raw)
        while view:
            n=os.write(fd,view);assert n>0;view=view[n:]
        os.lseek(fd,0,0);fcntl.fcntl(fd,1033,15);assert fcntl.fcntl(fd,1034)==15
        return fd
    fds=[]
    try:
        srcfd=os.open(source,os.O_RDONLY|os.O_DIRECTORY)
        outfd=os.open(run,os.O_RDONLY|os.O_DIRECTORY)
        manifestfd=mem(packet);fds=[srcfd,outfd,manifestfd]
        dirs={""}
        for name in files:
            parts=name.split("/")
            dirs.update("/".join(parts[:i]) for i in range(1,len(parts)))
        for mode in (0,1):
            wire=b"HIASXQ01"+struct.pack("<7Q",mode,srcfd,outfd,manifestfd,len(packet),len(files),0)+sha256(packet).digest()+bytes(32)
            request=mem(wire);started=time.monotonic_ns()
            try:
                child=subprocess.run([str(exporter)],stdin=request,capture_output=True,
                    pass_fds=tuple(fds+[request]),env={"PATH":""},timeout=60)
            finally:os.close(request)
            wanted=b"HIASXR01"+struct.pack("<3Q",mode,len(files),len(dirs))+sha256(packet).digest()+struct.pack("<8Q",1,1,1,1,16384,4095,256,67108864)
            (d/("receipt-"+str(mode)+".bin")).write_bytes(child.stdout)
            (d/("stderr-"+str(mode)+".bin")).write_bytes(child.stderr)
            row={"mode":mode,"returncode":child.returncode,"elapsed_ns":time.monotonic_ns()-started,
                "stdout":pin(child.stdout),"stdout_hex":child.stdout.hex(),"stderr":pin(child.stderr),
                "passed":child.returncode==0 and not child.stderr and child.stdout==wanted}
            report["cases"].append(row);save();assert row["passed"],row
            print("CURRENT_NATIVE_EXPORT_MODE_PASS",mode,row["elapsed_ns"],flush=True)
        actual=set()
        for path in (run/"source").rglob("*"):
            assert not path.is_symlink(),path
            if path.is_dir():
                assert path.stat().st_mode&0o7777==0o700,path
                continue
            name=str(path.relative_to(run/"source"));actual.add(name);raw=path.read_bytes()
            assert name in files and sha256(raw).hexdigest()==files[name],name
            assert path.stat().st_mode&0o7777==0o400 and path.stat().st_nlink==1,name
            assert path.suffix.lower() not in (".py",".pyc",".rs",".so",".elf",".o",".flat",".whl") and raw[:4]!=b"\x7fELF",name
        assert actual==set(files)
        for name,digest in files.items():
            assert sha256((source/name).read_bytes()).hexdigest()==digest,name
        report.update(passed=True,all_exported_files_exact=True,no_legacy_language_files=True,
            no_compiled_images=True,manifest=pin(packet),exporter=pin(exporter.read_bytes()),
            source_bytes=sum((run/"source"/n).stat().st_size for n in files),
            source_manifest_path=str(tc/"source.manifest.hiasxm"),
            construction_input_sources_unchanged=True)
        save();print("CURRENT_PHYSICAL_NATIVE_ONLY_SOURCE_PASS",len(files),report["source_bytes"],flush=True)
    except BaseException:
        report["error"]=traceback.format_exc();save();raise
    finally:
        for fd in fds:os.close(fd)

if __name__=="__main__":main()
