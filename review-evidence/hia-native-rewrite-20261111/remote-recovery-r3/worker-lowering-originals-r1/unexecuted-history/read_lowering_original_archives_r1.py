"""Read the complete original R9/R10 archives to locate missing frozen authors.

Read-only restoration. Original .py files are data: no imports, generation,
B3 compilation, native entries, reference executions or qualification replay.
An absent exact helper is reported as absent, never replaced by a similar file.
"""
from __future__ import annotations
import argparse,ast,base64,json,lzma,os,platform,resource,stat,subprocess,sys,tarfile,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
PLAN=json.loads(r'''{"schema":"hia-original-lowering-authoring-archive-readback-r1","reference_only_source_lookups":{"hia_composite_lowering_driver_helper.py":{"bytes":15664,"sha256":"fb392ada8b16cfaeedbdbfb55b46786c5923a8959f3cc32057f13383b5fa75df","source_of_expectation":"Exact R7 public-native-source-r1 and overlay/tools member rows; absence in R9/R10 remains an explicit result."},"generate_hia_composite_raw_driver.py":{"bytes":12378,"sha256":"bfc7d28d07a0ab4878fe3df4a51904850e10f7493f0571faccbfdcfe76ae5913","source_of_expectation":"Exact R7 public-native-source-r1/overlay/tools member rows."}},"archives":[{"name":"R9-explicit-importer","archive":{"gitsha":"a75abe1202c5b35e1411ba1d4fd69e33faa4e236","bytes":4595336,"sha256":"19c16b47ab03bad544bca724a23988ff65600e3739cfd0fde3052472a2fed1db","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3.tar.xz"},"ledger":{"gitsha":"a54869645bf2e5c952b944c77a736549cf550dee","bytes":69184,"sha256":"10ec135b2661c5507e769d6fae693ec09a370e5f3ed9c76b04a5267fb2cfc555","original_bytes":1116524,"original_sha256":"1d8a45345e150dd548e1b94d6b2f9bc85fc021fd67e09d7b4b038d540821071d","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-original-member-manifest.json.xz"},"custody":{"gitsha":"4303f24270508bea95812f01d376f8fa8fe095a5","bytes":1737,"path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3-custody.json","sha256":"85629375c887ecfb1fe5c26deff5c1323c8b48e59d66e21ad3e9919450634e3f"},"members":2949,"files":2389,"raw_file_bytes":71724847},{"name":"R10-program-admission","archive":{"gitsha":"76b8bf2f75c3abed0564830bbf165f3571291cab","bytes":3730136,"sha256":"3fcd6e2c10aacae6f84de0681a748531e3d8b130b87a29fbd34905783a0f7149","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/program-admission-r1.tar.xz"},"ledger":{"gitsha":"a0dbd8e056621b1da26fbe202a80e96de3c53be2","bytes":73948,"sha256":"f341aed5bb63943cc90dc8735922eba5209aaacdc8ce7aed710f41649ed249f0","original_bytes":902052,"original_sha256":"8713f1e06861004374a44e70e32006f88d4dba552c9601d1e4caf0d76116562f","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/program-admission-original-member-manifest.json.xz"},"custody":{"gitsha":"a7bf7f9c789d897012824767a4bacb6c61974b7c","bytes":1994,"path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/program-admission-r1-custody.json","sha256":"d9e829db01afe73c58f324b9afe3e1a806713c7fb75b926e3536755dd1714483"},"members":2440,"files":2002,"raw_file_bytes":43382682}],"additional_export_basenames":["hia_composite_lowering_driver_common.py","hia_composite_lowering_driver_main.py","hia_composite_lowering_driver_services.py","hia_composite_lowering_driver_stream.py","hia_composite_lowering_driver_helper.py","hia_composite_constructor_driver.py","generate_hia_composite_lowering_driver.py","generate_hia_composite_raw_driver.py","legacy_authoring.py","program_authoring.py"],"no_original_code_executed":true,"no_native_compiler_or_tests_executed":true}''')
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as out:out.write(json.dumps(obj,sort_keys=True,indent=2)+"\n")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",type=Path,default=Path(os.environ.get("GITHUB_WORKSPACE",".")))
    parser.add_argument("--out",type=Path,default=Path(os.environ.get("HIA_CI_OUTPUT","/tmp/hia-lowering-originals-r9r10")))
    args=parser.parse_args();repo=args.repo.resolve();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    assert sys.version_info[:3]==(3,12,14),sys.version
    assert platform.machine()=="x86_64"
    start=time.monotonic_ns();initial=resource.getrusage(resource.RUSAGE_SELF)
    initial_child=resource.getrusage(resource.RUSAGE_CHILDREN)
    self_raw=Path(__file__).read_bytes()
    git=["/usr/bin/git","-c","core.packedGitWindowSize=16m","-c","core.packedGitLimit=64m"]
    inputs={};reports=[];exports=[];status="FAIL";failure=None
    def fetch(row,destination):
        raw=subprocess.check_output(git+["cat-file","blob",row["gitsha"]],cwd=repo,timeout=30)
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),row
        record=subprocess.check_output(git+["ls-tree","-z","--long","HEAD","--",row["path"]],cwd=repo,timeout=30)
        assert record.endswith(b"\0") and len(record.split(b"\0"))==2,row["path"]
        meta,name=record[:-1].split(b"\t",1);mode,kind,identity,size=meta.split()
        assert (mode,kind,identity,size,name)==(b"100644",b"blob",row["gitsha"].encode(),str(row["bytes"]).encode(),row["path"].encode()),row["path"]
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open("xb") as stream:stream.write(raw)
        destination.chmod(0o644);inputs[destination]=(len(raw),digest(raw),0o644)
        return raw
    try:
        for item in PLAN["archives"]:
            folder=out/item["name"];folder.mkdir()
            archive=folder/"original.tar.xz"
            fetch(item["archive"],archive)
            ledger_raw=lzma.decompress(fetch(item["ledger"],folder/"original-members.json.xz"))
            assert (len(ledger_raw),digest(ledger_raw))==(item["ledger"]["original_bytes"],item["ledger"]["original_sha256"])
            ledger_file=folder/"original-members.json"
            with ledger_file.open("xb") as stream:stream.write(ledger_raw)
            ledger_file.chmod(0o644);inputs[ledger_file]=(len(ledger_raw),digest(ledger_raw),0o644)
            original=json.loads(ledger_raw);rows=original["members"]
            assert type(rows) is list and len(rows)==item["members"]
            expected={row["path"]:row for row in rows};assert len(expected)==len(rows)
            custody=json.loads(fetch(item["custody"],folder/"original-custody.json"))
            assert (custody["bytes"],custody["sha256"],custody["members"],custody["file_members"],custody["raw_file_bytes"])==(
                item["archive"]["bytes"],item["archive"]["sha256"],item["members"],item["files"],item["raw_file_bytes"])
            assert custody["member_manifest"]["sha256"]==digest(ledger_raw)
            assert custody["member_manifest"]["bytes"]==len(ledger_raw)
            seen=set();files=0;directories=0;total=0;candidates=[];checked=[]
            with tarfile.open(archive,"r|xz") as tf:
                for member in tf:
                    path=PurePosixPath(member.name)
                    assert member.name and not path.is_absolute() and ".." not in path.parts
                    assert member.name not in seen and member.name in expected,member.name
                    seen.add(member.name);row=expected[member.name]
                    assert member.mode==row["mode"] and not member.mode&0o7000,member.name
                    if member.isdir():
                        assert row["kind"]=="directory"
                        directories+=1;checked.append(dict(path=member.name,kind="directory",mode=member.mode));continue
                    assert member.isfile() and row["kind"]=="file" and member.size==row["bytes"],member.name
                    selected=path.name in PLAN["additional_export_basenames"]
                    chunks=[] if selected else None;hasher=sha256();size=0
                    handle=tf.extractfile(member);assert handle is not None
                    with handle:
                        for chunk in iter(lambda:handle.read(1<<20),b""):
                            hasher.update(chunk);size+=len(chunk)
                            if chunks is not None:chunks.append(chunk)
                    assert (size,hasher.hexdigest())==(row["bytes"],row["sha256"]),member.name
                    files+=1;total+=size
                    checked.append(dict(path=member.name,kind="file",bytes=size,sha256=hasher.hexdigest(),mode=member.mode))
                    if chunks is not None:candidates.append((row,b"".join(chunks)))
            assert seen==set(expected)
            assert (len(seen),files,total)==(item["members"],item["files"],item["raw_file_bytes"])
            save(folder/"complete-independent-member-readback.json",checked)
            for row,raw in candidates:
                basename=PurePosixPath(row["path"]).name
                destination=out/"authoring"/digest(raw)/basename
                destination.parent.mkdir(parents=True,exist_ok=True)
                if destination.exists():assert destination.read_bytes()==raw and stat.S_IMODE(destination.stat().st_mode)==row["mode"]
                else:
                    with destination.open("xb") as stream:stream.write(raw)
                    destination.chmod(row["mode"])
                assert destination.read_bytes()==raw and stat.S_IMODE(destination.stat().st_mode)==row["mode"]
                source=raw.decode("utf-8");tree=ast.parse(source,filename=row["path"])
                imports=[]
                for node in ast.walk(tree):
                    if isinstance(node,ast.Import):imports.append(dict(line=node.lineno,kind="import",names=[x.name for x in node.names]))
                    elif isinstance(node,ast.ImportFrom):imports.append(dict(line=node.lineno,kind="from",module=node.module,level=node.level,names=[x.name for x in node.names]))
                binding=dict(archive=item["name"],original_member=row["path"],path=str(destination.relative_to(out)),
                    basename=basename,bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=row["mode"],
                    complete_archive_readback_before_export=True,parsed_only_not_executed=True,imports=imports,
                    tool_import_text_lines=[dict(line=i+1,text=line) for i,line in enumerate(source.splitlines()) if "tools." in line and ("import" in line or ".py" in line)])
                exports.append(binding)
            reports.append(dict(name=item["name"],status="PASS",members=len(seen),file_members=files,
                directories=directories,raw_file_bytes=total,selected_authors=len(candidates),
                all_original_bytes_SHA256_modes=True,archive_identity=item["archive"],ledger_identity=item["ledger"]))
        resolved={}
        for basename,wanted in PLAN["reference_only_source_lookups"].items():
            found=[r for r in exports if r["basename"]==basename and (r["bytes"],r["sha256"])==(wanted["bytes"],wanted["sha256"])]
            resolved[basename]=dict(expected=wanted,found=bool(found),matches=found)
        # Export only small exact selected authors to the console. Complete
        # ledgers, all candidates and every original archive stay in artifacts.
        emitted=set()
        for row in exports:
            key=(row["basename"],row["sha256"])
            if key in emitted:continue
            emitted.add(key);raw=(out/row["path"]).read_bytes()
            if row["basename"] in ("hia_composite_lowering_driver_helper.py","generate_hia_composite_raw_driver.py","legacy_authoring.py","program_authoring.py") and len(raw)<=65536:
                print("HIA_LOWERING_ORIGINAL_SOURCE "+json.dumps(dict(row,base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
        save(out/"complete-authoring-inventory.json",exports)
        save(out/"exact-required-lookups.json",resolved)
        assert Path(__file__).read_bytes()==self_raw
        for path,(size,sha,mode) in inputs.items():
            assert path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode)==mode
            assert path.stat().st_size==size
            with path.open("rb") as stream:
                actual=sha256()
                for chunk in iter(lambda:stream.read(1<<20),b""):actual.update(chunk)
            assert actual.hexdigest()==sha
        status="PASS"
    except BaseException as exc:
        failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        now=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu=now.ru_utime+now.ru_stime-initial.ru_utime-initial.ru_stime+child.ru_utime+child.ru_stime-initial_child.ru_utime-initial_child.ru_stime
        if cpu>=90:
            status="FAIL";failure=dict(error_class="AggregateCpuBudget",actual_cpu=cpu,earlier_failure=failure)
        required={name:[{k:v for k,v in row.items() if k!="imports" and k!="tool_import_text_lines"} for row in exports if row["basename"]==name and (row["bytes"],row["sha256"])==(wanted["bytes"],wanted["sha256"])] for name,wanted in PLAN["reference_only_source_lookups"].items()}
        report=dict(schema="hia-lowering-original-archives-readback-r1",status=status,head=os.environ.get("GITHUB_SHA"),
            archives=reports,selected_author_count=len(exports),exact_required_matches=required,failure=failure,
            elapsed_ns=time.monotonic_ns()-start,aggregate_CPU_seconds=cpu,
            limits=dict(cpu=90,wall=180,address=1<<30),original_tests_reexecuted=0,AST_originals_only=True,
            generated_HIA=0,actual_B3_entries=0,native_entries=0,qualification_inherited=False,
            missing_author_is_not_replaced_or_marked_restored=True)
        save(out/"summary.json",report)
        print("HIA_LOWERING_ORIGINAL_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
