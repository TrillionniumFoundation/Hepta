#!/usr/bin/env python3
"""Losslessly package a completed composition; never execute its tests or builds."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time

TARGET_ROOTS = {"cargo-target", "raw-cargo-target", "rust-shadow-target"}
COMPILED_SUFFIXES = {".o", ".obj", ".a", ".so", ".dylib", ".rlib", ".rmeta", ".pyc", ".olean", ".ilean"}
MAGIC = {b"\x7fELF", b"\x00asm", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}
PRIVATE_PREFIXES = ("raw-ndu-build/hepta-contracts/", "raw-ndu-build/hepta-ndu/", "raw-ndu-build/hepta-types/")
UPSTREAM_COMMIT = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
UPSTREAM_TREE = "2790a0ee579229f422d8e65d9c7bdbf7fde57e3f"
CHUNK_LIMIT = 768 * 1024
TAR_BLOCK = 8 * 1024 * 1024

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def compact(j):
    return json.dumps(j, sort_keys=True, separators=(",", ":")).encode()

def source_paths(root):
    result=[]
    for folder, dirs, names in os.walk(root, followlinks=False):
        here=Path(folder)
        for name in list(dirs):
            q=here/name
            if q.is_symlink():
                result.append(q)
                dirs.remove(name)
        result.extend(here/name for name in names)
    return sorted(result, key=lambda p:p.relative_to(root).as_posix())

def run_git(repo, args):
    return subprocess.check_output(["git", *args], cwd=repo)

def regular_snapshot(path, namespace, archived, reason):
    before=path.stat()
    sha=digest_file(path)
    after=path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_mode)==(after.st_size, after.st_mtime_ns, after.st_mode), ("input changed", str(path))
    return {"path":namespace,"kind":"regular","bytes":before.st_size,"sha256":sha,"original_mode":stat.S_IMODE(before.st_mode),"original_mtime_ns":before.st_mtime_ns,"archived":archived,"reason":reason}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--source-repo",required=True)
    ap.add_argument("--source-commit",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--external-work",required=True)
    args=ap.parse_args()
    started=time.time_ns()
    evidence=Path(args.input).resolve()
    repo=Path(args.source_repo).resolve()
    output=Path(args.output).resolve()
    external=Path(args.external_work).resolve()
    assert evidence!=output and evidence not in output.parents
    final=json.loads((evidence/"RESULT.json").read_text())
    assert final["status"]=="completed"
    assert final["source"]["commit"]==args.source_commit
    assert final["source_and_tools_unchanged"] is True
    command_paths=sorted((evidence/"commands").glob("*.command.json"))
    assert len(command_paths)==31, len(command_paths)
    last=json.loads((evidence/"commands/ndu_model_planner.command.json").read_text())
    assert last["returncode"]==0 and not last["timed_out"] and last.get("launch_error") is None
    source_tree=run_git(repo,["rev-parse",args.source_commit+"^{tree}"]).decode().strip()
    assert final["source"]["tree"]==source_tree
    output.mkdir(parents=True,exist_ok=False)
    external.mkdir(parents=True,exist_ok=False)
    raw_receipt=json.loads((evidence/"raw-ndu-build/build-receipt.json").read_text())
    assert raw_receipt["upstream"]["commit"]==UPSTREAM_COMMIT
    adapter_binding=[]
    for name,sha in sorted(raw_receipt["adapter_files"].items()):
        git_path="rust/hia-ndu-raw-model/"+name
        blob=run_git(repo,["cat-file","blob",args.source_commit+":"+git_path])
        actual=evidence/"raw-ndu-build/hia-ndu-bridge"/name
        assert hashlib.sha256(blob).hexdigest()==sha==digest_file(actual), ("unbound adapter",name)
        adapter_binding.append({"source_path":git_path,"input_path":"raw-ndu-build/hia-ndu-bridge/"+name,"bytes":len(blob),"sha256":sha})
    entries=[]
    files={}
    snapshots={}
    for path in source_paths(evidence):
        relative=path.relative_to(evidence).as_posix()
        namespace="evidence/"+relative
        if path.is_symlink():
            target=os.readlink(path)
            entries.append({"path":namespace,"kind":"symlink","target":target,"target_text_sha256":hashlib.sha256(os.fsencode(target)).hexdigest(),"archived":False,"reason":"symlink recorded without following or recreating it"})
            continue
        if not path.is_file():
            entries.append({"path":namespace,"kind":"other","archived":False,"reason":"nonregular filesystem entry"})
            continue
        reason=None
        if relative.startswith(PRIVATE_PREFIXES):
            reason="private NDU upstream crate snapshot; content excluded from PUBLIC package, exact hash retained, original unchanged outside Git"
        elif any(part in {".git", ".cargo", "vendor", "third_party", "third-party", "registry", "checkouts"} for part in Path(relative).parts):
            reason="dependency/vendor/VCS material; content excluded from PUBLIC package, exact hash retained outside Git"
        elif relative.startswith("raw-ndu-build/") and not (
            relative in {"raw-ndu-build/Cargo.lock","raw-ndu-build/Cargo.toml","raw-ndu-build/build-receipt.json"}
            or relative.startswith("raw-ndu-build/command-evidence/")
            or relative[len("raw-ndu-build/hia-ndu-bridge/"):] in raw_receipt["adapter_files"] and relative.startswith("raw-ndu-build/hia-ndu-bridge/")
        ):
            reason="unreviewed build workspace material; content excluded from PUBLIC package with exact inventory hash"
        elif relative.startswith("ndu-build/") and not (
            relative in {"ndu-build/BUILD_ENVELOPE.json","ndu-build/builder.stdout","ndu-build/builder.stderr","ndu-build/build/build-commands.json","ndu-build/build/identity.json"}
            or relative.startswith("ndu-build/build/commands/")
            or relative.startswith("ndu-build/build/native/")
        ):
            reason="unreviewed native build workspace material; content excluded from PUBLIC package with exact inventory hash"
        elif relative.split("/")[0] in TARGET_ROOTS:
            reason="Cargo target output; full content hash retained, original file remains outside Git"
        elif "__pycache__" in path.parts or path.suffix in COMPILED_SUFFIXES:
            reason="compiled intermediate; full content hash retained, original file remains outside Git"
        else:
            with path.open("rb") as f:
                magic=f.read(4)
            if magic in MAGIC or magic[:2]==b"MZ":
                reason="compiled native executable or library; full content hash retained, original file remains outside Git"
        entry=regular_snapshot(path,namespace,reason is None,reason or "losslessly archived original evidence bytes")
        entries.append(entry)
        snapshots[namespace]=(path,entry["bytes"],entry["original_mtime_ns"],entry["original_mode"])
        if entry["archived"]:
            files[namespace]=path
    print(json.dumps({"phase":"input_inventory","entries":len(entries),"archived":len(files)}),flush=True)
    by_relative={x["path"][len("evidence/"):]:x for x in entries if x["path"].startswith("evidence/")}
    for absolute,sha in final.get("frozen_artifacts_sha256",{}).items():
        p=Path(absolute)
        if p.is_relative_to(evidence):
            assert by_relative[p.relative_to(evidence).as_posix()]["sha256"]==sha, str(p)

    tracked=set(run_git(repo,["ls-tree","-r","--name-only",args.source_commit]).decode().splitlines())
    driver_paths={"tools/qualify_hia_composition.py","hepta/hia_ndu.py","hepta/hia_ndu_cost.py","hepta/hia_json_preflight.py"}
    for cp in command_paths:
        command=json.loads(cp.read_text())
        for token in command.get("argv",command.get("command",[])):
            if not isinstance(token,str):
                continue
            for prefix in ("tools/","hepta/"):
                at=token.find("/"+prefix)
                candidate=token[at+1:] if at>=0 else token
                if candidate.startswith(prefix) and candidate.endswith(".py"):
                    driver_paths.add(candidate)
    driver_paths |= {x for x in tracked if x.startswith("hepta/hia_ndu_raw") and x.endswith(".py")}
    driver_paths={x for x in driver_paths if x in tracked}
    driver_data={}
    for name in sorted(driver_paths):
        data=run_git(repo,["cat-file","blob",args.source_commit+":"+name])
        namespace="drivers/"+name
        driver_data[namespace]=data
        entries.append({"path":namespace,"kind":"regular","bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"archived":True,"reason":"exact Git blob of executed outer driver or NDU controller","source_commit":args.source_commit,"source_path":name})
    entries.sort(key=lambda e:e["path"])
    inventory=b"".join(compact(e)+b"\n" for e in entries)
    inventory_gz=gzip.compress(inventory,compresslevel=6,mtime=0)
    assert len(inventory_gz)<=CHUNK_LIMIT
    (output/"INVENTORY.jsonl.gz").write_bytes(inventory_gz)
    archive_path=external/"payload.tar"
    content_members={}
    deduplicated_members=0
    deduplicated_bytes=0
    with tarfile.open(archive_path,"w",format=tarfile.PAX_FORMAT) as tar:
        for name in sorted([*files,*driver_data]):
            data=driver_data.get(name)
            entry=next(e for e in entries if e["path"]==name)
            info=tarfile.TarInfo(name)
            info.size=entry["bytes"]
            info.mode=entry.get("original_mode",0o644)
            info.uid=info.gid=0
            info.uname=info.gname=""
            info.mtime=0
            content_key=(entry["sha256"],entry["bytes"])
            if content_key in content_members:
                info.type=tarfile.LNKTYPE
                info.linkname=content_members[content_key]
                info.size=0
                tar.addfile(info)
                deduplicated_members+=1
                deduplicated_bytes+=entry["bytes"]
            elif data is not None:
                tar.addfile(info,io.BytesIO(data))
                content_members[content_key]=name
            else:
                with files[name].open("rb") as f:
                    tar.addfile(info,f)
                content_members[content_key]=name
    archive_sha=digest_file(archive_path)
    expected={e["path"]:e for e in entries if e["archived"]}
    seen=set()
    with tarfile.open(archive_path,"r") as tar:
        for member in tar:
            assert (member.isfile() or member.islnk()) and member.name in expected and member.name not in seen
            if member.islnk():
                assert member.linkname in seen and expected[member.linkname]["sha256"]==expected[member.name]["sha256"]
            h=hashlib.sha256()
            f=tar.extractfile(member)
            assert f is not None
            for block in iter(lambda:f.read(1024*1024),b""):
                h.update(block)
            assert h.hexdigest()==expected[member.name]["sha256"], member.name
            if member.isfile():
                assert member.size==expected[member.name]["bytes"], member.name
            seen.add(member.name)
    assert seen==set(expected)
    parts=[]
    offset=0
    reconstructed_sha=hashlib.sha256()
    gzip_stream_sha=hashlib.sha256()
    concatenated=external/"payload.tar.gz"
    with concatenated.open("xb") as concat:
        def emit(data):
            nonlocal offset
            compressed=gzip.compress(data,compresslevel=6,mtime=0)
            if len(compressed)>CHUNK_LIMIT:
                middle=len(data)//2
                assert middle>0
                emit(data[:middle]);emit(data[middle:])
                return
            name=f"payload-{len(parts):04d}.tar-fragment.gz"
            path=output/name
            path.write_bytes(compressed)
            restored=gzip.decompress(path.read_bytes())
            assert restored==data
            restored_sha=hashlib.sha256(restored).hexdigest()
            parts.append({"path":name,"bytes":len(compressed),"sha256":hashlib.sha256(compressed).hexdigest(),"tar_offset":offset,"uncompressed_bytes":len(data),"uncompressed_sha256":restored_sha})
            reconstructed_sha.update(restored)
            gzip_stream_sha.update(compressed)
            concat.write(compressed)
            offset+=len(data)
        with archive_path.open("rb") as source:
            for data in iter(lambda:source.read(TAR_BLOCK),b""):
                emit(data)
    assert reconstructed_sha.hexdigest()==archive_sha and offset==archive_path.stat().st_size
    for name,(path,size,mtime,mode) in snapshots.items():
        now=path.stat()
        assert (now.st_size,now.st_mtime_ns,stat.S_IMODE(now.st_mode))==(size,mtime,mode),("input changed",name)
    assert [p.relative_to(evidence).as_posix() for p in source_paths(evidence)]==[e["path"][len("evidence/"):] for e in entries if e["path"].startswith("evidence/")], "input file set changed"
    included=[e for e in entries if e["archived"]]
    excluded=[e for e in entries if not e["archived"]]
    manifest={
      "schema":"hepta.hia.composition-evidence-publication.v2",
      "public_scope_version":2,
      "public_scope":{"private_upstream_content_archived":False,"private_source_prefixes":list(PRIVATE_PREFIXES),"upstream_commit":UPSTREAM_COMMIT,"upstream_tree":UPSTREAM_TREE,"upstream_repository":"https://github.com/TrillionniumFoundation/hepta-private-ci.git","verified_tracked_hepta_adapter_files":adapter_binding,"dependency_vendor_snapshots_archived":False,"original_measurements_and_failure_bytes_unchanged":True,"supersedes":"../PUBLIC_SCOPE_REVISION.json"},
      "campaign":evidence.name,"original_evidence_root":str(evidence),
      "source_commit":args.source_commit,"source_tree":source_tree,
      "producer_path":"../package_composition_evidence.py",
      "producer_sha256":digest_file(Path(__file__)),
      "created_unix_ns":time.time_ns(),"packaging_wall_ns":time.time_ns()-started,
      "source_results_unchanged":True,"command_receipts":len(command_paths),
      "last_timing_command":"commands/ndu_model_planner.command.json",
      "original_campaign_status":final["status"],
      "qualification_commands_passed":final["qualification_commands_passed"],
      "p0_same_combination_build_execute_reject_cancel_recover":final["p0_same_combination_build_execute_reject_cancel_recover"],
      "all_seven_research_targets_closed":final["all_seven_research_targets_closed"],
      "qualifications":final["qualifications"],
      "inventory":{"path":"INVENTORY.jsonl.gz","bytes":len(inventory_gz),"sha256":hashlib.sha256(inventory_gz).hexdigest(),"uncompressed_bytes":len(inventory),"uncompressed_sha256":hashlib.sha256(inventory).hexdigest(),"entries":len(entries)},
      "archive":{"format":"ordered independent gzip members containing consecutive fragments of one POSIX tar stream","tar_bytes":offset,"tar_sha256":archive_sha,"concatenated_gzip_bytes":concatenated.stat().st_size,"concatenated_gzip_sha256":gzip_stream_sha.hexdigest(),"part_limit_bytes":CHUNK_LIMIT,"deduplicated_regular_members":deduplicated_members,"deduplicated_content_bytes":deduplicated_bytes,"deduplication":"Exact SHA256-and-length matches use prior regular tar member hard links; every extracted member is rehashed before acceptance","parts":parts,"outside_git_complete_archive":str(concatenated)},
      "archived_entries":len(included),"archived_original_bytes":sum(e.get("bytes",0) for e in included),
      "inventory_only_entries":len(excluded),"inventory_only_original_bytes":sum(e.get("bytes",0) for e in excluded),
      "frozen_driver_paths":sorted(driver_paths),
      "verification":{"all_archive_members_match_inventory":True,"all_parts_roundtrip_exactly":True,"reconstructed_tar_hash_matches":True,"original_inputs_stat_and_file_set_unchanged":True,"original_frozen_artifact_hashes_match":True},
      "scope":{"all_original_raw_measurements_reports_logs_registrations_kept":True,"all_31_command_receipts_kept":True,"generated_c_cpp_rust_drivers_and_assembly_kept":True,"native_binaries_private_upstream_and_Cargo_intermediates":"inventory and SHA256 only; original files are retained at original_evidence_root","source_snapshot":"exact executed outer Python drivers and NDU controller Git blobs; this is not a replacement for the full source tree","timing":"packaging time is separate from original campaign; no measurements or outcomes rerun","ci_artifacts":"not copied; root publishes CI evidence separately"},
      "authority":"DENY_ALL","safety_certificate":False
    }
    (output/"MANIFEST.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    (output/"RESTORE.txt").write_text("The numbered payload files are independently valid gzip members. In manifest order, concatenate their compressed bytes to payload.tar.gz, then decompress the complete multi-member gzip stream to recover payload.tar. Validate every compressed-part hash, every decompressed-part hash, the whole tar hash, and each regular or safely bound prior-member hard-linked tar member against INVENTORY.jsonl.gz before extraction. Tar members use evidence/ for original evidence paths and drivers/ for exact frozen source blobs. Compiled output excluded from Git remains identified by exact path/size/SHA256 in INVENTORY.jsonl.gz. No failed attempt or original observation has been rewritten.\n")
    publication=[]
    for path in sorted(output.iterdir()):
        if path.is_file():
            publication.append({"path":path.name,"bytes":path.stat().st_size,"sha256":digest_file(path)})
    (output/"PUBLICATION_FILES.json").write_text(json.dumps({"schema":"hepta.hia.publication-files.v1","files":publication},indent=2,sort_keys=True)+"\n")
    archive_path.unlink()
    print(json.dumps({"phase":"completed","output":str(output),"manifest_sha256":digest_file(output/"MANIFEST.json"),"parts":len(parts),"publication_bytes":sum(x["bytes"] for x in publication)+(output/"PUBLICATION_FILES.json").stat().st_size,"archived_entries":len(included),"inventory_only_entries":len(excluded),"source_commit":args.source_commit,"qualification_commands_passed":final["qualification_commands_passed"]},sort_keys=True),flush=True)

if __name__=="__main__":
    main()
