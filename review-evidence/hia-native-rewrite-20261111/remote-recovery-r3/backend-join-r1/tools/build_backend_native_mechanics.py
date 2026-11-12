"""Build the development-only fixed C mechanics; never encode HIA/Code/ELF here.
The build stage execs gcc in the enclosing original 180-wall process group.
All compiler descendants inherit 90 CPU / 1 GiB / core 0; common.run owns the
group timeout and wait. The seal stage requires that exact successful receipt.
This compiler artifact is not an installed-runtime or pure-HIA claim.
"""
from pathlib import Path
from hashlib import sha256
import argparse,json,os,resource,stat,sys
SOURCE_SHA="dae66f88b96826384c6c278e4f391754acdd43c51c989f963bd90e6bc83d764c"
def digest(raw):return sha256(raw).hexdigest()
def save(path,obj):path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
def pin(path):
 path=Path(path).absolute();st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
 raw=path.read_bytes()
 return dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(st.st_mode))
def same(row):return pin(row["path"])==row
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 p=argparse.ArgumentParser()
 p.add_argument("--stage",choices=("build","seal"),required=True)
 p.add_argument("--source",type=Path,required=True)
 p.add_argument("--out",type=Path,required=True)
 p.add_argument("--receipt",type=Path)
 args=p.parse_args();source=args.source.resolve();out=args.out.resolve()
 assert sys.version_info[:3]==(3,12,14)
 if args.stage=="build":
  out.mkdir(parents=True,exist_ok=False)
  compiler=Path("/usr/bin/gcc").resolve()
  source_pin=pin(source);compiler_pin=pin(compiler);builder_pin=pin(__file__)
  assert source_pin["sha256"]==SOURCE_SHA
  (out/"source.c").write_bytes(source.read_bytes())
  (out/"source.c").chmod(source_pin["mode"])
  target=out/"backend-native-mechanics"
  command=[str(compiler),"-std=c11","-O2","-fno-strict-aliasing","-Wall","-Wextra",
           "-Wno-misleading-indentation",str(source),"-o",str(target)]
  save(out/"build-inputs.json",dict(schema="hia-backend-development-C-mechanics-input-v1",
      source=source_pin,compiler=compiler_pin,builder=builder_pin,args=command,
      limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
          address=list(resource.getrlimit(resource.RLIMIT_AS)),
          core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
      group_timeout_owner="exact-pinned-common.run",gcc_exec_in_same_process_group=True,
      semantic_instruction_generation=False,installed=False))
  assert same(source_pin) and same(compiler_pin) and same(builder_pin)
  os.execve(str(compiler),command,{**os.environ,"LC_ALL":"C","LANG":"C"})
  raise AssertionError("unreachable exec")
 else:
  assert args.receipt is not None
  data=json.loads((out/"build-inputs.json").read_bytes())
  receipt=json.loads(args.receipt.read_bytes())
  assert receipt["status"]=="PASS" and receipt["returncode"]==0 and not receipt["timed_out"]
  assert receipt["timeout_seconds"]==180 and receipt["child_cpu_seconds"]<=90
  assert receipt["argv"][-1]==str(out) and receipt["argv"][2]==str(Path(__file__).resolve())
  assert data["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
  assert all(same(data[k]) for k in("source","compiler","builder"))
  assert data["source"]["sha256"]==SOURCE_SHA
  assert (out/"source.c").read_bytes()==source.read_bytes()
  target=out/"backend-native-mechanics";artifact=pin(target)
  assert artifact["bytes"]>0 and artifact["mode"]&0o111
  final=dict(schema="hia-backend-development-C-mechanics-built-v1",
      source=str(source),source_sha256=SOURCE_SHA,
      executable={k:artifact[k] for k in("bytes","sha256")},
      full_executable=artifact,compiler=data["compiler"],args=data["args"],
      actual_build_receipt=receipt,limits=data["limits"],source_before_after_exact=True,
      raw_source_snapshot=str(out/"source.c"),native_semantic_entries=0,
      compiler_TCB="system gcc development only",production=False,installed=False)
  save(target.with_suffix(".build.json"),final)
  save(out/"summary.json",dict(status="PASS_BUILD_ONLY",**final))
  print(json.dumps(dict(status="PASS_BUILD_ONLY",executable=artifact,
        source_sha256=SOURCE_SHA,native_semantic_entries=0,installed=False),sort_keys=True),flush=True)
if __name__=="__main__":main()
