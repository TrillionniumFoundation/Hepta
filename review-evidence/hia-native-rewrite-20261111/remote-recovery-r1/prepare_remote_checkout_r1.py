import hashlib,importlib.util,json,os,shutil,subprocess,sys,time
from pathlib import Path
target=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
previous=Path("/var/tmp/hia9acdfa-v67-0ef9541b/source")
expected="a3c61136b79fdb7a4b6d6428fb4bdf31cd5ed270"
expected_tree="a29123841003090d9a5759e152d7681a79568ce3"
assert previous.is_dir()
assert not target.exists(), "new recovery directory already exists; inspect instead of overwriting"
target.mkdir(mode=0o700)
records=[]
def step(name,argv,cwd=None,timeout=600):
    start=time.monotonic()
    with (target/(name+".stdout.log")).open("xb") as out,(target/(name+".stderr.log")).open("xb") as err:
        p=subprocess.run(argv,cwd=cwd,stdout=out,stderr=err,timeout=timeout,env={**os.environ,"GIT_TERMINAL_PROMPT":"0"})
    r={"name":name,"returncode":p.returncode,"seconds":time.monotonic()-start}
    records.append(r)
    (target/"preparation-progress.json").write_text(json.dumps(records,indent=2)+"\n")
    print(json.dumps(r),flush=True)
    if p.returncode: raise RuntimeError("step failed: "+name)
    return (target/(name+".stdout.log")).read_text()
venv="/home/qian-qi/.openclaw/workspaces/azi5/tasks/hia-selfhost-completion-20261109/venv/bin/python"
assert Path(venv).exists()
probe="import sys,importlib.util,json;print(json.dumps({'version':sys.version,'executable':sys.executable,'modules':{k:importlib.util.find_spec(k) is not None for k in ('pytest','z3')}}))"
step("python-readiness",[venv,"-I","-B","-c",probe],timeout=30)
source=target/"source"
step("git-clone-local",["/usr/bin/git","clone","--no-hardlinks","--no-checkout",str(previous),str(source)],timeout=300)
step("git-fetch-recovery",["/usr/bin/git","-c","credential.helper=","-c","credential.interactive=false","fetch","--depth=1","https://github.com/TrillionniumFoundation/Hepta.git",expected],cwd=source,timeout=600)
step("git-checkout-recovery",["/usr/bin/git","checkout","--detach",expected],cwd=source,timeout=120)
head=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=source,text=True).strip()
tree=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD^{tree}"],cwd=source,text=True).strip()
assert head==expected and tree==expected_tree
tracked=subprocess.check_output(["/usr/bin/git","ls-tree","-rz","--long","HEAD"],cwd=source)
files=0;total=0
for entry in tracked.split(b"\0"):
    if not entry: continue
    meta,path=entry.split(b"\t",1);mode,kind,want,size=meta.split()
    assert kind==b"blob"
    p=source/os.fsdecode(path)
    data=os.readlink(p).encode() if mode==b"120000" else p.read_bytes()
    assert len(data)==int(size)
    actual=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest().encode()
    assert actual==want,os.fsdecode(path)
    if mode!=b"120000": assert bool(p.stat().st_mode&0o111)==(mode==b"100755"),os.fsdecode(path)
    files+=1;total+=len(data)
status=subprocess.check_output(["/usr/bin/git","status","--porcelain=v1","--untracked-files=no"],cwd=source,text=True)
assert not status,status
out={"schema":"hia-native-remote-recovery-checkout-v1","host":"rog","target":str(target),"source":str(source),"previous_source_unmodified_by_this_script":str(previous),"head":head,"tree":tree,"verified_files":files,"verified_bytes":total,"verified_git_blob_bytes_modes_sizes":True,"python":venv,"disk_free_bytes":shutil.disk_usage(target).free,"steps":records}
(target/"RECOVERY_CHECKOUT.json").write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps(out),flush=True)
