import hashlib,json,os,pathlib,stat,subprocess,sys,tarfile,tempfile,time,traceback
BASE=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7")
ROOT=BASE/"static-budget-integration-v70-r1"
A=ROOT/".git"/"hia-static-integration-recovery-r1"
OUT=A/"source-reconstruction-r1"
ARCHIVE=BASE/"library-recovery-v70-r1/static-budget-9028d181-source.tar.gz"
ORIGINAL=BASE/"recovery-v70-published-8ca-r1"
OLD_PREFIX="/workspace/scratch/dda74a4fae35/recovery-v67-reset-r1/hia-native-integration-v68/"
BASE_HEAD="8ca2197693c98e48d0d16ab3c077efc7cd535653"
BASE_TREE="d9a0a779301d25ffbfdc1601ed86ce0d76a9236b"
ENV=dict(os.environ,GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0")
record={"schema":"hepta.hia.static-budget-source-reconstruction.v1","status":"RUNNING",
"scope":"NEW_RECONSTRUCTION_FROM_SAVED_OWNER_FILES","root":str(ROOT),"base_head":BASE_HEAD,
"base_tree":BASE_TREE,"started_unix_ns":time.time_ns(),"qualification":False,"whole_native":False,
"default_native":False,"legacy_deletion":False,"original_9028_git_history_restored":False,
"lost_92fbc_recovered":False,"original_missing_prerequisite_failure_preserved":True,"tests_run":False,
"commands":[],"written":[],"patch_hunks":[],"inputs":[]}
error=None
created=False
def sha(raw):return hashlib.sha256(raw).hexdigest()
def exclusive(path,raw,mode=0o600):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
    with os.fdopen(fd,"wb") as f:f.write(raw)
def git(*args,timeout=30,details=True):
    argv=["git","-C",str(ROOT),*args]
    r=subprocess.run(argv,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    record["commands"].append({"argv":argv,"returncode":r.returncode,"stdout":r.stdout.decode("utf-8","backslashreplace") if details else None,
                               "stdout_bytes":len(r.stdout),"stdout_sha256":sha(r.stdout),"stderr":r.stderr.decode("utf-8","backslashreplace")})
    if r.returncode:raise RuntimeError("command failed: "+repr(argv))
    return r.stdout
def relpath(text):
    p=pathlib.PurePosixPath(text)
    if p.is_absolute() or ".." in p.parts or not p.parts:raise RuntimeError("unsafe relative path")
    return str(p)
virtual={}
before={}
modes={}
def seed(rel,raw,mode=None):
    rel=relpath(rel)
    if rel not in before:
        p=ROOT/rel
        if os.path.lexists(p):
            st=p.lstat()
            if not stat.S_ISREG(st.st_mode):raise RuntimeError("expected regular file: "+rel)
            old=p.read_bytes()
            before[rel]={"exists":True,"bytes":len(old),"sha256":sha(old),"mode":stat.S_IMODE(st.st_mode)}
        else:before[rel]={"exists":False}
    virtual[rel]=raw
    modes[rel]=mode if mode is not None else before[rel].get("mode",0o644)
def current(rel):
    if rel in virtual:return virtual[rel].decode("utf-8")
    raw=(ROOT/rel).read_bytes()
    seed(rel,raw)
    return raw.decode("utf-8")
try:
    if sys.version_info[:3]!=(3,14,4):raise RuntimeError("unexpected Python version")
    if os.path.lexists(OUT):raise FileExistsError("reconstruction output already exists")
    if git("rev-parse","HEAD").decode().strip()!=BASE_HEAD or git("rev-parse","HEAD^{tree}").decode().strip()!=BASE_TREE:
        raise RuntimeError("isolated base differs")
    if git("status","--porcelain=v1","-z","--untracked-files=all",details=False):
        raise RuntimeError("isolated base must be clean before reconstruction")
    old_failure=(A/"inspection.json").read_bytes()
    if len(old_failure)!=4959 or sha(old_failure)!="c729750ca255454d0ba3c659fe7fd1796283f4e12ef72b70f4e01b54d5f3d948":
        raise RuntimeError("original prerequisite failure receipt differs")
    recipe_raw=(A/"published-recovery-recipe.json").read_bytes()
    if len(recipe_raw)!=83462 or sha(recipe_raw)!="9763cfc30a7ba85609d50a2db6cb7aed70f8c1fa6aceb090c280f82753241f3d":
        raise RuntimeError("published recipe differs")
    recipe=json.loads(recipe_raw)
    for name,artifact in recipe["artifacts"].items():
        raw=artifact["content"].encode("utf-8")
        if len(raw)!=artifact["bytes"] or sha(raw)!=artifact["sha256"]:
            raise RuntimeError("recipe artifact identity mismatch: "+name)
    archive_raw=ARCHIVE.read_bytes()
    if len(archive_raw)!=326545 or sha(archive_raw)!="d2a9b74964119e532a086c7b523a4bd0fa226c3356753dec8dafa8f97f3bfe3f":
        raise RuntimeError("saved source archive differs")
    expected_paths={
        "hepta/hia_static_budget.py","hepta/hia_static_budget_native.py",
        "tools/generate_hia_static_budget.py","examples/hia_bootstrap/static_budget.hiaasm",
        "tests/test_hia_static_budget_native.py","docs/HIA_STATIC_BUDGET_NATIVE.md",
        "tools/hia_native_bigints.py","tests/test_hia_native_bigints.py",
        "tools/hia_heap_bound_graphs.py","tests/test_hia_heap_graphs_native.py",
        "hepta/hia_native_value_graph.py","tools/hia_native_value_graph.py",
        "tests/test_hia_native_binary_graph.py","tests/test_hia_native_value_graph.py"}
    found=set()
    with tarfile.open(ARCHIVE,"r:gz") as tf:
        cm=tf.getmember("static-budget-9028d181-checkpoint.json")
        checkpoint=tf.extractfile(cm).read()
        if len(checkpoint)!=7764 or sha(checkpoint)!="690dbb3ff3df351d9c65b1320aa1657eddc85fd15debe39be364cb58647f945c":
            raise RuntimeError("saved owner checkpoint differs")
        record["saved_owner_checkpoint"]=json.loads(checkpoint)
        for member in tf.getmembers():
            if not member.name.startswith("source/"):continue
            rel=relpath(member.name.removeprefix("source/"))
            if not member.isfile() or rel not in expected_paths or rel in found:
                raise RuntimeError("unexpected saved source member: "+rel)
            raw=tf.extractfile(member).read()
            if len(raw)!=member.size or member.mode!=0o644:raise RuntimeError("saved source member representation differs")
            seed(rel,raw,member.mode)
            record["inputs"].append({"path":rel,"source":"verified 9028 archive","bytes":len(raw),"mode":member.mode,"sha256":sha(raw)})
            found.add(rel)
    if found!=expected_paths:raise RuntimeError("saved owner dependency file set incomplete")
    registration_paths=set()
    for key in recipe["replay"]["patches"]:
        lines=recipe["artifacts"][key]["content"].splitlines(keepends=True)
        if lines[0].strip()!="*** Begin Patch" or lines[-1].strip()!="*** End Patch":
            raise RuntimeError("unsupported patch envelope")
        i=1
        rel=None
        while i<len(lines)-1:
            line=lines[i]
            if line.startswith("*** Update File: "):
                full=line[len("*** Update File: "):].rstrip("\r\n")
                if not full.startswith(OLD_PREFIX):raise RuntimeError("unexpected old checkout prefix")
                rel=relpath(full[len(OLD_PREFIX):])
                registration_paths.add(rel)
                current(rel)
                i+=1
                continue
            if line.rstrip("\r\n")!="@@":
                raise RuntimeError("unsupported patch control: "+repr(line))
            if rel is None:raise RuntimeError("hunk has no target")
            i+=1
            chunk=[]
            while i<len(lines)-1 and not lines[i].startswith("@@") and not lines[i].startswith("*** "):
                row=lines[i]
                if row[:1] not in (" ","+","-"):raise RuntimeError("unsupported patch row")
                chunk.append(row)
                i+=1
            old="".join(row[1:] for row in chunk if row[0] in (" ","-"))
            new="".join(row[1:] for row in chunk if row[0] in (" ","+"))
            text=current(rel)
            count=text.count(old) if old else 0
            if count!=1:raise RuntimeError("patch context match count "+str(count)+" for "+key+" in "+rel)
            seed(rel,text.replace(old,new,1).encode("utf-8"),modes[rel])
            record["patch_hunks"].append({"patch":key,"path":rel,"old_sha256":sha(old.encode()),"new_sha256":sha(new.encode()),"matches":count})
    complete=recipe["replay"]["complete_file"]
    if os.path.lexists(ROOT/complete["path"]):raise RuntimeError("new installed integration test unexpectedly exists")
    seed(complete["path"],recipe["artifacts"][complete["artifact"]]["content"].encode("utf-8"),0o644)
    registration_paths.add(complete["path"])
    if len(registration_paths)!=17 or len(record["patch_hunks"])!=40:
        raise RuntimeError("registration path/hunk inventory differs")
    proof_rel="tests/test_hia_scalar_proof_identity.py"
    proof=(ORIGINAL/proof_rel).read_bytes()
    if len(proof)!=6620 or sha(proof)!="03cbde73f488afc7b44dbc0fd25b785a35ffa4acd8cda19feabc72c10558be0e":
        raise RuntimeError("authorized scalar proof fixture differs")
    seed(proof_rel,proof,0o644)
    record["inputs"].append({"path":proof_rel,"source":"separately authorized v70 fixture repair","bytes":len(proof),"mode":0o644,"sha256":sha(proof)})
    if len(virtual)!=30:raise RuntimeError("unexpected reconstructed path count: "+str(len(virtual)))
    OUT.mkdir(mode=0o700)
    created=True
    exclusive(OUT/"saved-owner-checkpoint.json",checkpoint)
    plan=[{"path":rel,"before":before[rel],"after":{"bytes":len(raw),"sha256":sha(raw),"mode":modes[rel]}} for rel,raw in sorted(virtual.items())]
    exclusive(OUT/"write-plan.json",(json.dumps(plan,indent=2,sort_keys=True)+"\n").encode())
    for rel,raw in sorted(virtual.items()):
        p=ROOT/rel
        old=before[rel]
        if old["exists"]:
            if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=old["sha256"] or stat.S_IMODE(p.stat().st_mode)!=old["mode"]:
                raise RuntimeError("target changed after plan: "+rel)
        elif os.path.lexists(p):
            raise RuntimeError("new target appeared after plan: "+rel)
        p.parent.mkdir(parents=True,exist_ok=True)
        fd,temp=tempfile.mkstemp(prefix=".hia-reconstruction-",dir=p.parent)
        try:
            with os.fdopen(fd,"wb") as f:f.write(raw)
            os.chmod(temp,modes[rel])
            os.replace(temp,p)
        finally:
            if os.path.exists(temp):os.unlink(temp)
        if p.read_bytes()!=raw or stat.S_IMODE(p.stat().st_mode)!=modes[rel]:
            raise RuntimeError("written source identity differs: "+rel)
        record["written"].append({"path":rel,"bytes":len(raw),"sha256":sha(raw),"mode":modes[rel]})
    git("add","--",*sorted(virtual))
    git("diff","--cached","--check")
    changed=git("diff","--cached","--name-only","-z",details=False).split(b"\0")
    changed={p.decode() for p in changed if p}
    if changed!=set(virtual):raise RuntimeError("staged path set differs from authorized source plan")
    record["source_tree_before_generation"]=git("write-tree").decode().strip()
    record["status_porcelain"]=git("status","--porcelain=v1","--untracked-files=all").decode()
    record["diff_stat"]=git("diff","--cached","--stat").decode()
    record["registration_paths"]=sorted(registration_paths)
    record["generated_assets_pending"]=True
    record["status"]="RECONSTRUCTED_SOURCE_AND_REGISTRY_PENDING_GENERATION"
except BaseException as exc:
    error=exc
    record["status"]="FAILED"
    record["error"]={"type":type(exc).__name__,"message":str(exc),"traceback":traceback.format_exc()}
finally:
    record["ended_unix_ns"]=time.time_ns()
    report_path=OUT/"report.json" if created else A/"source-reconstruction-r1-failed-before-write.json"
    exclusive(report_path,(json.dumps(record,indent=2,sort_keys=True)+"\n").encode())
    data=report_path.read_bytes()
    print(json.dumps({"status":record["status"],"scope":record["scope"],"error":record.get("error"),
                      "report":str(report_path),"report_bytes":len(data),"report_sha256":sha(data),
                      "written":len(record["written"]),"hunks":len(record["patch_hunks"]),
                      "source_tree_before_generation":record.get("source_tree_before_generation"),
                      "qualification":False,"tests_run":False},sort_keys=True,indent=2),flush=True)
sys.exit(0 if error is None else 1)
