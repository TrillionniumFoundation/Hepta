import hashlib,json,os,pathlib,stat,subprocess,sys,tarfile,time,traceback
payload=json.load(sys.stdin)
BASE=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7")
SOURCE=BASE/"recovery-v70-published-8ca-r1"
TARGET=BASE/"static-budget-integration-v70-r1"
ARCHIVE=BASE/"library-recovery-v70-r1/static-budget-9028d181-source.tar.gz"
BASE_HEAD="8ca2197693c98e48d0d16ab3c077efc7cd535653"
BASE_TREE="d9a0a779301d25ffbfdc1601ed86ce0d76a9236b"
OWNER_HEAD="9028d1817f83908137cf24930dcdf3c8f6465392"
OWNER_TREE="abd4b9a64aaa7dfbc391d52c7c72bc8932a8fd7a"
PREREQUISITE="f5bb6d4a2014fc43a14737b92bc94e21e5b3be4b"
ENV=dict(os.environ,GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0")
record={"schema":"hepta.hia.static-budget-integration-recovery-inspection.v1","source":str(SOURCE),"target":str(TARGET),
"started_unix_ns":time.time_ns(),"commands":[],"status":"RUNNING","source_worktree_copied":False,
"lost_92fbc_recovered":False,"tests_run":False,"qualification":False,"product_original_modified":False}
audit=None
error=None
def run(args,timeout=20,details=True):
    before=time.monotonic()
    try:
        r=subprocess.run(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        item={"argv":args,"seconds":time.monotonic()-before,"returncode":r.returncode,
              "stdout":r.stdout.decode("utf-8","backslashreplace") if details else None,
              "stdout_bytes":len(r.stdout),"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),
              "stderr":r.stderr.decode("utf-8","backslashreplace"),"timed_out":False}
        record["commands"].append(item)
        if r.returncode:raise RuntimeError("command failed: "+repr(args))
        return r.stdout
    except subprocess.TimeoutExpired as exc:
        record["commands"].append({"argv":args,"timed_out":True,"stdout":(exc.stdout or b"").decode("utf-8","backslashreplace"),
                                   "stderr":(exc.stderr or b"").decode("utf-8","backslashreplace")})
        raise
def git(path,*args,timeout=20,details=True):
    return run(["git","-C",str(path),*args],timeout,details)
def exclusive(path,raw,mode=0o600):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
    with os.fdopen(fd,"wb") as stream:stream.write(raw)
try:
    if os.path.lexists(TARGET):raise FileExistsError("isolated target already exists")
    recipe_bytes=payload["recipe"].encode("utf-8")
    if len(recipe_bytes)!=83462 or hashlib.sha256(recipe_bytes).hexdigest()!="9763cfc30a7ba85609d50a2db6cb7aed70f8c1fa6aceb090c280f82753241f3d":
        raise RuntimeError("published recovery recipe identity mismatch")
    recipe=json.loads(recipe_bytes)
    expected_commits=recipe["replay"]["prerequisite_order"]
    record["expected_commits"]=expected_commits
    if git(SOURCE,"rev-parse","HEAD").decode().strip()!=BASE_HEAD or git(SOURCE,"rev-parse","HEAD^{tree}").decode().strip()!=BASE_TREE:
        raise RuntimeError("source repository committed base identity changed")
    archive_bytes=ARCHIVE.read_bytes()
    if len(archive_bytes)!=326545 or hashlib.sha256(archive_bytes).hexdigest()!="d2a9b74964119e532a086c7b523a4bd0fa226c3356753dec8dafa8f97f3bfe3f":
        raise RuntimeError("authorized archive identity mismatch")
    run(["git","clone","--shared","--no-checkout",str(SOURCE),str(TARGET)],60)
    git(TARGET,"checkout","--detach",BASE_HEAD,timeout=30)
    audit=TARGET/".git"/"hia-static-integration-recovery-r1"
    audit.mkdir(mode=0o700)
    exclusive(audit/"published-recovery-recipe.json",recipe_bytes)
    bundle_raw=None
    source_members=[]
    with tarfile.open(ARCHIVE,"r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():raise RuntimeError("archive contains unexpected non-file member")
            raw=tf.extractfile(member).read()
            if member.name=="static-budget-9028d181.bundle":
                bundle_raw=raw
            elif member.name.startswith("source/"):
                rel=member.name.removeprefix("source/")
                path=pathlib.PurePosixPath(rel)
                if path.is_absolute() or ".." in path.parts:raise RuntimeError("unsafe archived source path")
                source_members.append((rel,member.mode,raw))
    if bundle_raw is None or len(bundle_raw)!=186308 or hashlib.sha256(bundle_raw).hexdigest()!="1cd66f3ae322dfa8584e142dbd39f6a98882b34c4aa4310870f55a8e6cca05d3":
        raise RuntimeError("bundle identity mismatch")
    bundle=audit/"static-budget-9028d181.bundle"
    exclusive(bundle,bundle_raw)
    record["bundle"]={"path":str(bundle),"bytes":len(bundle_raw),"sha256":hashlib.sha256(bundle_raw).hexdigest()}
    git(TARGET,"cat-file","-e",PREREQUISITE+"^{commit}")
    git(TARGET,"merge-base","--is-ancestor",PREREQUISITE,BASE_HEAD)
    git(TARGET,"bundle","verify",str(bundle),timeout=30)
    git(TARGET,"fetch","--no-tags",str(bundle),"refs/heads/codex/hia-native-program-static-budget-20261111-dda7:refs/remotes/static-recovery/9028",timeout=30)
    git(TARGET,"fsck","--full","--no-dangling",timeout=60,details=False)
    actual_commits=git(TARGET,"rev-list","--reverse",PREREQUISITE+".."+OWNER_HEAD).decode().splitlines()
    record["actual_commits"]=actual_commits
    if actual_commits!=expected_commits:raise RuntimeError("owner dependency graph differs from published recovery recipe")
    if git(TARGET,"rev-parse",OWNER_HEAD+"^{tree}").decode().strip()!=OWNER_TREE:
        raise RuntimeError("owner source tree identity differs")
    record["dependency_changes"]=[]
    for commit in actual_commits:
        parent=git(TARGET,"show","-s","--format=%P",commit).decode().strip()
        paths=git(TARGET,"diff-tree","--no-commit-id","--name-only","-r",commit).decode().splitlines()
        subject=git(TARGET,"show","-s","--format=%s",commit).decode().strip()
        record["dependency_changes"].append({"commit":commit,"parent":parent,"subject":subject,"paths":paths})
    record["source_members"]=[]
    for rel,mode,expected in source_members:
        actual=git(TARGET,"show",OWNER_HEAD+":"+rel,details=False)
        tree=git(TARGET,"ls-tree",OWNER_HEAD,"--",rel).decode().strip()
        actual_mode=int(tree.split(" ",1)[0],8)&0o777
        if actual!=expected or actual_mode!=mode:
            raise RuntimeError("archived source differs from Git object: "+rel)
        record["source_members"].append({"path":rel,"bytes":len(actual),"mode":mode,"sha256":hashlib.sha256(actual).hexdigest(),"git_exact":True})
    if git(TARGET,"rev-parse","HEAD").decode().strip()!=BASE_HEAD:raise RuntimeError("inspection changed target HEAD")
    if git(TARGET,"status","--porcelain=v1","-z","--untracked-files=all",details=False):raise RuntimeError("inspection dirtied working tree")
    if git(SOURCE,"rev-parse","HEAD").decode().strip()!=BASE_HEAD or git(SOURCE,"rev-parse","HEAD^{tree}").decode().strip()!=BASE_TREE:
        raise RuntimeError("original committed base changed")
    record["target_head"]=BASE_HEAD
    record["target_tree"]=BASE_TREE
    record["owner_head"]=OWNER_HEAD
    record["owner_tree"]=OWNER_TREE
    record["target_clean"]=True
    record["source_committed_identity_unchanged"]=True
    record["status"]="BUNDLE_DEPENDENCIES_AND_SOURCE_EXACT"
except BaseException as exc:
    error=exc
    record["status"]="FAILED"
    record["error"]={"type":type(exc).__name__,"message":str(exc),"traceback":traceback.format_exc()}
finally:
    record["ended_unix_ns"]=time.time_ns()
    if audit is not None:
        exclusive(audit/"inspection.json",(json.dumps(record,indent=2,sort_keys=True)+"\n").encode())
    print(json.dumps(record,indent=2,sort_keys=True),flush=True)
sys.exit(0 if error is None else 1)
