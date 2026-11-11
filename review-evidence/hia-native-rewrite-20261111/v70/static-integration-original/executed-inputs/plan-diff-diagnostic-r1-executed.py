import hashlib,json,os,pathlib,subprocess,time
R=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7/static-budget-integration-v70-r1")
A=R/".git/hia-static-integration-recovery-r1"
P=json.loads((A/"source-reconstruction-r1/write-plan.json").read_bytes())
E=dict(os.environ,GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
def git(*args):
 r=subprocess.run(["git","-C",str(R),*args],env=E,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 if r.returncode:raise RuntimeError(repr(args)+repr(r.stderr))
 return r.stdout
def sha(x):return hashlib.sha256(x).hexdigest()
def names(x):return {v.decode() for v in x.split(b"\0") if v}
expected={r["path"] for r in P if not r["before"]["exists"] or any(r["before"][k]!=r["after"][k] for k in ("bytes","mode","sha256"))}
actual=names(git("diff","--cached","--name-only","-z"))
diag={"schema":"hia.static-reconstruction-plan-diagnostic.v1","read_only_product":True,
"head":git("rev-parse","HEAD").decode().strip(),"tree":git("rev-parse","HEAD^{tree}").decode().strip(),
"expected_changed":sorted(expected),"actual_changed":sorted(actual),"missing":sorted(expected-actual),"extra":sorted(actual-expected),
"planned_unchanged":sorted({x["path"] for x in P}-expected),
"status":git("status","--porcelain=v1","--untracked-files=all").decode(),
"no_renames":git("diff","--cached","--no-renames","--name-status").decode(),"details":[]}
for row in P:
 path=row["path"]
 if path not in expected.symmetric_difference(actual):continue
 idx=git("show",":"+path)
 cur=(R/path).read_bytes()
 attrs=git("check-attr","--all","--",path).decode()
 diag["details"].append({"path":path,"plan":row,"index_bytes":len(idx),"index_sha256":sha(idx),
                         "current_bytes":len(cur),"current_sha256":sha(cur),"attrs":attrs})
raw=(json.dumps(diag,sort_keys=True,indent=2)+"\n").encode()
out=A/"plan-diff-diagnostic-r1.json"
fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as f:f.write(raw)
print(raw.decode(),end="")
