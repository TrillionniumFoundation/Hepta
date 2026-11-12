"""Generate the exact new DB-node source; no previous component result is reused."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,os,stat,resource
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
assert resource.getrlimit(resource.RLIMIT_CPU)==(90,90)
assert resource.getrlimit(resource.RLIMIT_AS)==(1<<30,1<<30)
assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)
CONTEXT=Path(os.environ["HIA_NAMESPACE_CI_CONTEXT"]).resolve()
context=json.loads(CONTEXT.read_bytes());TREE=Path(context["namespace_working"])
DEV=Path(context["namespace_evidence"]);REF=Path(context["reference"])
OUT=DEV/"generation-r1";OUT.mkdir()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    path=Path(path).resolve();info=path.stat();assert stat.S_ISREG(info.st_mode)
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;exec(compile(path.read_bytes(),str(path),"exec"),value.__dict__);return value
sys.path.insert(0,str(REF))
before={str(p):pin(p) for p in sorted(TREE.rglob("*")) if p.is_file()}
for short in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_db_node_r1"):
    owner=load("tools."+short,TREE/"tools"/(short+".py"))
from hepta.hia_agent_assembly import render_assembly,assemble_program
source=render_assembly(owner.document()).encode("utf-8")
path=TREE/"examples/hia_bootstrap/agent_namespace_db_node_r1.hiaasm"
path.parent.mkdir(parents=True,exist_ok=True)
with path.open("xb") as stream:stream.write(source)
program=assemble_program(source.decode("utf-8"));document=program.as_dict()
profile=dict(functions=len(document["functions"]),
    blocks=sum(len(f["blocks"]) for f in document["functions"]),
    ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
    max_blocks=max(len(f["blocks"]) for f in document["functions"]),
    max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
assert 0<profile["functions"]<=128 and profile["blocks"]<=1536
assert profile["max_blocks"]<=256 and profile["ops"]<=8192 and profile["max_block_params"]<=16
after={p:pin(p) for p in before};assert before==after
result=dict(status="GENERATED",source_before=before,source_after=after,source_unchanged=True,
    generated={"db_node":dict(path=str(path),**pin(path),profile=profile)},
    scope="NEW_MAIN_DB_NODE_SOURCE_GENERATION_ONLY",VM_entries=0,native_entries=0,
    generation_limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0),
    ordinary_Store_closed=False,counts_inherited=False)
(OUT/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
print(json.dumps(result,sort_keys=True),flush=True)
