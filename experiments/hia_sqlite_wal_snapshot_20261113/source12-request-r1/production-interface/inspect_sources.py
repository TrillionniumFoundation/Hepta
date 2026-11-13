"""Read-only source index for exact 8556199; no product imports or execution."""
from pathlib import Path
import ast, hashlib, json, re
BASE=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-fixture-successor-r1/source")
OUT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/agent-store-production-static-r1")
def pin(path, data):
 return {"path":path.relative_to(BASE).as_posix(),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()}
unpack=re.compile(r"core_unpack|HIAUNP|88485|de602c")
production=re.compile(r"sqlite3|(?:self\.)?(?:store|db|connection)\.db\.|\.db\.|AgentStore|\.transaction\(")
out={"schema":"hia.agent-store.static-source-index.v1","source_commit":"8556199d761540f84c15856a6a9cf1a6f863ffc5","source_tree":"d60dbcda95d3c06797fae7a4d97c4640fe37f627","read_only":True,"product_imports":0,"product_executions":0,"files":[],"unpack_anchors":[],"production_files":[],"SQL_calls":[],"test_methods":[]}
for directory in ("hepta","tools","tests"):
 for path in sorted((BASE/directory).rglob("*")):
  if not path.is_file() or path.suffix not in (".py",".json"):continue
  if path.suffix==".json" and not (directory=="tests" and "fixtures" in path.parts):continue
  data=path.read_bytes()
  try:text=data.decode("utf-8")
  except UnicodeDecodeError:continue
  rel=path.relative_to(BASE).as_posix();lines=text.splitlines()
  p=pin(path,data);matched=False
  if directory in ("tests","tools") and unpack.search(text):
   matched=True
   out["unpack_anchors"].append({"file":p,"matches":[{"line":i+1,"text":line,"before":lines[max(0,i-2):i],"after":lines[i+1:i+3]} for i,line in enumerate(lines) if unpack.search(line)]})
  if path.suffix!=".py": 
   if matched:out["files"].append(p)
   continue
  tree=ast.parse(text,filename=rel)
  parent={}
  for node in ast.walk(tree):
   for child in ast.iter_child_nodes(node):parent[child]=node
  def scope(node):
   parts=[]
   while node in parent:
    node=parent[node]
    if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):parts.append(node.name)
   return ".".join(reversed(parts))
  if directory=="hepta" and production.search(text):
   matched=True
   out["production_files"].append({"file":p,"imports":[{"line":n.lineno,"text":ast.get_source_segment(text,n)} for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))],"definitions":[{"name":scope(n)+"."+n.name,"line":n.lineno,"end_line":n.end_lineno} for n in ast.walk(tree) if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))],"matches":[{"line":i+1,"text":line} for i,line in enumerate(lines) if production.search(line)]})
  if directory=="hepta":
   for n in ast.walk(tree):
    if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ("execute","executemany","executescript","commit","rollback","cursor","connect"):
     receiver=ast.unparse(n.func.value)
     if "db" in receiver or "sqlite" in receiver or "conn" in receiver:
      matched=True
      out["SQL_calls"].append({"path":rel,"scope":scope(n),"line":n.lineno,"end_line":n.end_lineno,"receiver":receiver,"operation":n.func.attr,"call":ast.get_source_segment(text,n),"literal_sql":n.args[0].value if n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str) else None})
  if directory=="tests" and production.search(text):
   matched=True
   for n in ast.walk(tree):
    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith("test"):
     out["test_methods"].append({"path":rel,"id":rel[:-3].replace("/",".")+"."+scope(n)+"."+n.name,"line":n.lineno,"end_line":n.end_lineno,"body_directly_mentions_store_SQL":bool(production.search(ast.get_source_segment(text,n) or ""))})
  if matched:out["files"].append(p)
out["files"]=sorted({x["path"]:x for x in out["files"]}.values(),key=lambda x:x["path"])
body=(json.dumps(out,sort_keys=True,indent=2,ensure_ascii=True)+"\n").encode()
target=OUT/"RAW-SOURCE-INDEX.json"
with target.open("xb") as f:f.write(body)
print(json.dumps({"path":str(target),"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"files":len(out["files"]),"unpack_files":len(out["unpack_anchors"]),"production_files":len(out["production_files"]),"SQL_calls":len(out["SQL_calls"]),"test_methods":len(out["test_methods"]),"product_executions":0}))
