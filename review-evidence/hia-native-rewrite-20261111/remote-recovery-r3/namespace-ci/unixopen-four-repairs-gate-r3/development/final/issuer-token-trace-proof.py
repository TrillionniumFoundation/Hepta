"""Exact issuer token expansion and recorded trace signature proof; no HIA execution."""
from __future__ import annotations
import ast,hashlib,io,json,tokenize
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EXPECTED={
 "issuer-before.py":(23325,"abbb7f40338e7b099e855281d7dab9ff64834eed"),
 "issuer-after.py":(23378,"33c3bde4fdae6781ae33a20be776a22ea29222f8"),
 "replay-before.py":(19692,"625dcb194b2f28c6b05c5ab1551e9d21f93ee45d"),
 "replay-after.py":(19692,"b8854ced763c3df029137ae0e82e586e5f20ea55")}
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def identity(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),gitsha=git(raw))
raws={}
for name,(size,expected) in EXPECTED.items():
 p=ROOT/name;raw=p.read_bytes()
 # Source-transfer normalization is allowed only for this exact extra LF.
 if len(raw)==size+1 and raw.endswith(b"\n\n") and git(raw[:-1])==expected:
  p.write_bytes(raw[:-1]);raw=p.read_bytes()
 assert len(raw)==size and git(raw)==expected,(name,identity(raw))
 raws[name]=raw
old=raws["issuer-before.py"].decode();new=raws["issuer-after.py"].decode()
before="    for name,value in CONSTANTS.items():"
after="    for name,value in sorted(CONSTANTS.items(), key=lambda item: len(item[0]), reverse=True):"
assert old.count(before)==new.count(after)==1 and old.replace(before,after)==new
tree=ast.parse(new)
assign={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
constants=eval(compile(ast.Expression(assign["CONSTANTS"]),"constants-only","eval"),{"__builtins__":{},"int":int})
policy=ast.literal_eval(assign["POLICY"])
assert ast.literal_eval(next(n.value for n in ast.parse(old).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=="POLICY"))==policy
lines=policy.splitlines(keepends=True);starts=[];at=0
for line in lines:starts.append(at);at+=len(line)
def offset(pos):return starts[pos[0]-1]+pos[1]
replacements=[]
for t in tokenize.generate_tokens(io.StringIO(policy).readline):
 if t.type==tokenize.NAME and t.string in constants:
  replacements.append(dict(start=offset(t.start),end=offset(t.end),name=t.string,value=str(constants[t.string])))
token_exact=policy
for r in reversed(replacements):token_exact=token_exact[:r["start"]]+r["value"]+token_exact[r["end"]:]
longest=policy
for name,value in sorted(constants.items(),key=lambda item:len(item[0]),reverse=True):
 longest=longest.replace(name,str(value))
assert longest==token_exact
ast.parse(longest)
old_expanded=policy
for name,value in constants.items():old_expanded=old_expanded.replace(name,str(value))
try:ast.parse(old_expanded)
except SyntaxError as exc:old_error=dict(type="SyntaxError",message=exc.msg,line=exc.lineno,offset=exc.offset,text=exc.text)
else:raise AssertionError("original prefix corruption did not reproduce")
prefixes=[dict(short=a,long=b) for a in constants for b in constants if a!=b and b.startswith(a)]
old_replay=raws["replay-before.py"].decode();new_replay=raws["replay-after.py"].decode()
assert old_replay.count('magic(b"HIAUPT01")')==1
assert new_replay.count('magic(b"HIAPUT01")')==1
assert old_replay.replace('magic(b"HIAUPT01")','magic(b"HIAPUT01")')==new_replay
asm=Path("/workspace/scratch/9acdfa9f5639/runtime-development/nine-role-local-r4/source/inputs/native_unixopen_issued_executor.S").read_bytes()
assert git(asm)=="af439d426a8acb1a2bc114077185fc24ca42cc8a"
line=next(x for x in asm.decode().splitlines() if x.strip().startswith(".equ UI_PARENT_TRACE,"))
value=int(line.split(",")[1],0)
assert value.to_bytes(8,"little")==b"HIAPUT01"
trace=Path("/workspace/scratch/9acdfa9f5639/runtime-development/twelve-role-local-r2/evidence/policy-unixopen-open-success-r1/cases/new_named_temp/trace.bin").read_bytes()
assert trace[84424:84432]==value.to_bytes(8,"little")
for name,raw in raws.items():assert (ROOT/name).read_bytes()==raw
report=dict(schema="namespace-unix9-constant-and-trace-exact-proof-v1",
 scope="SOURCE_TOKEN_AND_RECORDED_BYTE_PROOF_NO_HIA_TARGET_EXECUTION",status="PASS",
 sources={name:identity(raw) for name,raw in raws.items()},
 issuer_one_line_exact_forward_inverse=True,POLICY_unchanged=True,
 constants_unchanged=True,constant_name_tokens=len(replacements),prefix_collisions=prefixes,
 new_expansion_equals_exact_NAME_token_substitution=True,
 new_expanded_AST_parses=True,old_expansion_error=old_error,
 constant_replacements=replacements,old_expansion=identity(old_expanded.encode()),
 new_expansion=identity(longest.encode()),replay_one_literal_exact_forward_inverse=True,
 fixed_ASM=identity(asm),actual_parent_trace_equate=line,decoded_magic=value.to_bytes(8,"little").decode(),
 original12_FAIL_trace=identity(trace),first_parent_record_offset=84424,
 source_before_after_exact=True,changed_test_assertions=0,
 product_AST_assembly=0,B3=0,VM=0,native=0,
 original_12_failure_unchanged=True)
data=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
(ROOT/"summary.json").write_bytes(data);assert (ROOT/"summary.json").read_bytes()==data
print(json.dumps({k:report[k] for k in ["status","constant_name_tokens","issuer_one_line_exact_forward_inverse","new_expansion_equals_exact_NAME_token_substitution","replay_one_literal_exact_forward_inverse","decoded_magic","B3","VM","native"]},sort_keys=True))
