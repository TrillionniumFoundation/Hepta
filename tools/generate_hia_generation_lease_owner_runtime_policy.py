"""Fixed typed-call and generation policy, sharing the original action dispatcher."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_typed as typed
from tools import generate_hia_generation_lease_owner_runtime_effects as effects
from tools import generate_hia_multiversion_public_lease_admission as public
ROOT=Path(__file__).resolve().parents[1]
ENTRY=typed.POLICY_ENTRY.replace('generation_lease_typed_policy','generation_lease_runtime_policy').replace(
 '    if length(s)!=256 or length(w)<WORK or length(o)<OUTPUT:',
 '    if length(s)<256 or length(w)<WORK or length(o)<OUTPUT:').replace(
 '    phase=get(o,PHASE)\n','    phase=get(o,PHASE)\n    if phase==306:\n        return begin_generation(s,o,w)\n    if length(s)!=256:\n        return 4294967293\n')
def source_program():
 functions=ast.parse(ENTRY+'\n'+typed.HELPERS+'\n'+effects.full_source()).body
 by_name={node.name:node for node in functions if isinstance(node,ast.FunctionDef)}
 needed={'generation_lease_runtime_policy'};pending=list(needed)
 while pending:
  name=pending.pop()
  for node in ast.walk(by_name[name]):
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Name):
    dependency=node.func.id
    if dependency in by_name and dependency not in needed:
     needed.add(dependency);pending.append(dependency)
 source='\n\n'.join(ast.unparse(node)for node in functions if isinstance(node,ast.FunctionDef)and node.name in needed)
 constants={**effects.C,'I_ADMISSION':public.I_ADMISSION,'TYPED_MAGIC':typed.TYPED_MAGIC,
  'TYPED_VALUE_MAGIC':typed.VALUE_MAGIC,'TYPED_VALUE_REPLY':typed.VALUE_REPLY,'TYPED_CALL_MAGIC':typed.CALL_MAGIC,
  'T_TYPED':typed.T_TYPED,'T_REQUEST':typed.T_REQUEST,'T_OUTPUT':typed.T_OUTPUT,'COREQ':public.STATE_MAGIC}
 return public.substitute(source,constants)
def main():
 tree=document(source_program(),'generation_lease_owner_runtime_policy')
 path=ROOT/'examples/hia_bootstrap/generation_lease_owner_runtime_policy.hepta'
 path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
