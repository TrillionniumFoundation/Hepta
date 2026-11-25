"""Author the independent HIAGCN01 resumable, full-width scalar CNF role.

This file is a development author. The executable consumes only its checked-in
HIA source. It does not call a Python/Rust/Z3 solver or the old bounded CNF role.
"""
from pathlib import Path
import ast,copy,json
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import _CORE_TRAP_TAGS
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_sha_alias import Builder
from tools.generate_hia_cnf import BODY
from tools.hia_general_cnf_common import CONSTANTS,ENTRY,HASH,FORMULA_HASH,sha_source
from tools.hia_general_cnf_projection import NODES,DRIVER as PROJECTOR,lifted_projection
from tools.hia_general_cnf_bitblast import LOGIC,DRIVER as BITBLAST,lifted_bitblast
from tools.hia_general_cnf_solver import SOLVER,WITNESS

ROOT=Path(__file__).resolve().parents[1]

def evaluator_source():
    fns={n.name:n for n in ast.parse(BODY).body if isinstance(n,ast.FunctionDef)}
    selected=('evaluate_word_node','evaluate_word_division','evaluate_signed_division','evaluate_word_overflow')
    class Lift(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            if n.name=='evaluate_word_node':
                n.name='evaluate_word_operation'
                n.args.args=n.args.args[1:]
                n.args.args[0].arg='w'
            return self.generic_visit(n)
        def visit_Name(self,n):
            if n.id in ('source','scratch'):return ast.copy_location(ast.Name('w',n.ctx),n)
            return n
        def visit_Call(self,n):
            n=self.generic_visit(n)
            if isinstance(n.func,ast.Name):
                if n.func.id=='read64':n.func.id='nget'
                elif n.func.id=='read_stack':
                    n.func.id='get';n.args[1]=ast.BinOp(ast.Name('PHI_BASE',ast.Load()),ast.Add(),n.args[1])
            return n
    values=[ast.unparse(ast.fix_missing_locations(Lift().visit(copy.deepcopy(fns[n])))) for n in selected]
    values.append('''def evaluate_general_word(w:mutbuf,node:u64) -> u64:
    row=32+40*node
    op=nget(w,row)
    if op == 2:
        return nget(w,row+32)
    return evaluate_word_operation(w,op,nget(w,row+8),row)
''')
    return '\n\n'.join(values)

def policy_source():
    constants=dict(CONSTANTS)
    constants.update(PROJECT_OVERFLOW_CODE=_CORE_TRAP_TAGS['overflow'],PROJECT_DIVISION_CODE=_CORE_TRAP_TAGS['division_by_zero'],PROJECT_TRAP_CODE_MAX=len(_CORE_TRAP_TAGS))
    text='\n\n'.join((ENTRY,HASH,FORMULA_HASH,sha_source(),NODES,lifted_projection(),PROJECTOR,LOGIC,lifted_bitblast(),BITBLAST,SOLVER,WITNESS,evaluator_source()))
    class Bind(ast.NodeTransformer):
        def visit_Name(self,n):
            if n.id in constants:return ast.copy_location(ast.Constant(constants[n.id]),n)
            return n
    tree=ast.fix_missing_locations(Bind().visit(ast.parse(text)))
    names=[n.name for n in tree.body]
    assert len(names)==len(set(names)),names
    return ast.unparse(tree)+'\n'

def main():
    source=policy_source()
    doc=document(source,'general_cnf',builder_type=Builder)
    target=ROOT/'examples/hia_bootstrap/general_cnf.hepta'
    target.write_text(render_assembly(doc))
    counts={'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),'ops':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
    print(json.dumps({'source_bytes':target.stat().st_size,'author_bytes':len(source),'counts':counts},sort_keys=True),flush=True)

if __name__=='__main__':main()
