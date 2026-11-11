"""Exact source-only ACK correction proof; no native or CLI outcome claim."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,copy,importlib.util,json,sys

def read_module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    assert sys.version_info[:3] == (3,12,14),sys.version
    oldpath=args.project/'development/reference-cli-entry-owner-r4.py'
    newpath=args.project/'tools/cli_entry_owner.py'
    before={path:path.read_bytes() for path in (oldpath,newpath)}
    assert sha256(before[oldpath]).hexdigest()=='d47f72eccb763bd4cc7ffb2a92aac7e96e3178c9f4df3c1bb60b9ccd68f0221c'
    assert sha256(before[newpath]).hexdigest()=='529a4c5cab15d8fb74e81d991d79b32070078a4149ca5f87ccfa966f6e95e496'
    old=read_module(oldpath,'cli_original_errno_ack')
    new=read_module(newpath,'cli_repaired_errno_ack')
    assert old.CONSTANTS == new.CONSTANTS
    assert old.BODY == new.BODY and old.literals() == new.literals()
    old_nodes=ast.parse(old.COMMON)
    expected=copy.deepcopy(old_nodes)
    predicate='pending != 1 and pending != 14 and word(s, 40) != 0'
    desired='pending != 1 and pending != 14 and pending != 16 and word(s, 40) != 0'
    oldtest=ast.parse(predicate,mode='eval').body
    newtest=ast.parse(desired,mode='eval').body
    ack=[node for node in expected.body if node.name=='acknowledge']
    assert len(ack)==1
    targets=[node for node in ast.walk(ack[0]) if isinstance(node,ast.If)
             and ast.dump(node.test)==ast.dump(oldtest)]
    assert len(targets)==1
    targets[0].test=newtest
    assert ast.dump(expected)==ast.dump(ast.parse(new.COMMON))
    # This is the original textual replacement's actual result in the pinned
    # interpreter. Keep its complete source and do not substitute a paraphrase.
    assert predicate not in old.COMMON
    assert len(new._ack_matches)==1
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'old-common.py').write_text(old.COMMON)
    (out/'new-common.py').write_text(new.COMMON)
    def result(expression,pending,raw):
        return eval(compile(ast.Expression(expression),'ack-predicate','eval'),
                    {'__builtins__':{}},{'pending':pending,'s':None,'word':lambda s,at:raw})
    rows=[]
    for pending,raw in [(16,0),(16,1),(16,2**64-2),(16,2**64-4095),
                        (1,123),(14,0),(14,1),(2,0),(2,1),(5,1)]:
        previous=result(oldtest,pending,raw);current=result(newtest,pending,raw)
        assert current==(previous and pending!=16)
        rows.append(dict(operation=pending,raw_return=str(raw),
                         old_nonzero_guard_rejects=previous,new_nonzero_guard_rejects=current))
    assert all(path.read_bytes()==raw for path,raw in before.items())
    report=dict(status='PASS_SOURCE_ONLY',scope='EXACT_SINGLE_AST_PREDICATE_CORRECTION',
                actual_native_entries=0,old_common_textual_matches=0,new_ast_matches=1,
                all_other_common_AST_equal=True,all_CLI_phase_bodies_byte_equal=True,
                predicates=rows,sources=[dict(path=str(path),bytes=len(raw),
                  sha256=sha256(raw).hexdigest()) for path,raw in before.items()])
    (out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True),flush=True)
if __name__=='__main__':main()
