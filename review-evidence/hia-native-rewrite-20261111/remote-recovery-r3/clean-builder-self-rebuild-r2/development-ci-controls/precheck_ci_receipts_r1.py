"""Execute only the current CI's immutable receipt-counting suffix."""
from pathlib import Path
import ast
import importlib.util
import json
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('selfbuild_ci_readonly_count', ROOT/'ci_self_rebuild_r4.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
out=ROOT/'ci-receipts-precheck-r1';out.mkdir()
state=m.Qualification(ROOT,out,ROOT/'ci-source-index-r2.json');state.project=ROOT
state.index=json.loads((ROOT/'ci-source-index-r2.json').read_bytes())
tree=ast.parse((ROOT/'ci_self_rebuild_r4.py').read_bytes())
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Qualification')
fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='fresh_gates')
at=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='receipt_rows')
module=ast.Module(body=fn.body[at:],type_ignores=[])
exec(compile(module,str(ROOT/'ci_self_rebuild_r4.py'), 'exec'),{**vars(m),'self':state})
report={'schema':'hia-selfbuild-exact-ci-receipt-suffix-local-precheck-r1','status':'PASS','scope':'READ_ONLY_EXISTING_RECEIPTS_NO_TARGET_EXECUTION','CI':m.record(ROOT/'ci_self_rebuild_r4.py'),'result':state.result,'receipt_index':m.record(out/'actual-external-compile-receipts.json'),'native_HIA_entries':0,'new_B3_calls':0}
m.write_json(out/'summary.json',report)
print(json.dumps({'status':'PASS','actual_external_B3':state.result['fresh_external_B3_calls'],'actual_HIA_packers':state.result['fresh_external_HIA_packer_calls'],'new_native_entries':0}),flush=True)
