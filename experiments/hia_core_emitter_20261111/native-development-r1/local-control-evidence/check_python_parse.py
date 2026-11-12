import ast, hashlib, json, os, platform, sys
from pathlib import Path
root=Path(__file__).resolve().parent
policy=json.loads((root/'policy.json').read_bytes())
observed=[]
for name,wanted in policy['controls'].items():
 raw=(root/name).read_bytes()
 assert len(raw)==wanted['bytes'] and hashlib.sha256(raw).hexdigest()==wanted['sha256']
 tree=ast.parse(raw,filename=name)
 compile(tree,name,'exec',dont_inherit=True)
 observed.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'parsed_and_compiled_only':True})
expected=json.loads((root/'expected-tests.json').read_bytes())
assert expected==policy['test_groups']
ids=[identifier for group in expected.values() for identifier in group['ids']]
assert len(ids)==len(set(ids))==116
report={'schema':'hia.core-native-control-python-parse.v1','status':'PASS','python':sys.version,'implementation':platform.python_implementation(),'controls':observed,'method_denominator':116,'product_modules_executed':False,'native_compiler_executed':False,'product_tests_executed':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
fd=os.open(root/'PYTHON-PARSE.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
with os.fdopen(fd,'wb') as out: out.write(raw)
print(json.dumps({'status':'PASS','parsed_control_files':len(observed),'methods':116,'python':platform.python_version(),'report_sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True))
