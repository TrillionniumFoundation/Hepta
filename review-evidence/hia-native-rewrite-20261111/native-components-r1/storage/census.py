#!/usr/bin/env python3
"""Read-only exact-source census. Does not import production or execute tests."""
from pathlib import Path
from hashlib import sha256
import ast, collections, json, re, subprocess
ROOT=Path('/workspace/scratch/9acdfa9f5639/native-agent-state-integration')
OUT=Path(__file__).resolve().parent
snapshot_path=Path('/workspace/scratch/9acdfa9f5639/hia-v65-stage5-publication/full-source-snapshot.json')
raw=snapshot_path.read_bytes()
assert len(raw)==368228 and sha256(raw).hexdigest()=='53697c5ebac2a0aa91e631fb3081f951635322e9b16600150fcd82725a288e6b'
expected=json.loads(raw)
assert expected['head']=='d5da1eb760454ef3df5153c5e80eb046ddb389d9'
OWNER_PATHS=('hepta/hia_agent_store.py','hepta/hia_agent_service.py','hepta/hia_agent_journal_native.py')
TEST_PATHS=('tests/test_hia_agent_native_tools.py','tests/test_hia_agent_journal_native.py',
 'tests/test_hia_agent_artifact_store_native.py','tests/test_hia_agent_candidate_native.py',
 'tests/test_hia_worker_request_native.py','tests/test_hia_worker_request_review.py',
 'tests/test_hia_agent_native_campaign.py','tests/test_hia_agent_buffer_lifecycle.py',
 'tests/test_hia_agent_native_proof_contract.py','tests/test_hia_agent_installed_resources.py')
GATE_PATHS=('tools/qualify_hia_agent_journal_callers.py','tools/qualify_hia_agent_buffer_lifecycle.py',
 'tools/hia_agent_native_qualification.py','hepta/hia_agent_worker.py',
 'docs/HIA_AGENT_JOURNAL_NATIVE.md','.github/workflows/hia-core.yml',
 'review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v3.py')
pins={}
def read(path):
    data=(ROOT/path).read_bytes()
    actual=sha256(data).hexdigest()
    assert actual==expected['files'][path],path
    pins[path]={'bytes':len(data),'sha256':actual}
    return data.decode()
sql=[];transactions=[];tests=[];ddl=[]
class Visitor(ast.NodeVisitor):
    def __init__(self,path,text):
        self.path,self.text,self.stack,self.withs=path,text,[],[]
    def visit_ClassDef(self,node):
        self.stack.append(node.name);self.generic_visit(node);self.stack.pop()
    def visit_FunctionDef(self,node):
        self.stack.append(node.name)
        if node.name.startswith('test_'):
            tests.append({'path':self.path,'id':'.'.join([self.path[:-3].replace('/','.')]+self.stack),
                          'line':node.lineno,'end_line':node.end_lineno})
        self.generic_visit(node);self.stack.pop()
    def visit_With(self,node):
        contexts=[ast.unparse(item.context_expr) for item in node.items]
        selected=[x for x in contexts if '.transaction(' in x]
        if selected:transactions.append({'path':self.path,'owner':'.'.join(self.stack),'line':node.lineno,
                                        'end_line':node.end_lineno,'context':selected})
        self.withs.extend(selected);self.generic_visit(node)
        if selected:del self.withs[-len(selected):]
    def visit_Call(self,node):
        if self.path in OWNER_PATHS and isinstance(node.func,ast.Attribute) and node.func.attr in ('execute','executescript'):
            receiver=ast.unparse(node.func.value)
            if receiver.endswith('.db') and node.args:
                assert isinstance(node.args[0],ast.Constant) and type(node.args[0].value) is str
                statement=node.args[0].value
                entry={'path':self.path,'owner':'.'.join(self.stack),'line':node.lineno,
                       'end_line':node.end_lineno,'receiver':receiver,'method':node.func.attr,
                       'sql':statement,'parameters_source':ast.unparse(node.args[1]) if len(node.args)>1 else None,
                       'lexical_transactions':list(self.withs),
                       'tables':sorted(set(re.findall(r'\b(?:FROM|INTO|UPDATE|TABLE IF NOT EXISTS)\s+(\w+)',statement,re.I)))}
                sql.append(entry)
                if node.func.attr=='executescript':
                    ddl.extend(x.strip()+';' for x in statement.split(';') if x.strip())
        self.generic_visit(node)
for path in OWNER_PATHS:
    text=read(path);Visitor(path,text).visit(ast.parse(text))
for path in TEST_PATHS:
    text=read(path);Visitor(path,text).visit(ast.parse(text))
# Only production SQL is the owner inventory; test SQL has deliberately injected observations.
production_sql=[row for row in sql if row['path'] in OWNER_PATHS]
production_transactions=[row for row in transactions if row['path'] in OWNER_PATHS]
for path in GATE_PATHS:read(path)
tracked_python=[p for p in expected['files'] if p.endswith('.py') and p.split('/')[0] in ('hepta','tools')]
callers=[]
production_sql_files=[]
for path in tracked_python:
    text=(ROOT/path).read_text()
    if not re.search(r'\bAgentStore\b|\bHIAAgentService\b|\.store\.db|\.acquire_slot\(|\.invoke_lease\(|\.release_slot\(',text):
        continue
    actual=sha256(text.encode()).hexdigest()
    assert actual==expected['files'][path],path
    pins[path]={'bytes':len(text.encode()),'sha256':actual}
    matches=[]
    for no,line in enumerate(text.splitlines(),1):
        if re.search(r'AgentStore\(|HIAAgentService\(|\.store\.db|\.acquire_slot\(|\.invoke_lease\(|\.release_slot\(',line):
            matches.append({'line':no,'text':line.strip()})
    if matches:callers.append({'path':path,'matches':matches})
    if re.search(r'(?:self\.db|store\.db)\.(?:execute|executescript)\(',text):
        production_sql_files.append(path)
assert sorted(production_sql_files)==sorted(OWNER_PATHS),production_sql_files
assert len(ddl)==10
out={'schema':'hia.agent-persistence-static-census.v1','scope':'Read-only pinned-source inventory, no native/test execution or qualification',
     'source_commit':expected['head'],'source_tree':expected['tree'],'snapshot_sha256':sha256(raw).hexdigest(),
     'owner_files':list(OWNER_PATHS),'source_pins':pins,'schema_ddl':ddl,
     'sql_call_sites':production_sql,'sql_call_site_count':len(production_sql),
     'sql_calls_by_owner_file':dict(collections.Counter(row['path'] for row in production_sql)),
     'distinct_sql':sorted(set(row['sql'] for row in production_sql)),
     'lexical_transaction_blocks':production_transactions,
     'transaction_caveat':'Lexical contexts are not an interprocedural proof. adopt/rollback and their store.put calls run within the call owner atomic transaction; ordinary calls retain autocommit behavior.',
     'production_constructor_and_direct_callers':callers,'audited_test_ids':tests,
     'test_execution_claimed':False,'source_mutation':False}
for path,row in pins.items():assert sha256((ROOT/path).read_bytes()).hexdigest()==row['sha256'],path
target=OUT/'census.json'
data=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode()
target.write_bytes(data)
print(json.dumps({'path':str(target),'bytes':len(data),'sha256':sha256(data).hexdigest(),
 'owner_call_counts':out['sql_calls_by_owner_file'],'all_sql_calls':len(production_sql),
 'distinct_sql':len(out['distinct_sql']),'ddl':len(ddl),'lexical_transactions':len(production_transactions),
 'pinned_files':len(pins),'listed_tests':len(tests),'source_recheck':True},sort_keys=True))

