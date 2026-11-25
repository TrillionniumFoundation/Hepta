from pathlib import Path
import hashlib, importlib, json
from hepta.hia_agent_assembly import render_assembly
root=Path(__file__).resolve().parents[1]

def pin(path):
    p=root/path;b=p.read_bytes()
    return {'path':path,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

roles=[]
for module,entry,suffix in [
    ('multiversion_background_jobs',None,None),
    ('multiversion_background_job_refs',None,None),
    ('multiversion_background_queue',None,None),
    ('background_optimizer_execution','execute',''),
    ('background_optimizer_execution','publish_continue','_publication'),
    ('background_optimizer_submission',None,None),
    ('background_optimizer_account',None,None),
    ('background_optimizer_business_worker','business',''),
    ('background_optimizer_business_worker','business_failure','_failure'),
    ('background_optimizer_shutdown',None,None),
]:
    m=importlib.import_module('tools.generate_hia_'+module)
    d=m.document(m.source_program(entry)if entry else m.source_program(),module)
    name=module+(suffix or '')
    source='examples/hia_bootstrap/'+name+'.hepta'
    rendered=render_assembly(d)
    # The authoring module field is intentionally fixed by each original author.
    # Use that author's program/main convention for byte reproduction.
    if hasattr(m,'program'):
        d=m.program(entry)if entry else m.program()
        rendered=render_assembly(d)
    (root/source).write_text(rendered)
    functions=d['functions']
    values=[]
    for f in functions:
        names={x['name']for b in f['blocks']for x in b['params']}
        names.update(x['name']for b in f['blocks']for op in b['ops']for x in op.get('out',[]))
        values.append(len(names))
    row={'role':name,'author':pin('tools/generate_hia_'+module+'.py'),'source':pin(source),
         'functions':len(functions),'blocks':sum(len(f['blocks'])for f in functions),
         'operations':sum(len(b['ops'])for f in functions for b in f['blocks']),
         'maximum_function_blocks':max(len(f['blocks'])for f in functions),
         'maximum_function_values':max(values),
         'maximum_block_parameters':max(len(b['params'])for f in functions for b in f['blocks'])}
    assert row['functions']<=128 and row['blocks']<=1536 and row['operations']<=8192,row
    assert row['maximum_function_blocks']<=256 and row['maximum_function_values']<=2048 and row['maximum_block_parameters']<=16,row
    roles.append(row)
    print(name,row['source']['bytes'],row['functions'],row['blocks'],row['operations'],row['maximum_function_values'],flush=True)

report={'schema':'hepta.hia.background-retirement-consumers.offline.v1',
 'base_commit':'085069dec1631744ed6eb8d62f93c774240c9907',
 'authoring_verifier':'the original verify_program called by compact_authoring_cfg before and after compaction',
 'native_limits_changed':False,'native_built':False,'runtime_qualified':False,'whole_background_qualified':False,
 'shared_author_only':pin('tools/hia_background_retirement_source.py'),
 'source_policy_probes':pin('docs/HIA_BACKGROUND_NATIVE_RETIREMENT_SOURCE_PROBES.json'),
 'roles':roles,
 'new_captured_bindings':{
   'submission':'W800/808/816 actual cell entry/context/extent from the same captured public factory op17',
   'business':'W384/392/400 actual cell entry/context/extent from the same captured public factory op17',
   'shutdown':'W192/200/208 actual cell entry/context/extent; enclosing owner retains the factory lease',
   'account':'existing W192/200/208 retained without relocation'},
 'remaining':['actual coherent new dependency builds and native gates',
              'business retained cleanup after true worker exit',
              'original complete shutdown, failure drain, and allocation comparisons',
              'constructor fixed capture and complete public lifecycle']}
(root/'docs/HIA_BACKGROUND_NATIVE_RETIREMENT_CONSUMERS.json').write_text(json.dumps(report,indent=2)+'\n')
old=json.loads((root/'docs/HIA_BACKGROUND_NATIVE_RETIREMENT.json').read_text())
old['roles']=[r for r in roles if r['role'].startswith('multiversion_')]
old['shared_payload_failure_rule']='Only actual legacy op3 statuses 1,5,6 are established pre-consumption; protocol and internal outcomes remain unknown.'
(root/'docs/HIA_BACKGROUND_NATIVE_RETIREMENT.json').write_text(json.dumps(old,indent=2)+'\n')
sd=json.loads((root/'docs/HIA_BACKGROUND_NATIVE_SHUTDOWN.json').read_text())
sd['sources']=[{**pin(x['path']),'runtime_required':x['runtime_required']}for x in sd['sources']]
sd['sources'].append({**pin('tools/hia_background_retirement_source.py'),'runtime_required':False})
sd['author_validation']={k:v for k,v in roles[-1].items()if k not in ('author','source')}
sd['required_private_profiles']=['HIABGQ04','HIABJO03','HIABFP03/op26','HIABFQ04/op21','HIABVQ02/29,31']
(root/'docs/HIA_BACKGROUND_NATIVE_SHUTDOWN.json').write_text(json.dumps(sd,indent=2)+'\n')
print('all source pin records written; native qualification remains false')
