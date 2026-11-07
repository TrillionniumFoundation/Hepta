#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently validate only the REA ledger source projection on ai395."""
import contextlib, hashlib, importlib.util, json, pathlib, subprocess, sys
sys.dont_write_bytecode = True
task = pathlib.Path('/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4')
root = task / 'runtime'
evidence = task / 'evidence'
expected_commit = 'd95866c9e244e03a182740d420f94294ee43cdcd'
log = evidence / 'runtime-rea-ledger-validation.log'
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def clean():
    assert subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=root,text=True).strip() == expected_commit
    assert not subprocess.check_output(['/usr/bin/git','status','--porcelain=v1'],cwd=root,text=True).strip()
clean()
spec = importlib.util.spec_from_file_location('independent_rea_compatibility_ledger',root/'scripts/rea_compatibility_ledger.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
paths = [module.INPUTS_PATH,module.MAP_PATH,module.ENVIRONMENT_PATH,module.LEDGER_PATH,
         'scripts/rea_compatibility_ledger.py','tests/rea_compatibility_ledger_tests.py']
before = {path:digest(root/path) for path in paths}
with log.open('w') as stream, contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
    inputs = module.read_json(root/module.INPUTS_PATH)
    mapping = module.read_json(root/module.MAP_PATH)
    environment = module.read_json(root/module.ENVIRONMENT_PATH)
    old = module.read_json(root/module.LEDGER_PATH)
    snapshots = module.snapshot_rows(old['tools'])
    snapshot_digest = module.digest_json(snapshots)
    assert snapshot_digest == inputs['catalog_snapshot_sha256']
    new = module.assemble_ledger(root,module.published_pin(root,inputs),inputs,mapping,environment,snapshots)
    assert set(old) == set(new)
    assert {k:v for k,v in old.items() if k!='runtime'} == {k:v for k,v in new.items() if k!='runtime'}
    assert set(old['runtime']) == set(new['runtime'])
    retained = lambda value: {k:v for k,v in value.items() if k not in ('source_files','source_manifest_sha256')}
    assert retained(old['runtime']) == retained(new['runtime'])
    old_files, new_files = old['runtime']['source_files'], new['runtime']['source_files']
    assert [v['path'] for v in old_files] == [v['path'] for v in new_files]
    changes = []
    for prior,current in zip(old_files,new_files):
        assert set(prior)==set(current)=={'path','bytes','sha256'}
        if prior != current:
            changes.append({'path':prior['path'],'before':prior,'after':current})
    expected_paths = {
        'src/mcp/mod.rs','src/mcp/rea_contract.rs','src/mcp/rea_engine_profile.rs',
        'src/mcp/rea_engine_profile_tests.rs','src/mcp/rea_ghidra_analysis_1214_v4.java',
        'src/mcp/rea_ghidra_contract.rs','src/mcp/rea_ghidra_contract_v4.rs',
        'src/mcp/rea_ghidra_contract_v4_tests.rs','src/mcp/server.rs',
        'tests/rea_ghidra_analysis_external.py'}
    assert {v['path'] for v in changes} == expected_paths
    assert new['runtime']['source_manifest_sha256'] == '68de289328342e6e81a6adce96e74260f8b669524a36b15d4bac0afaa83ed563'
    assert module.check_mapping(root,inputs,mapping,environment,new) == new
    canonical_digest = module.digest_json(new)
    projected = evidence/'runtime-rea-ledger-projection.json'
    projected.write_bytes((json.dumps(new,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode())
    print(json.dumps({'snapshot_sha256':snapshot_digest,'new_source_manifest_sha256':new['runtime']['source_manifest_sha256'],
                      'canonical_output_sha256':canonical_digest,'serialized_output_sha256':digest(projected),
                      'changed_source_paths':[v['path'] for v in changes]},indent=2),flush=True)
    unit_argv = ['/usr/bin/python3','-B','tests/rea_compatibility_ledger_tests.py','-v']
    print(json.dumps({'unit_test_argv':unit_argv}),flush=True)
    result = subprocess.run(unit_argv,cwd=root,stdout=stream,stderr=subprocess.STDOUT)
    assert result.returncode == 0, ('ledger unit tests failed',result.returncode)
    clean()
    assert before == {path:digest(root/path) for path in paths}
    report = {'schema':'hia-runtime-independent-rea-ledger-projection-v1','source_commit':expected_commit,
              'state':'passed','unit_test_exit_code':result.returncode,'unit_test_argv':unit_argv,
              'input_file_sha256':before,'source_files_unchanged':True,'snapshot_sha256':snapshot_digest,
              'preserved_fields':'all top-level except runtime; all runtime except source_files/source_manifest_sha256',
              'changed_source_rows':changes,'new_source_manifest_sha256':new['runtime']['source_manifest_sha256'],
              'canonical_output_sha256':canonical_digest,'serialized_output_sha256':digest(projected),
              'projected_output_path':str(projected),'log_path':str(log)}
    print('INDEPENDENT_REA_LEDGER_PROJECTION_PASSED',flush=True)
report['log_sha256']=digest(log)
out=evidence/'runtime-rea-ledger-validation.json'
out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'state':'passed','report_path':str(out),'report_sha256':digest(out),
                  'canonical_output_sha256':canonical_digest,'serialized_output_sha256':digest(projected),
                  'new_source_manifest_sha256':new['runtime']['source_manifest_sha256'],'log_sha256':digest(log)}),flush=True)
