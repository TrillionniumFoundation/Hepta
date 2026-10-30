#!/usr/bin/env python3
"""Export completed qualification receipts; no compilation or execution."""
from __future__ import annotations

from hashlib import sha256
import gzip
import io
import json
from pathlib import Path
import tarfile

OUT=Path(__file__).resolve().parent


def main():
    setup=json.loads((OUT/'SETUP.json').read_bytes())
    run=json.loads((OUT/'RUN.json').read_bytes())
    source=Path(setup['isolated_checkout'])
    evidence=Path(setup['output_root'])
    reports=OUT/'reports'
    reports.mkdir(exist_ok=True)
    names={'ndu-loop':'RESULT.json','adaptive':'qualification.json','owned-state':'qualification.json',
           'narrowing':'RESULT.json','owned-continuation':'RESULT.json','agent-assembly':'RESULT.json'}
    summary={'schema':'hepta.hia.step21-preflight-summary.v1','head':run['head'],
             'isolated_checkout':str(source),'bound_source_files':len(setup['source_files']),
             'all_six_commands_exit_zero':run['all_six_passed'],'source_unchanged':run['source_unchanged'],
             'recursive_native_source_pin':setup['recursive_identity_observed']['source_commit'],
             'recursive_native_binary_sha256':setup['recursive_binary_sha256'],
             'recursive_identity_sha256':setup['recursive_manifest_sha256'],
             'main_repository_modified':False,'qualification_gate_or_parameters_changed':False,
             'formal_ndu_agent_ring_studies_repeated_or_modified':False,'gates':[]}
    for row in run['gates']:
        raw=(evidence/row['name']/names[row['name']]).read_bytes()
        (reports/(row['name']+'.json')).write_bytes(raw)
        r=json.loads(raw)
        item={'name':row['name'],'returncode':row['returncode'],'command_wall_ns':row['wall_ns'],
              'original_report_sha256':sha256(raw).hexdigest()}
        for key in ('ok','passed','status','controls','source_bindings_unchanged','sources_unchanged','source_unchanged',
                    'tools_unchanged','all_episodes_completed','all_actual_outputs_correct','all_actual_budgets_passed',
                    'performance_qualified','model_completion_requests','agent_advantage_qualified','performance_advantage_established'):
            if key in r:item[key]=r[key]
        for key in ('episodes','native_observations','vm_observations'):
            if key in r:item[key+'_count']=len(r[key])
        summary['gates'].append(item)
    (OUT/'SUMMARY.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    (OUT/'README.md').write_text('''# Isolated step21 preflight on 46d88

All six requested existing CI qualification commands passed once on an independent sparse checkout of `46d88bd18b1b3dadb246e92eb22c49fe44ec2d72`. The 356 selected source files were matched to their exact Git blobs, and checkout HEAD, clean status and every bound file were checked before and after each command. The main repository was not edited.

| Qualification | Exit | Command outer wall | Actual result |
| --- | ---: | ---: | --- |
| NDU loop | 0 | 12.835164116 s | 30 episodes complete; all actual outputs and budgets pass |
| Adaptive | 0 | 1.960142945 s | Native switching, sealing/tamper/active-call/expired-evidence controls pass |
| Owned state | 0 | 0.832185654 s | Live-owner switch, alias/queue replay/cancellation/refusal controls pass |
| Narrowing | 0 | 1.861900357 s | 288 finite native observations; source/tools unchanged; no performance qualification |
| Owned continuation | 0 | 0.828372805 s | Actual cancelled prefix, verified switch, exact single-use suffix and resource release pass |
| Agent assembly | 0 | 2.306951096 s | Exact roundtrip/LLVM, 81 VM and 24 native observations; 0 model requests |

Commands match workflow step21 flags/defaults; only absolute output storage paths and local compiler/build locations differ. The original recursive NDU profile is used: source `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`, Rust 1.90.0, binary SHA-256 `04b6c861af5dd119a566f9cf1d43f5524f0fa148beeccd2e9fee5bb9bcc518b7`. It was extracted from the retained `hia-verified-000ac.zip`; the manifest is unmodified and the actual executable `--identity` response matches it. No finite/stream substitute or relaxed identity check was used.

This is an existing CI qualification replay, not a repeat of the separately frozen e223 NDU/Agent/Ring research. Reported timing here is command execution bookkeeping, not a new performance advantage claim. Agent assembly consists of controls and native checks; its `agent_advantage_qualified` remains false and `model_completion_requests` is zero.

## Preparation failures and isolation

The first whole-history clone failed because the partial source repository lacks unrelated promisor history object `c1dbf715fcda2bdf53984ebad3e0f526887faecb`; its original failure and diagnostic stderr are preserved. The isolated checkout was then initialized independently with read-only access to available Git objects, and all required current-tree blobs were materialized into its own object store from hash-matched source bytes. Sparse-index setup emitted existing-path warnings; no source was overwritten, and clean status plus all 356 blob/file hashes were verified before qualification. No qualification itself was retried.

Host `/dev/shm` holds the isolated checkout and original native artifacts; the default sandbox mounts a separate empty `/dev/shm`. Original outputs are therefore exported here for review. `evidence.tar.gz` contains every qualification output file, including native binaries, selected exact source files, the original recursive manifest/binary, commands, logs and setup records. Every archive member is inventoried and rehashed. No failure or native output is omitted.

`SUMMARY.json` provides scoped results; `RUN.json` holds exact commands and return codes; `reports/` preserves the six primary reports byte-for-byte. The remaining step20 historical-validator restoration belongs to a separate task.
''')
    members={}
    for path in sorted(evidence.rglob('*')):
        if path.is_file():members['qualification/'+path.relative_to(evidence).as_posix()]=path
    for name,entry in setup['source_files'].items():
        path=source/name
        assert sha256(path.read_bytes()).hexdigest()==entry['sha256']
        members['source/'+name]=path
    for name in ('identity.json','hepta-hia-ndu-bridge'):
        members['recursive-build/'+name]=Path(setup['recursive_manifest']).parent/name
    for path in sorted(OUT.rglob('*')):
        if path.is_file() and path.name not in ('evidence.tar.gz','EVIDENCE_MANIFEST.json','EXPORT_VERIFICATION.json','export.log'):
            members['replay/'+path.relative_to(OUT).as_posix()]=path
    inventory=[]
    archive=OUT/'evidence.tar.gz'
    with archive.open('wb') as sink,gzip.GzipFile(fileobj=sink,mode='wb',filename='',mtime=0,compresslevel=9) as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tar:
        for name,path in sorted(members.items()):
            raw=path.read_bytes()
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o644;info.mtime=0
            tar.addfile(info,io.BytesIO(raw))
            inventory.append({'member':name,'original_path':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest()})
    record={'schema':'hepta.hia.step21-evidence-manifest.v1','head':run['head'],
            'archive_bytes':archive.stat().st_size,'archive_sha256':sha256(archive.read_bytes()).hexdigest(),
            'members':inventory,'omitted_qualification_output_files':[],'member_count':len(inventory),
            'scope':'All qualification output files and stable replay metadata; the live export process log is outside the archive.'}
    (OUT/'EVIDENCE_MANIFEST.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    wanted={row['member']:row for row in inventory}
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            raw=tar.extractfile(member).read();entry=wanted.pop(member.name)
            assert len(raw)==entry['bytes'] and sha256(raw).hexdigest()==entry['sha256']
    assert not wanted
    verified={'head':run['head'],'archive_sha256':record['archive_sha256'],'archive_bytes':record['archive_bytes'],
              'all_members_rehashed':True,'member_count':len(inventory),'native_files_retained':True,
              'new_model_or_native_executions_during_export':0}
    (OUT/'EXPORT_VERIFICATION.json').write_text(json.dumps(verified,indent=2,sort_keys=True)+'\n')
    print(json.dumps(verified,sort_keys=True))


if __name__=='__main__':
    main()
