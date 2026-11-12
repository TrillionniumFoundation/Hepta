"""Seal completed importer development evidence without rewriting old records."""
from hashlib import sha256
import json
from pathlib import Path
import stat
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT.parent
OLD=WORK/'native-composite-driver-reconstructed'
BASE=WORK/'Hepta-v66-restored'
ARCHIVE=WORK/'hia-legacy-composite-native-import-r3-development.tar.xz'
assert not ARCHIVE.exists()

def facts(path):
    raw=path.read_bytes()
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mode':stat.S_IMODE(path.stat().st_mode)}

def write(name,value):
    path=ROOT/name
    assert not path.exists(),path
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

current=ROOT/'checkpoints/importer-source-r3/source.json'
source=json.loads(current.read_bytes())
for name,record in source['files'].items():
    assert facts(ROOT/name)==record,(name,facts(ROOT/name),record)
original=OLD/'checkpoints/public-native-source-r1/source.json'
for record in json.loads(original.read_bytes())['files']:
    expected={k:record[k] for k in ('bytes','sha256')}
    actual=facts(OLD/record['path'])
    assert {k:actual[k] for k in expected}==expected
    assert actual['mode']==int(record['mode'],8)

reports={}
for name,count,key in [('profile-panel-r2',117,'cases_completed'),('byte-boundaries-r2',5,'cases_completed'),('protocol-r3',33,'cases')]:
    path=ROOT/'development'/name/'summary.json';record=json.loads(path.read_bytes())
    assert record['status']=='PASS' and record[key]==count
    assert record.get('all_source_and_image_pins_unchanged',record.get('all_source_image_pins_unchanged')) is True
    reports[name]={'summary':str(path.relative_to(ROOT)),**facts(path),'cases':count,'wall_ns':record['wall_ns']}
bundlepath=ROOT/'development/build-r3/bundle.json'
bundle=json.loads(bundlepath.read_bytes())
assert bundle['status']=='PASS' and len(bundle['components'])==37
exe=Path(bundle['executable']['path']);exefacts=facts(exe)
assert exefacts['sha256']==bundle['executable']['sha256'] and exefacts['bytes']==bundle['executable']['bytes']

# Include current immutable dependency bytes directly, mapped to their original
# workspace-relative path. Historic baseline remains a separate Git dependency.
external={}
for path in [ROOT/'development/build-r3/source-before.json',ROOT/'development/profile-panel-r2/source-before.json']:
    for name,record in json.loads(path.read_bytes()).items():
        p=Path(name)
        if p.is_relative_to(ROOT):
            continue
        actual=facts(p)
        assert actual['bytes']==record['bytes'] and actual['sha256']==record['sha256'],name
        if p in external:assert external[p]==actual
        external[p]=actual
extras=[original,OLD/'development/publication-bundle-r2/bundle.json']
extras += [OLD/row['path'] for row in json.loads(original.read_bytes())['files']]
extras += [OLD/'development'/name for name in ('mechanical_executor.py','raw_mechanical_executor.py','publication_mechanical_executor.py','pipeline_panel_support.py')]
extras += [BASE/'tests'/name for name in ('test_hia_program_composite.py','test_hia_composite_v6_resources.py','test_hia_core_upgrade.py')]
extras += [BASE/'tools'/name for name in ('generate_hia_selfhost.py','qualify_hia_selfhost.py')]
panel=OLD/'development/complete-profile-panel-r2'
extras.append(panel/'summary.json')
for row in json.loads((panel/'summary.json').read_bytes())['results']:
    extras.append(panel/row['case']/'source-document.json')
for p in extras:
    actual=facts(p)
    if p in external:assert external[p]==actual
    external[p]=actual
dependency_map={str(p):{'archive_path':'dependencies/'+str(p.relative_to(WORK)),**record} for p,record in sorted(external.items())}
write('DEPENDENCY_CUSTODY.json',{'scope':'EXACT_CURRENT_COMPONENT_COMPILER_ORACLE_AND_AUTHORING_DEPENDENCIES','files':dependency_map,
    'baseline_git_commit':'e2f392e5658d3cb2d6867a14b88c6335b5975f96',
    'prior_complete_ordinary_archive':{'sha256':'7b511739276154447217574595291a23557a40582cc556b7be4e5f7c55d224ed','bytes':122722348,
    'git_custody_commit':'9be384e9a01096081730c3012ecad773326a323d'},
    'note':'No full repository copy. Runtime sources, images, receipts and compiler are embedded; the exact baseline Git commit supplies the remaining hosted development/test dependencies.'})
write('FINAL_SOURCE_MANIFEST.json',{'scope':'COMPLETE_EXPLICIT_LEGACY_COMPOSITE_IMPORTER_NATIVE_DEVELOPMENT_R3',
    'production_files':source['files'],'source_manifest':{'path':str(current.relative_to(ROOT)),**facts(current)},
    'ordinary_source_manifest':{'original_path':str(original),**facts(original)},
    'bundle':{'path':str(bundlepath.relative_to(ROOT)),**facts(bundlepath)},
    'executable':{'path':str(exe.relative_to(ROOT)),**exefacts},'components':bundle['components'],
    'packer':bundle['packer'],'compiler_sha256':bundle['compiler_sha256'],'completed_reports':reports,
    'production_activation':False,'whole_stack_closed':False,'cold_qualified':False,
    'new_nested_executor_independent_review_complete':False,'syscall_trace_observed':False})

handoff='''# Complete explicit legacy composite importer: native development r3

## Delivered behavior

The standalone x86-64 ELF reads raw JSON bytes from stdin and executes the complete historical `import_legacy_composite_v2` semantic path. All language decisions run in 37 embedded HIA images. A separately compiled HIA packer emitted the actual ELF from the fixed mechanical syscall template and those exact images. The executable runs with empty PATH and HOME; it does not load Python or an external compiler, interpret a host semantic plan, or launch child processes.

The native sequence preserves the original public raw-byte contract: integer JSON admission; exact four-field legacy envelope; explicit historical schema; schema rename; complete legacy lowering; complete primitive-v1 admission; the renamed-input byte gate; a fresh independent ordinary composite-v1 lowering and primitive-v6 admission; complete canonical payload comparison excluding only the schema digit; then the original report and full structured source. Legacy import remains an explicit operation. It is not selected by ordinary structured input.

Successful stdout is the complete canonical object `{"core":...,"report":...,"structured":...}`. All report hashes and claims match the retained importer. Semantic refusal writes its native 128-byte diagnostic frame and exits 2 without stdout; ABI and I/O failures have separate native exits. Native generic diagnostic codes and order are compared; this does not claim all hosted English context text or private Python object semantics are identical.

## Exact current result

Current production identity is `checkpoints/importer-source-r3/source.json` and the 16 files it lists. `development/build-r3/bundle.json` binds all 37 HIA sources, actual images, receipts, historical B3 compiler and actual packer output. The executable is `development/build-r3/hia-import-legacy-composite`, 7,299,291 bytes, SHA-256 `6ea85c3d4fc14409c40f713836551bc2618b6bda811ca14a0282469a94df9a82`.

All final r3 source and image pins remained unchanged across these completed gates:

| Gate | Result | Recorded elapsed time |
| --- | --- | --- |
| Complete public profile/raw-input panel | 117 / 117 PASS | 30.386812598 s |
| Exact 8 MiB and late-error boundaries | 5 / 5 PASS | 325.586331276 s |
| Actual component protocol controls | 33 / 33 PASS | 0.194115330 s |

The 122 public cases compare the complete returned Core, structured source and report bytes on acceptance, and the first rejection category on refusal. They include 82 previously frozen nominal fixtures explicitly relabelled as the historical schema, supported/unsupported resource profiles, schema/key precedence, malformed JSON/UTF-8/surrogates, depth and byte limits. Newer structured features are not silently granted to the old profile.

The five decisive byte cases use valid declarations within all original language limits. Original canonical input of 8,388,606 bytes becomes exactly 8,388,608 after the rename and succeeds, returning 8,389,875 complete bytes. Inputs of 8,388,607 and 8,388,608 bytes reach the renamed-input error only after the full legacy Core gate. An old lowering error and an old primitive type error each precede that late byte error, as in the retained implementation. The successful response is hashed in complete <=8 MiB SHA updates; no output bytes are omitted or truncated.

Protocol evidence covers actual issued-source projection, complete Core comparison, malformed initialization and ACK correlation, replay and permanent refusal. Short advertised workspaces cannot persist poison and are explicitly a fixed-executor lease-discard responsibility. Private same-pipeline source leases are not external authentication. Fixed-executor syscall failure injection has not been observed.

## Preserved original failures and revisions

`development/build-r1` contains the original actual B3 rejection of a direct two-readbuf entry. The correction uses the established RWW entry with explicit borrow/read and loan.end, without changing the compiler limits. `development/build-r2` and the complete r2 smoke/public results remain intact.

`development/byte-boundaries-r1` preserves the first actual large-input failure: both semantic paths completed, but the r2 importer sent the entire >8 MiB response as one update to the existing bounded SHA kernel. This produced ABI exit 3, not a language refusal or timeout. R3 changes only the importer continuation to hash all bytes in bounded updates; the original SHA kernel, language and compiler limits are unchanged. The full five-case boundary gate and complete 117-case panel were then rerun under new identities on the actual r3 ELF.

`development/protocol-r1` preserves the development harness bytearray/ctypes TypeError after ten passing controls. R2 converted only that test input to immutable bytes; r3 reran all 33 controls against current production. No failed original is overwritten or relabelled as passed.

## Ownership and current limits

The additional RUN_CHILD operation is a fixed same-process context switch selected by HIA. Each child has independent controller, type state, temporary buffers, spool and counters; only the selected immutable source lease is borrowed. On completion, only the successful actual readonly Core mapping is transferred back. Other child mappings and descriptors are released. No fork, exec, schema selection or language lowering occurs in the template. Independent review of this new nested executor and external syscall tracing remain outstanding; prior ordinary-executor review does not automatically cover this extension.

This is an independent development candidate. It is not installed as the default route, is not matching-current cold/full qualification, and does not close whole-stack or source-authoring self-hosting. Python generators, assembly authoring, hosted oracles and existing semantic owners remain available. The historical B3 compiler is byte-bound development provenance, not a new qualification claim. The unchanged B3 compile limits are 10 CPU seconds, 20 wall seconds, 256 MiB address space, 8 MiB stack and the original 1 MiB compiler capacities. Native public case timeout is 180 seconds in these importer panels; no retained, cold or language deadline changed.

## Recovery

The archive preserves this entire overlay, including all source revisions, actual compiler/packer inputs and receipts, emitted executables, original failures, complete raw cases and final success logs. Current immutable external sources, images, compiler, receipts, hosted oracle sources and the frozen 82-document corpus are mapped by `DEPENDENCY_CUSTODY.json` under `dependencies/`. The exact restored baseline commit is `e2f392e5658d3cb2d6867a14b88c6335b5975f96`; the prior full ordinary-driver archive is already held by recovery commit `9be384e9a01096081730c3012ecad773326a323d`.

Every archive member is read back and compared to its original bytes, SHA-256 and mode. No old archive, live peer source or shared branch is modified by sealing.
'''
assert not (ROOT/'FINAL_HANDOFF.md').exists()
(ROOT/'FINAL_HANDOFF.md').write_text(handoff)

members={}
for p in sorted(ROOT.rglob('*')):
    if '__pycache__' in p.parts or p.suffix=='.pyc':continue
    assert not p.is_symlink(),p
    members['importer/'+str(p.relative_to(ROOT))]=p
members['importer']=ROOT
for p,row in external.items():members[dependency_map[str(p)]['archive_path']]=p
# Explicit parent directories retain observed original directory modes.
for archive_name,p in list(members.items()):
    parent_name=Path(archive_name).parent;parent=p.parent
    while str(parent_name) not in ('.',''):
        name=str(parent_name)
        if name not in members:members[name]=parent
        parent_name=parent_name.parent;parent=parent.parent

ledger=[]
for name,p in sorted(members.items()):
    row={'path':name,'original_path':str(p),'kind':'directory' if p.is_dir() else 'file','mode':stat.S_IMODE(p.stat().st_mode)}
    if p.is_file():row.update(facts(p))
    ledger.append(row)
started=time.monotonic_ns()
with tarfile.open(ARCHIVE,'w:xz',preset=6) as tar:
    for row in ledger:tar.add(row['original_path'],arcname=row['path'],recursive=False)
with tarfile.open(ARCHIVE,'r:xz') as tar:
    actual=tar.getmembers();assert len(actual)==len(ledger)
    for member,row in zip(actual,ledger):
        assert member.name==row['path'] and member.mode==row['mode']
        p=Path(row['original_path'])
        if row['kind']=='directory':assert member.isdir() and p.is_dir()
        else:
            assert member.isfile() and member.size==row['bytes']
            raw=tar.extractfile(member).read()
            assert raw==p.read_bytes() and sha256(raw).hexdigest()==row['sha256']
            assert facts(p)=={k:row[k] for k in ('bytes','sha256','mode')}
ledgerpath=WORK/'hia-legacy-composite-native-import-r3-development.members.json'
custodypath=WORK/'hia-legacy-composite-native-import-r3-development.custody.json'
assert not ledgerpath.exists() and not custodypath.exists()
ledgerpath.write_text(json.dumps({'scope':'FULL_ARCHIVE_MEMBER_READBACK','members':ledger},indent=2,sort_keys=True)+'\n')
custody={'scope':'COMPLETE_EXPLICIT_IMPORTER_NATIVE_DEVELOPMENT_R3_CUSTODY','archive':str(ARCHIVE),**facts(ARCHIVE),
    'members':len(ledger),'file_members':sum(r['kind']=='file' for r in ledger),'raw_file_bytes':sum(r.get('bytes',0) for r in ledger),
    'member_manifest':{'path':str(ledgerpath),**facts(ledgerpath)},'readback_all_original_bytes_sha256_mode':True,
    'source_manifest':facts(current),'completed_reports':reports,'whole_stack_closed':False,'production_activation':False,
    'wall_ns':time.monotonic_ns()-started}
custodypath.write_text(json.dumps(custody,indent=2,sort_keys=True)+'\n')
print(json.dumps(custody,sort_keys=True),flush=True)
