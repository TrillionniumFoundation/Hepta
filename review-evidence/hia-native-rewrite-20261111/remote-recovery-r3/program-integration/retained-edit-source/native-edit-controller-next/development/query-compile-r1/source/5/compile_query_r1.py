"""Freeze current query controller and compile with the unchanged real B3 gate."""
from pathlib import Path
from hashlib import sha256
import json,time,traceback
from hepta.hia_agent_assembly import assemble_program,render_assembly
from tools.qualify_hia_selfhost import compile_stage
from generate_hia_edit_query_driver import document

ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent;OUT=ROOT/'development/query-compile-r1';OUT.mkdir(exist_ok=False)
COMPILER=BASE/'native-agent-edit-development/facts-source-and-compile-r1/source/compiler/B3.image.bin'
paths=[ROOT/'tools/generate_hia_edit_query_driver.py',ROOT/'tools/hia_edit_controller_common.py',ROOT/'tools/edit_authoring.py',
    ROOT/'examples/hia_bootstrap/agent_edit_query_driver.hiaasm',COMPILER,Path(__file__),
    BASE/'Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py',BASE/'Hepta-agent-edit-native/tools/generate_hia_selfhost.py',
    BASE/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py',
    BASE/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_services.py',
    BASE/'native-composite-legacy-import-next/tools/generate_hia_legacy_import_driver.py']
frozen={p:p.read_bytes() for p in paths};rows=[]
for i,(p,raw) in enumerate(frozen.items()):
    target=OUT/'source'/str(i)/p.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    rows.append(dict(path=str(p),copy=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest()))
(OUT/'source.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
summary=dict(status='INCOMPLETE',scope='NATIVE_QUERY_COMPILATION_ONLY_NOT_COMPLETE_EDIT_EXECUTION');start=time.monotonic_ns()
try:
    doc=document();raw=render_assembly(doc).encode();assert raw==frozen[paths[3]];checked=assemble_program(raw)
    profile=dict(functions=len(doc['functions']),blocks=sum(len(f['blocks']) for f in doc['functions']),
        max_blocks=max(len(f['blocks']) for f in doc['functions']),ops=sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
        max_block_params=max(len(b['params']) for f in doc['functions'] for b in f['blocks']))
    assert profile['functions']<=128 and profile['blocks']<=1536 and profile['max_blocks']<=256 and profile['ops']<=8192 and profile['max_block_params']<=16
    image,receipt=compile_stage(OUT,'agent-edit-query-driver',COMPILER,raw)
    manifest=dict(schema='hepta.hia.agent-edit-query-driver-native.v1',source_path=rows[3]['copy'],source_sha256=sha256(raw).hexdigest(),
        image_path=str(image),image_sha256=sha256(image.read_bytes()).hexdigest(),compiler_sha256=sha256(frozen[COMPILER]).hexdigest())
    (OUT/'agent-edit-query-driver.manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    summary.update(status='PASS',profile=profile,manifest=manifest,compiler_receipt=receipt)
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));traceback.print_exc();raise
finally:
    summary['source_before_after_equal']=all(p.read_bytes()==v for p,v in frozen.items());summary['elapsed_ns']=time.monotonic_ns()-start
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True),flush=True)
    assert summary['source_before_after_equal']
