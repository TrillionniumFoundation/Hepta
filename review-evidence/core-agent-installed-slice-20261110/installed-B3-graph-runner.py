"""Current cold B3 graph/filter and real installed query, not whole Agent native."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys
B=Path(__file__).resolve().parents[1];R=B/'agent-core-slice-development';T=Path('/var/tmp/hia-ci4');sys.path.insert(0,str(R))
from tests.test_hia_agent_entry import CHILD,fixture
from tests.test_hia_agent_slice_native import independent_cases
from hepta.hia_edit_query import prepare_edit
from tools.build_hia_agent_slice import build
cold=T/'core-installed-cold.json';d=json.loads(cold.read_bytes());assert d['status']=='COLD_SELFHOST_REPLAY_PASS' and all(d['checks'].values())
nested=json.loads(Path(d['nested_report']).read_bytes());compiler=Path(nested['generations'][-1]['produced_image'])
application=T/'current-B3-native-agent-slice';manifest=build(application,compiler,cold);m=json.loads(manifest.read_bytes())
installed=T/'installed';artifact=T/'installed-native-graph';artifact.mkdir(mode=0o700)
for n in (m['image_path'],'manifest.json','hia-agent-slice'):shutil.copyfile(application/n,artifact/n)
(artifact/'hia-agent-slice').chmod(0o700)
assert sha256((artifact/m['image_path']).read_bytes()).hexdigest()==m['image_sha256']
rows=[]
for i,(wire,expected) in enumerate(independent_cases()):
 p=subprocess.run([str(artifact/'hia-agent-slice')],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,cwd=artifact,env={'PATH':'','LANG':'C'})
 (T/f'installed-current-B3-filter-{i}.stdout.bin').write_bytes(p.stdout);(T/f'installed-current-B3-filter-{i}.stderr.bin').write_bytes(p.stderr)
 assert (p.returncode,p.stdout,p.stderr)==(0,expected,b''),p
 rows.append(dict(case=i,returncode=p.returncode,output_sha256=sha256(p.stdout).hexdigest()))
expected=prepare_edit(fixture(),function='calculate',block='entry',output='y',fields=['op'])
script='import sys\nsys.path.insert(0,sys.argv[1])\n'+CHILD.split('from hepta.cli import')[0]+'''
import json
from pathlib import Path
from hepta.hia_agent_slice_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
assert not any('agent-core-slice-development' in n for n in sys.path)
from hepta import hia_edit_query as query
def absent(*a,**kw):raise AssertionError('host graph slicing used in installed native query')
query._reference_edit_slice=absent
query._cfg_downstream_slice=absent
result=query.prepare_edit(json.loads(sys.stdin.buffer.read()),function='calculate',block='entry',output='y',fields=['op'])
assert not blocked.intersection(sys.modules)
print(json.dumps(result))
'''
env={'PATH':'','LANG':'C','HEPTA_HIA_AGENT_SLICE_MANIFEST':str(artifact/'manifest.json')}
payload=json.dumps(fixture()).encode()
p=subprocess.run([sys.executable,'-I','-S','-B','-c',script,str(installed)],input=payload,capture_output=True,timeout=15,cwd=artifact,env=env)
(T/'installed-current-B3-graph-query.stdout.json').write_bytes(p.stdout);(T/'installed-current-B3-graph-query.stderr.bin').write_bytes(p.stderr)
assert p.returncode==0 and not p.stderr and json.loads(p.stdout)==expected,(p.returncode,p.stderr)
# Selected manifest or installed source failures never invoke the host graph algorithm.
source=installed/'hepta/_data/examples/hia_bootstrap/agent_slice.hiaasm';original=source.read_bytes()
source.write_bytes(original+b'\n')
try:
 rejected=subprocess.run([sys.executable,'-I','-S','-B','-c',script,str(installed)],input=payload,capture_output=True,timeout=15,cwd=artifact,env=env)
 assert rejected.returncode!=0 and not rejected.stdout and b'source identity mismatch' in rejected.stderr
finally:source.write_bytes(original)
report=dict(status='PASS',source_commit='e2fd1c582d7967fb24dab55e6b1c2a2a835929a8',actual_completed_cold_B3_sha256=sha256(compiler.read_bytes()).hexdigest(),native_graph_image_sha256=m['image_sha256'],native_filter_sha256=sha256((artifact/'hia-agent-slice').read_bytes()).hexdigest(),standalone_native_filters=rows,installed_empty_PATH_isolated_graph_query=True,source_checkout_absent=True,host_graph_algorithms_disabled=True,whole_query_matches_reference=True,tampered_source_selected_route_refuses_without_fallback=True,whole_agent_native=False,host_admission_wire_and_persistence_retained=True)
(T/'current-B3-installed-agent-slice.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report))
