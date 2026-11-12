from pathlib import Path
import ast
import hashlib
import json

ROOT = Path('/workspace/scratch/dda74a4fae35')
WORK = ROOT / 'v76-unified-integration-r1'
SOURCE = WORK / 'source'
HARNESS = ROOT / 'v76-source-generation-r1'
PACKET = ROOT / 'v76-context-identity-r7/qualifier-addendum-r1/context-qualifier-addendum.json'
raw = PACKET.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '7ba4932910eb913d8aa3b60e0dc76326bf8302f00f641549b7d824cde07ad8c8'
packet = json.loads(raw)
assert packet['base_commit'] == '5f7f95367e8e395863801487e969d286b9091110'
assert packet['base_owner_source_blob'] == '82dc963a8147dfddb2df620a5f6ecccb8bc18af5'
assert packet['frozen14_modified'] is False
assert packet['original48_executed'] is False
assert packet['original52_reexecuted'] is False
assert packet['source_control_methods'] == 10

def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())

def inventory():
    return {p.relative_to(SOURCE).as_posix(): identity(p.read_bytes())
            for p in SOURCE.rglob('*') if p.is_file()}

before = inventory()
assert len(before) == 3151
assert not (SOURCE / '.git').exists()
for name, row in packet['original48_files'].items():
    actual = identity((SOURCE / name).read_bytes())
    assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], name

for name, row in packet['owned_files'].items():
    target = SOURCE / name
    assert not target.exists(), name
    content = row['utf8'].encode('utf-8')
    assert identity(content) == dict(bytes=row['bytes'], sha256=row['sha256'], git_blob=row['git_blob_sha'])
    ast.parse(content.decode('utf-8'), filename=name)
    target.write_bytes(content)
    target.chmod(0o644)

def append_tuple(path, variable, additions):
    old = path.read_text()
    tree = ast.parse(old)
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == variable for t in n.targets))
    assert isinstance(node.value, ast.Tuple)
    existing = [n.value for n in node.value.elts if isinstance(n, ast.Constant)]
    missing = [name for name in additions if name not in existing]
    lines = old.splitlines(keepends=True)
    offset = sum(map(len, lines[:node.value.end_lineno - 1])) + node.value.end_col_offset - 1
    assert old[offset] == ')'
    new = old[:offset] + ''.join('    ' + repr(name) + ',\n' for name in missing) + old[offset:]
    updated = ast.parse(new)
    newer = next(n for n in updated.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == variable for t in n.targets))
    assert len(newer.value.elts) == len(node.value.elts) + len(missing)
    newer.value = node.value
    assert ast.dump(updated) == ast.dump(tree)
    path.write_text(new)
    return missing

source_additions = append_tuple(SOURCE / 'tools/hia_selfhost_contract.py',
                               'SOURCE_FILES', packet['source_contract_additions'])
assert set(source_additions) == {'tools/qualify_hia_service_context.py',
                               'tests/test_hia_service_context_qualifier.py',
                               'tests/test_hia_agent_native_campaign.py'}
builder_additions = append_tuple(SOURCE / 'tools/build_hia_service_context.py',
                                'REQUIRED_SOURCE_NAMES', packet['builder_required_additions'])
assert len(builder_additions) == 6

selector = 'tests.test_hia_service_context_qualifier.ServiceContextQualifierSourceTests'
workflow = SOURCE / '.github/workflows/hia-core.yml'
w = workflow.read_text()
anchor = "              'tests.test_hia_service_context_builder.ServiceContextAdapterTests',\n"
assert w.count(anchor) == 1
w = w.replace(anchor, anchor + '              ' + repr(selector) + ',\n')
anchor = '      - name: Preserve actual cold failure and stage evidence\n'
assert w.count(anchor) == 1
w = w.replace(anchor, '''      - name: Native service context through all original Agent callers
        run: |
          python -B -m tools.qualify_hia_service_context \\
            --cold-report "$RUNNER_TEMP/hia-cold.json" \\
            --evidence "$RUNNER_TEMP/hia-service-context-callers"
''' + anchor)
anchor = '            ${{ runner.temp }}/hia-service-context/\n'
assert w.count(anchor) == 1
w = w.replace(anchor, anchor + '            ${{ runner.temp }}/hia-service-context-callers/\n')
workflow.write_text(w)

driver = HARNESS / 'tools/hia_source_integration_v76.py'
mandatory_added = append_tuple(driver, 'MANDATORY_CONTROLS', [selector])
assert mandatory_added == [selector]

after = inventory()
assert len(after) == 3153
changed = {name: row for name, row in after.items() if before.get(name) != row}
assert set(changed) == set(packet['owned_files']) | {
    '.github/workflows/hia-core.yml', 'tools/hia_selfhost_contract.py', 'tools/build_hia_service_context.py'}
for name, row in packet['original48_files'].items():
    assert before[name] == after[name], name
report = {
    'schema': 'hia.v76.context-caller-source-integration.v1',
    'source_packet_blob': '6f3c6c56b571c9336a10f864c23b02e823b0e2e0',
    'source_packet_sha256': identity(raw)['sha256'],
    'source_files': len(after), 'source_contract_additions': source_additions,
    'builder_required_additions': builder_additions, 'source_selector': selector,
    'source_control_methods': 10, 'original48_sources_unchanged': True,
    'component_gate_count_unchanged': 52, 'changed_files': changed,
    'driver_identity': identity(driver.read_bytes()),
    'whole_native_delivery_qualified': False,
}
(WORK / 'CONTEXT-CALLER-INTEGRATION.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
