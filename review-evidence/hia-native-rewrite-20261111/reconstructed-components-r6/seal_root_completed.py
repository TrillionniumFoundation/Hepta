"""Preserve completed originals and verify the exact archive and live sources."""
from pathlib import Path
from hashlib import sha256, sha1
import io
import json
import stat
import tarfile

ROOT = Path('/workspace/scratch/9acdfa9f5639')
OUT = ROOT / 'recovery-completed-r6'
EDIT = ROOT / 'native-agent-edit-development'
REPO = ROOT / 'Hepta-agent-edit-native'
rows = {}

def add_file(path, name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    raw = path.read_bytes()
    rows[name] = (path, raw, stat.S_IMODE(path.stat().st_mode))

def add_tree(root, prefix):
    for path in sorted(root.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            add_file(path, prefix + '/' + path.relative_to(root).as_posix())

add_tree(ROOT / 'hia-v67-0ef-github-qualification', 'github-0ef-complete')
for path in sorted(EDIT.iterdir()):
    if path.name.startswith(('query-', 'packet-graph-')):
        if path.is_dir():
            add_tree(path, 'agent-edit/' + path.name)
        else:
            add_file(path, 'agent-edit/' + path.name)
for name in ('facts_harness.py', 'packet_graph_harness.py', 'freeze_vm_compile_query_r2.py',
             'test_query_native_r2.py', 'freeze_vm_compile_packet_graph_r1.py',
             'freeze_vm_compile_packet_graph_r2.py', 'test_packet_graph_wire_r1.py',
             'test_packet_graph_wire_r2.py'):
    add_file(EDIT / name, 'agent-edit/' + name)
for name in ('docs/HIA_AGENT_EDIT_QUERY_NATIVE.md', 'tools/generate_hia_agent_edit_query_packet.py',
             'tools/generate_hia_packet_graph.py', 'tools/hia_agent_edit_source_views.py',
             'examples/hia_bootstrap/agent_edit_query_packet.hiaasm',
             'examples/hia_bootstrap/packet_graph.hiaasm'):
    add_file(REPO / name, 'current-source/' + name)
manifest = dict(
    scope='COMPLETED_GITHUB_0EF_QUALIFICATION_AND_NATIVE_EDIT_QUERY_WIRE_DEVELOPMENT',
    head='0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    github_run=43021706295, github_conclusion='success',
    github_source_tests=331, github_source_seconds=281.363,
    github_native_unittest_groups=17, github_native_tests=791,
    github_cold_seconds=130.389865651, original_limit_seconds=180, oracle_workers=2,
    cold_outer_checks=11, cold_phases=38, cold_nested_checks=5051,
    complete_original_artifact=dict(
        filename='HIA-v67-0ef9541-github-native-20261111.zip', bytes=78179457,
        sha256='4d63d1f748f95c83e24102c3cbe385afedcfcaf3a0eca5b34af5316118389b0f',
        library_file_id='libfile_fde3_f-6846770572cc8191bfd3c234007a008d_2a707b49f4e88191b36ca8a6f555e3a2',
        stored_separately=True, complete_independent_member_readback=True),
    query_complete_cases=99, query_expected_slice_refusals=3,
    query_private_controls=7, bridge_wire_cases=130, bridge_private_controls=8,
    earlier_failed_attempts_retained=True, whole_stack_closed=False,
    full_ROG_job_still_not_claimed_complete=True,
    files=[dict(path=name, bytes=len(raw), sha256=sha256(raw).hexdigest(), mode=mode)
           for name, (path, raw, mode) in sorted(rows.items())])
encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
archive = OUT / 'root-completed-ci-query-and-wire.tar.xz'
with tarfile.open(archive, 'x:xz') as tf:
    for name, (path, raw, mode) in sorted(rows.items()):
        member = tarfile.TarInfo(name)
        member.size, member.mode = len(raw), mode
        tf.addfile(member, io.BytesIO(raw))
    member = tarfile.TarInfo('MANIFEST.json')
    member.size, member.mode = len(encoded), 0o644
    tf.addfile(member, io.BytesIO(encoded))
with tarfile.open(archive, 'r:xz') as tf:
    assert len(tf.getmembers()) == len(rows) + 1
    assert tf.extractfile('MANIFEST.json').read() == encoded
    for name, (path, raw, mode) in rows.items():
        member = tf.getmember(name)
        assert member.isfile() and member.mode == mode and tf.extractfile(member).read() == raw
        assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == mode
raw = archive.read_bytes()
receipt = dict(scope=manifest['scope'], archive=str(archive), bytes=len(raw),
    sha256=sha256(raw).hexdigest(), git_sha=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
    members=len(rows) + 1, original_bytes=sum(len(item[1]) for item in rows.values()),
    all_original_bytes_modes_and_live_readback_equal=True, whole_stack_closed=False)
(OUT / 'root-custody.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True), flush=True)
