"""Copy/archive the closed finite actual and source28 evidence; never execute it."""
from __future__ import annotations
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

HERE=Path(__file__).resolve().parent
PLAN=Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
ACTUAL=Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-actual-r4b')
ROOT=Path('/workspace/scratch/e26ed3e2edcf/root')
PARENT='6e704d8457ebb357fa71e3f0d40fc5064d943da8'
TREE='7dc365bfc650a5c620611f56c56f0a648f0e6cae'
PREFIX='experiments/hia_cli_json_graph_20261112/c-runtime-lifetime-actual-r4b'
sys.path.insert(0,str(PLAN/'control'))
from common import read_file, identity

def wire(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def record(path,name=None):
    raw,p=read_file(path,32<<20)
    return {'path':name if name is not None else path.relative_to(HERE).as_posix(),
            'bytes':len(raw),'sha256':p['sha256'],'git_blob':blob(raw)}
def create(path,raw):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(0o600)
    assert read_file(path,32<<20)[0]==raw
    return record(path)
def paths(root):
    result=[];pending=[root]
    while pending:
        d=pending.pop();assert stat.S_ISDIR(d.lstat().st_mode)
        for p in sorted(d.iterdir()):
            i=p.lstat()
            if stat.S_ISDIR(i.st_mode):pending.append(p)
            else:assert stat.S_ISREG(i.st_mode) and i.st_nlink==1;result.append(p)
    return sorted(result)
def tree_hash(leaves):
    root={}
    for name,r in leaves.items():
        p=name.split('/');node=root
        for part in p[:-1]:node=node.setdefault(part,{})
        assert p[-1] not in node
        node[p[-1]]=(r['mode'],r['sha'])
    def visit(node):
        rows=[]
        for name,v in node.items():
            if isinstance(v,dict):mode,digest,key='40000',visit(v),name.encode()+b'/'
            else:mode,digest=v;key=name.encode()
            rows.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)))
        raw=b''.join(r[1] for r in sorted(rows))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return visit(root)

def main():
    audit=json.loads((HERE/'AUDIT.json').read_bytes())
    assert audit['audit_status']=='READONLY_ACTUAL_AUDIT_PASS' and audit['qualification_status']=='FINITE_C_RUNTIME_LIFETIME_PASS'
    assert audit['actual_regular_count']==114 and audit['HIA_returns']==48 and audit['C_pump_calls_including_refusals']==11
    root_readback=ROOT/'cli-c-runtime-lifetime-invocation-r4b/READBACK.json'
    assert record(root_readback,str(root_readback))['sha256']=='ac59a52e1e3e4e8fc58ab883ab82d658947871298783e11721adf77185baa133'
    source_readback=ROOT/'cli-runtime-layout-source28-r4b-invocation/READBACK.json'
    assert record(source_readback,str(source_readback))['sha256']=='f37ac4a76e7dfbe369bc0a8d28f598ebba9f70593e8520325e60671663c30847'
    groups=[('actual',ACTUAL),('root-review',ROOT/'cli-c-runtime-lifetime-review-r4b'),
            ('root-invocation',ROOT/'cli-c-runtime-lifetime-invocation-r4b'),
            ('source28-actual',Path('/workspace/scratch/e26ed3e2edcf/native-cli-runtime-layout-source-controls-r4b')),
            ('source28-owner',ROOT/'cli-runtime-layout-source28-r4b-owner'),
            ('source28-invocation',ROOT/'cli-runtime-layout-source28-r4b-invocation')]
    source_rows=[]
    for prefix,folder in groups:
        for p in paths(folder):source_rows.append((p,prefix+'/'+p.relative_to(folder).as_posix()))
    for n in ('review_cli_finite_r4b_inputs.py','invoke_cli_finite_r4b_once.py',
              'audit_cli_finite_r4b_actual.py','audit_cli_finite_r4b_actual_reader_r2.py',
              'invoke_cli_source28_r4b_once.py','audit_cli_source28_r4b_actual.py'):
        p=ROOT/n;assert p.is_file();source_rows.append((p,'root-readers/'+n))
    peer=Path('/tmp/hia-v92-standard-ci-readonly-43324913647-r1/cli-peer/ELF-R4B-ADDRESS-ORIGINS-STATIC-REVIEW.json')
    assert record(peer,str(peer))['sha256']=='2074252046c8230e45c86a2882011314fefedefe70d728970a9ad70999ad63a6'
    source_rows.append((peer,'peer-review/ELF-R4B-ADDRESS-ORIGINS-STATIC-REVIEW.json'))
    originals=[]
    for source,relative in sorted(source_rows,key=lambda x:x[1]):
        raw,pin=read_file(source,32<<20)
        copied=create(HERE/'originals'/relative,raw)
        originals.append({**copied,'source':str(source),'source_pin':pin})
    assert sum(r['path'].startswith('originals/actual/') for r in originals)==114
    for r in originals:
        raw,p=read_file(Path(r['source']),32<<20)
        assert p==r['source_pin'] and blob(raw)==r['git_blob']
    originals_record={'schema':'hia.cli-json.r4b-complete-actual-originals.v1',
        'parent_commit':PARENT,'qualification_status':'FINITE_C_RUNTIME_LIFETIME_PASS_ONLY',
        'count':len(originals),'bytes':sum(r['bytes'] for r in originals),'rows':originals,
        'actual114':114,'full_root_review_and_invocation_including_failed_reader_history':True,
        'source28_owner_and_all_originals_included':True,'original_bytes_modified':False,
        'new_product_execution':False}
    op=create(HERE/'ORIGINALS.json',wire(originals_record))
    archive=HERE/'ORIGINALS.tar.gz'
    with archive.open('xb') as dest:
        with gzip.GzipFile(fileobj=dest,filename='',mode='wb',compresslevel=1,mtime=0) as gz:
            with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tf:
                for r in originals:
                    raw=read_file(HERE/r['path'],32<<20)[0]
                    assert len(raw)==r['bytes'] and hashlib.sha256(raw).hexdigest()==r['sha256']
                    info=tarfile.TarInfo(r['path']);info.size=len(raw);info.mode=0o600;info.mtime=0
                    tf.addfile(info,io.BytesIO(raw))
        dest.flush();os.fsync(dest.fileno())
    archive.chmod(0o600)
    with tarfile.open(archive,'r:gz') as tf:
        members=tf.getmembers();assert [m.name for m in members]==[r['path'] for r in originals]
        for m,r in zip(members,originals):
            raw=tf.extractfile(m).read()
            assert m.isreg() and len(raw)==r['bytes'] and hashlib.sha256(raw).hexdigest()==r['sha256']
            assert blob(raw)==r['git_blob'] and raw==read_file(HERE/r['path'],32<<20)[0]
    ap=record(archive)
    arp=create(HERE/'ARCHIVE-READBACK.json',wire({'schema':'hia.cli-json.r4b-archive-readback.v1',
        'archive':ap,'members':len(originals),'uncompressed_original_bytes':originals_record['bytes'],
        'full_member_body_SHA_Git_original_equality':True,'actual_modified':False,'no_product_replay':True}))
    encoded=base64.b64encode(read_file(archive,32<<20)[0])
    transport=[]
    for i,start in enumerate(range(0,len(encoded),524288)):
        raw=encoded[start:start+524288]+b'\n'
        transport.append(create(HERE/'binary-transport'/('ARCHIVE.%03d.base64'%i),raw))
    restored=base64.b64decode(b''.join((HERE/r['path']).read_bytes().strip() for r in transport),validate=True)
    assert restored==read_file(archive,32<<20)[0]
    binary=[]
    for r in originals:
        p=HERE/r['path']
        if p.suffix in ('.bin','.so'):
            binary.append({'original':{k:r[k] for k in ('path','bytes','sha256','git_blob')},'archive_member':r['path']})
    create(HERE/'binary-transport/INDEX.json',wire({'schema':'hia.cli-json.r4b-binary-custody.v1',
        'archive':ap,'ordered_whole_base64_parts':transport,'binary_originals':binary,
        'complete_base64_decode_equal_to_actual_archive':True,'every_member_decoded_equal_to_original':True,
        'raw_binary_tool_readback_not_claimed':True,'publication_pending':True}))
    handoff={'schema':'hia.cli-json.r4b-finite-actual-handoff.v1',
        'status':'COMPLETE_ACTUAL_READONLY_CUSTODY_PENDING_GIT_PUBLICATION','parent_commit':PARENT,
        'parent_tree':TREE,'prefix':PREFIX,'audit':record(HERE/'AUDIT.json'),'originals':op,
        'archive':ap,'archive_readback':arp,'full_originals_count':len(originals),
        'full_original_bytes':originals_record['bytes'],'actual_regular_originals':114,
        'actual_regular_bytes':audit['actual_regular_bytes'],'work_typed_rows':107,'work_regular_bytes':5222543,
        'runtime_expected_loaded_executed_pass':8,'lifetime_expected_loaded_executed_pass':10,
        'actual_HIA_returns':48,'actual_C_pump_calls_including_refusals':11,'raw_leaf_only_cases':2,
        'source28_separate_actual_PASS':True,'source28':audit['source28'],
        'outer':audit['outer'],'inner_owners':audit['inner_owners'],
        'runtime_elapsed_ns':audit['runtime_elapsed_ns'],'lifetime_elapsed_ns':audit['lifetime_elapsed_ns'],
        'worker_elapsed_ns':audit['worker_elapsed_ns'],'launcher_elapsed_ns':audit['launcher_elapsed_ns'],
        'C_image':audit['C_image'],'HIA_image':audit['HIA_image'],'mapped_runtime':audit['runtime_joins'],
        'all4555system_182source_and_external_originals_freshly_rehashed':True,
        'four_input_snapshots_and_root_preexec_equal':True,'eight_saved_trace_runs':audit['trace_runs'],
        'trace_records':78,'negative_trace_overflow_ten_dropped_preserved':True,
        'all_request_state_and_trace_binaries_in_archive':True,
        'read_only_join_count':audit['check_count'],'frozen_helper_readonly_checks':audit['frozen_helper_checks'],
        'root_final_readback':record(root_readback,str(root_readback)),
        'root_source28_readback':record(source_readback,str(source_readback)),
        'root_initial_reader_errors_preserved':True,'prior_r1_r2b_r3_HOLDs_unchanged':True,
        'scope':'Exact r4b finite development request only, CPython3.12.14 with reused actual v89 B3',
        'unexecuted_scopes':audit['unexecuted_scopes'],'original17_CLI_executed':False,
        'original46_traces_executed':False,'full_graph_qualified':False,'body_driver_qualified':False,
        'current_v92_matching_or_fresh_cold':False,'installation_executed':False,'default_changed':False,
        'no_new_test_or_product_execution_by_this_auditor':True,
        'r4f2_WIP_separate_and_not_part_of_this_actual':True}
    create(HERE/'HANDOFF.json',wire(handoff))
    publication=HERE/'publication';publication.mkdir(mode=0o700)
    base=json.loads((PLAN/'publication/FULL-TREE.provider.json').read_bytes())
    assert base['sha']==TREE and not base['truncated']
    leaves={r['path']:{'mode':r['mode'],'sha':r['sha']} for r in base['tree'] if r['type']=='blob'}
    assert len(leaves)==6719 and tree_hash(leaves)==TREE
    old={r['sha'] for r in leaves.values()}; additions=[]
    for p in paths(HERE):
        if publication in p.parents:continue
        row=record(p);raw=read_file(p,32<<20)[0]
        if p.suffix in ('.bin','.so') or p.name.endswith('.tar.gz'):encoding='base64'
        else:
            try:raw.decode('utf-8');encoding='utf-8'
            except UnicodeDecodeError:encoding='base64'
        row.update(absolute=str(p),repository_path=PREFIX+'/'+row['path'],git_mode='100644',encoding=encoding)
        assert row['repository_path'] not in leaves
        leaves[row['repository_path']]={'mode':'100644','sha':row['git_blob']};additions.append(row)
    unique={}
    for r in additions:
        if r['git_blob'] not in old:unique.setdefault(r['git_blob'],r)
    plan={'schema':'hia.cli-json.r4b-actual-publication-plan.v1','parent_commit':PARENT,'parent_tree':TREE,
        'prefix':PREFIX,'parent_leaves':6719,'new_leaves':len(additions),'full_leaves':len(leaves),
        'expected_tree':tree_hash(leaves),'all_additions':additions,'new_blobs':list(unique.values()),
        'tree_elements':[{'path':r['repository_path'],'mode':'100644','type':'blob','sha':r['git_blob']} for r in additions]}
    create(publication/'PLAN.json',wire(plan))
    print(json.dumps({'originals':len(originals),'original_bytes':originals_record['bytes'],'archive':ap,
        'new_leaves':len(additions),'full_leaves':len(leaves),'new_unique_blobs':len(unique),
        'new_unique_bytes':sum(r['bytes'] for r in unique.values()),'expected_tree':plan['expected_tree'],
        'handoff':record(HERE/'HANDOFF.json')}))

if __name__=='__main__':main()
