"""Read exact follow25 complete hia_read originals without executing images.

Whole ZIP, inner archive, inventory, original modes, every completed entry and
all referenced compressed CAS are independently verified. The old storage text
mismatch and wire SIGKILL remain FAIL/OPEN. No new quota or native test is added.
"""
from __future__ import annotations
import argparse,base64,collections,io,json,os,stat,tarfile,traceback,zipfile,zlib
from hashlib import sha256
from pathlib import Path,PurePosixPath
ZIP_BYTES=65270962
ZIP_SHA='93bf932de85332c8b1c67ce14fbe7e5268dc9846d207f8e90044ea2e797946a1'
INNER_BYTES=10717668
INNER_SHA='f73691dda6c34f337f391ac9a2c2e5bc119ec1dc061f8a9581e593d4a494c513'
INDEX_BYTES=4607230
INDEX_SHA='e4eef36fdcce3e6cbc816bf0e18db438a331847919b570f7945b0017f02e251f'
EXPECTED_MEMBERS=9965
EXPECTED_RAW_BYTES=101822617
HEAD='df7f8cfab21687c32de6366724e955335b068ec4'
SCOPE='worker-complete-hia-read-business-development-r1'
COMPILER='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
SOURCE={
  "agent_read_flow": "fe0b3e044138e4eaeccb70e0b4835460dbae6e663673fdf95a63b1265e479785",
  "agent_read_values": "5069cb714ac9f1cff654e67fd074c556c0f2a3d1b7e67b14dab6b6d394ea799c",
  "emit": "9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2",
  "scan": "c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3",
  "sha256_stream": "7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68"
}
IMAGE={
  "agent_read_flow": "1a44a1b650be4a4416b900cf9298937b8cf31a058dd2a6f3deedc10404a644db",
  "agent_read_values": "0b9438fcda3660c76904a0cb5a3210edae4d079975a76e841e6c5299992c298d",
  "emit": "9b69271adb5c3024842fc065e294b9a3550077801b76e43046c4eb09e3925a80",
  "scan": "3545a6c60334b5f7e92eda8df582472a2a493c74b814e5ac9158cdd2e866b026",
  "sha256_stream": "e9b0c18a52518af8d9e9909451d8174a02b7d6adc2910f8ca68d1b284a7093cb"
}
def digest(raw):return sha256(raw).hexdigest()
def hashed(stream,output=None):
    h=sha256();n=0
    while True:
        chunk=stream.read(1<<20)
        if not chunk:break
        h.update(chunk);n+=len(chunk)
        if output is not None:output.write(chunk)
    return n,h.hexdigest()
def safe_name(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and '..' not in p.parts and str(p)==name
    return name
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def emit(name,raw):
    print(json.dumps(dict(event='WORKER_READ25_ORIGINAL',name=name,bytes=len(raw),
        sha256=digest(raw),base64=base64.b64encode(raw).decode()),sort_keys=True),flush=True)
def cas_identity(raw,expected):
    decoder=zlib.decompressobj();h=sha256();total=0
    for start in range(0,len(raw),1<<20):
        chunk=raw[start:start+(1<<20)]
        while chunk:
            out=decoder.decompress(chunk,1<<20)
            h.update(out);total+=len(out)
            chunk=decoder.unconsumed_tail
    while True:
        out=decoder.decompress(b'',1<<20)
        if not out:break
        h.update(out);total+=len(out)
    out=decoder.flush();h.update(out);total+=len(out)
    assert decoder.eof and not decoder.unused_data and h.hexdigest()==expected
    return total
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--zip',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    result=dict(scope='READ_ONLY_EXACT_WORKER_READ_FOLLOW25_ORIGINALS',status='FAIL',
        original_head=HEAD,run_id=43148645083,job_id=130952352570,artifact_id=13913401010,
        native_entries_executed=0,qualification_repeated=False,whole_worker_closed=False)
    try:
        with a.zip.open('rb') as stream:assert hashed(stream)==(ZIP_BYTES,ZIP_SHA)
        checked_zip=[];zip_saved={}
        with zipfile.ZipFile(a.zip) as z:
            infos=z.infolist()
            names=[i.filename for i in infos];assert len(names)==len(set(names))
            for info in infos:
                if info.is_dir():continue
                name=safe_name(info.filename)
                assert not stat.S_ISLNK(info.external_attr>>16)
                with z.open(info) as stream:size,h=hashed(stream)
                assert size==info.file_size
                checked_zip.append(dict(name=name,bytes=size,sha256=h,crc32=info.CRC))
            for suffix in ('/evidence.tar.xz','/evidence-members.json','/custody.json'):
                options=[i for i in infos if i.filename.endswith(suffix) and not i.is_dir()]
                assert len(options)==1,(suffix,[i.filename for i in options])
                item=options[0];target=out/item.filename.rsplit('/',1)[-1]
                with z.open(item) as stream,target.open('xb') as dest:row=hashed(stream,dest)
                zip_saved[suffix]=(target,row)
        assert zip_saved['/evidence.tar.xz'][1]==(INNER_BYTES,INNER_SHA)
        assert zip_saved['/evidence-members.json'][1]==(INDEX_BYTES,INDEX_SHA)
        custody=json.loads(zip_saved['/custody.json'][0].read_bytes())
        assert custody['scope']==SCOPE and custody['status']=='FAIL'
        assert (custody['bytes'],custody['sha256'],custody['members'],
                custody['original_bytes'])==(INNER_BYTES,INNER_SHA,EXPECTED_MEMBERS,EXPECTED_RAW_BYTES)
        rows=json.loads(zip_saved['/evidence-members.json'][0].read_bytes())
        assert len(rows)==EXPECTED_MEMBERS and sum(r['bytes'] for r in rows)==EXPECTED_RAW_BYTES
        expected={safe_name(r['name']):r for r in rows};assert len(expected)==len(rows)
        by_path=collections.defaultdict(list)
        for row in rows:by_path[row['path']].append(row)
        held={};cas={};cas_stored={};incomplete_cas={};partial_ledgers={};seen=set();inner=[]
        def selected(name):
            return (name.startswith(('run/steps/worker-read-wire/','run/steps/worker-read-storage/'))
                or name in ('run/summary.json','run/identity.json','run/steps.json')
                or name.startswith('run/read-compile/') and name.endswith(('.json','.harness.py'))
                or '/actual-' in name and name.endswith(('.json','.jsonl')))
        with tarfile.open(zip_saved['/evidence.tar.xz'][0],'r|xz') as tf:
            for item in tf:
                assert item.isfile() and item.name not in seen and item.name in expected
                row=expected[item.name];raw=tf.extractfile(item).read()
                assert (len(raw),digest(raw),item.mode)==(row['bytes'],row['sha256'],row['mode'])
                seen.add(item.name);inner.append(dict(name=item.name,bytes=len(raw),sha256=digest(raw),mode=item.mode))
                filename=item.name.rsplit('/',1)[-1]
                if '/cas/' in item.name and filename.endswith('.zlib'):
                    identity=filename[:-5]
                    assert len(identity)==64 and all(x in '0123456789abcdef' for x in identity)
                    try:
                        cas[item.name]=dict(bytes=cas_identity(raw,identity),sha256=identity)
                        cas_stored[item.name]=raw
                    except (AssertionError,zlib.error) as exc:
                        # A killed original writer may leave an unreferenced
                        # partial CAS object. Its archived bytes remain exact.
                        incomplete_cas[item.name]=dict(stored_bytes=len(raw),
                            stored_sha256=digest(raw),error_class=type(exc).__name__,
                            error=str(exc))
                if selected(item.name):
                    held[item.name]=raw
                    target=out/'selected'/item.name
                    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        assert seen==set(expected)
        save(out/'zip-members-verified.json',checked_zip)
        save(out/'inner-members-verified.json',inner)
        save(out/'cas-uncompressed-verified.json',cas)
        save(out/'uncompleted-cas-originals.json',incomplete_cas)
        # These are exact archived originals, already protected by the complete
        # ZIP, inner archive and per-member checks. Print them before interpreting
        # optional producer ledger fields, so a reader bug cannot hide the frontier.
        for name in sorted(held):
            if (name.startswith(('run/steps/worker-read-wire/','run/steps/worker-read-storage/'))
                    or name.endswith(('/actual-wire-r1/pending-native-entry.json','/actual-storage-r1/pending-native-entry.json'))
                    or name.endswith(('/actual-wire-r1/cases.jsonl','/actual-storage-r1/cases.jsonl'))):
                emit(name,held[name])

        assert any((row['bytes'],row['sha256'])==(28670,
            '0989d6431729dc6a23f4faf84035096f217edb929f182a691836317d4c6ae27e')
            for row in rows),'exact original ledger writer was not archived'
        complete_entries={};entry_counts={};case_counts={}
        def completed_lines(name,raw):
            lines=raw.splitlines(keepends=True)
            if lines and not lines[-1].endswith(b'\n'):
                tail=lines.pop()
                partial_ledgers[name]=dict(bytes=len(tail),sha256=digest(tail),
                    base64=base64.b64encode(tail).decode())
            return [json.loads(line) for line in lines if line.strip()]
        def ref_check(root,ref):
            path=root+'/cas/'+ref['sha256']+'.zlib'
            assert path in cas and cas[path]==dict(bytes=ref['bytes'],sha256=ref['sha256'])
            return path
        def ref_tree(root,value):
            if isinstance(value,dict):
                if set(value)=={'bytes','sha256'}:
                    ref_check(root,value)
                else:
                    for child in value.values():ref_tree(root,child)
            elif isinstance(value,list):
                for child in value:ref_tree(root,child)
        for name,raw in held.items():
            if not name.endswith('/entries.jsonl'):continue
            records=completed_lines(name,raw);root=name.rsplit('/',1)[0]
            counts=collections.Counter()
            for record in records:
                counts[record['role']]+=1
                assert record['input_and_canaries_unchanged'] is True
                assert record['role'] in SOURCE
                for key in ('source','second_before','second_after','workspace_before','workspace_after'):
                    ref_check(root,record[key])
            complete_entries[root]=records;entry_counts[root]=dict(counts)
        for name,raw in held.items():
            if not name.endswith('/cases.jsonl'):continue
            root=name.rsplit('/',1)[0];records=completed_lines(name,raw)
            for ordinal,record in enumerate(records,1):
                assert record['case']==ordinal and record['status']=='PASS'
                if record.get('private_protocol') is not True:
                    assert record['all_values_errors_wire_calls_and_sql_binds_equal'] is True
                    expected_value=ref_check(root,record['expected'])
                    actual_value=ref_check(root,record['actual'])
                    assert zlib.decompress(cas_stored[expected_value])==zlib.decompress(cas_stored[actual_value])
                ref_tree(root,record)
            case_counts[root]=records
        bundle=json.loads(held['run/read-compile/bundle.json'])
        assert bundle['status']=='PASS' and set(bundle['components'])==set(SOURCE)
        # The pinned compile writer stores every admitted source/image byte
        # string in frozen-inputs/<source-after ordinal>/<basename>. External
        # reference/GraphWire source paths are deliberately not separate roots
        # of common.finish; their exact frozen copies are the authoritative
        # archived bindings. Do not replace this with a hash-only file search.
        compile_after_name='run/read-compile/source-after.json'
        compile_after=json.loads(held[compile_after_name])
        compile_paths=[r['path'] for r in compile_after]
        assert len(compile_paths)==len(set(compile_paths))
        frozen_bindings={}
        for ordinal,pinned in enumerate(compile_after):
            original_path=pinned['path']
            assert PurePosixPath(original_path).is_absolute()
            frozen_name='run/read-compile/frozen-inputs/'+str(ordinal)+'/'+PurePosixPath(original_path).name
            archived=expected[frozen_name]
            assert (archived['bytes'],archived['sha256'],archived['mode'])==(
                pinned['bytes'],pinned['sha256'],pinned['mode'])
            direct=by_path.get(original_path,[])
            assert all((r['bytes'],r['sha256'],r['mode'])==
                (pinned['bytes'],pinned['sha256'],pinned['mode']) for r in direct)
            frozen_bindings[original_path]=dict(original_pin=pinned,
                frozen_member=frozen_name,direct_members=[r['name'] for r in direct])
        save(out/'compile-admitted-frozen-bindings.json',frozen_bindings)
        emit('run/read-compile/bundle.json',held['run/read-compile/bundle.json'])
        emit('derived/compile-admitted-frozen-bindings.json',
            (json.dumps(frozen_bindings,sort_keys=True,indent=2)+'\n').encode())
        for role,row in bundle['components'].items():
            assert row['source_sha256']==SOURCE[role] and row['image_sha256']==IMAGE[role]
            assert row['compiler_sha256']==COMPILER
            for part in ('source','image'):
                binding=frozen_bindings[row[part+'_path']]
                pinned=binding['original_pin']
                assert (pinned['bytes'],pinned['sha256'])==(
                    row[part+'_bytes'],row[part+'_sha256']),(role,part,binding,row)
            receipt_rows=by_path[row['receipt_path']];assert len(receipt_rows)==1
            receipt=json.loads(held[receipt_rows[0]['name']])
            assert receipt['image_sha256']==COMPILER
            assert receipt['input_sha256']==SOURCE[role] and receipt['produced_sha256']==IMAGE[role]
        wire='read/development/actual-wire-r1'
        pending_name=wire+'/pending-native-entry.json'
        assert pending_name in held and wire in complete_entries
        pending=json.loads(held[pending_name])
        process_name='run/steps/worker-read-wire/process.json'
        process=json.loads(held[process_name])
        stdout=held['run/steps/worker-read-wire/stdout.log']
        stderr=held['run/steps/worker-read-wire/stderr.log']
        assert (len(stdout),digest(stdout))==(process['stdout_bytes'],process['stdout_sha256'])
        assert (len(stderr),digest(stderr))==(process['stderr_bytes'],process['stderr_sha256'])
        assert process['returncode']==-9 and process['timed_out'] is False
        assert (len(stdout),digest(stdout))==(5056,
            '0ee5ef4d9b573bc5fe6dc8da6dda6086352928bb83259b44847f1e4b8902f097')
        lines=[json.loads(l) for l in stdout.splitlines() if l.strip()]
        starts=[r for r in lines if r.get('event')=='READ_CASE_START']
        passes=[r for r in lines if r.get('event')=='READ_CASE_PASS']
        assert all(r['group']=='wire' for r in starts+passes)
        assert [r['ordinal'] for r in passes]==list(range(1,len(passes)+1))
        wire_cases=case_counts.get(wire,[])
        assert len(passes)==len(wire_cases)
        assert [r['label'] for r in passes]==[r['label'] for r in wire_cases]
        assert len(starts) in (len(passes),len(passes)+1)
        for prior,complete in zip(starts,passes):
            assert prior['label']==complete['label'] and prior['ordinal']==complete['ordinal']
        pending_counts=entry_counts[wire]
        completed_native_ordinal=pending_counts.get(pending['role'],0)
        state=('actual_entry_not_completed' if pending['role_entry']==completed_native_ordinal+1
               else 'last_recorded_entry_completed_but_later_phase_unknown')
        assert pending['role_entry'] in (completed_native_ordinal,completed_native_ordinal+1)
        selected_buffers=[]
        def preserve_buffer(role,label,identity,size):
            path=wire+'/cas/'+identity+'.zlib'
            if path not in cas:return False
            assert cas[path]==dict(bytes=size,sha256=identity)
            raw=zlib.decompress(cas_stored[path])
            assert len(raw)==size and digest(raw)==identity
            target=out/'selected-buffers'/(label+'.bin')
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            prefix=raw[:8192]
            emit('derived/'+label+'.prefix-8192.bin',prefix)
            selected_buffers.append(dict(role=role,label=label,original_bytes=size,
                original_sha256=identity,prefix_bytes=len(prefix),prefix_sha256=digest(prefix),
                saved_path=str(target),full_original_verified=True))
            return True
        for field,prefix in (('source','source'),('second','second'),('workspace_before','workspace')):
            pending[field+'_already_in_verified_cas']=preserve_buffer(pending['role'],
                'pending-'+field,pending[field+'_sha256'],pending[prefix+'_bytes'])
        last=complete_entries[wire][-1] if complete_entries[wire] else None
        if last:
            for field in ('source','second_before','second_after','workspace_before','workspace_after'):
                ref=last[field];assert preserve_buffer(last['role'],'last-completed-'+field,ref['sha256'],ref['bytes'])
        assert wire+'/summary.json' not in held
        original=json.loads(held['run/summary.json'])
        assert original['status']=='FAIL' and original['scope']==SCOPE
        storage='read/development/actual-storage-r1'
        storage_summary=json.loads(held[storage+'/summary.json'])
        assert storage_summary['status']=='FAIL' and storage_summary['cases']==9
        assert storage_summary['failure']['error_class']=='AssertionError'
        result.update(status='PASS_READBACK_ONLY',original_wire_status='FAIL_SIGKILL_NO_TERMINAL_SUMMARY',
            original_storage_status='FAIL_CONFIRMED_ERROR_TEXT_MISMATCH',
            exact_storage_summary=storage_summary,original_wire_completed_cases=len(wire_cases),
            original_wire_planned_cases=49,wire_completed_cases=wire_cases,
            wire_completed_entry_counts=pending_counts,last_completed_entry=last,
            pending_entry=pending,pending_marker_interpretation=state,
            pending_component=bundle['components'][pending['role']],
            unfinished_case=starts[-1] if len(starts)>len(passes) else None,
            exact_wire_process=process,zip_files=len(checked_zip),inner_members=len(inner),
            cas_objects=len(cas),logical_cas_bytes=sum(v['bytes'] for v in cas.values()),
            uncompleted_unreferenced_cas=incomplete_cas,partial_uncompleted_ledgers=partial_ledgers,
            all_completed_entry_buffers_verified=True,
            all_original_component_source_image_receipt_bindings_verified=True,
            exact_compile_frozen_bindings=frozen_bindings,
            all_case_counts={key:len(value) for key,value in case_counts.items()},
            all_entry_counts=entry_counts,selected_buffers=selected_buffers,
            diagnosis_limit='A pending marker without completed entry ledger does not distinguish time inside native code from post-return custody before flush. Exact remaining case is from original stdout, not inferred from SIGKILL.',
            quota_changed=False)
        emit('derived/last-completed-entry.json',(json.dumps(last,sort_keys=True,indent=2)+'\n').encode())
        emit('derived/pending-component-binding.json',
            (json.dumps(result['pending_component'],sort_keys=True,indent=2)+'\n').encode())
        save(out/'summary.json',result);print(json.dumps(result,sort_keys=True),flush=True)
    except BaseException as exc:
        result.update(failure=dict(error_class=type(exc).__name__,error=str(exc)))
        save(out/'summary.json',result);traceback.print_exc();raise
if __name__=='__main__':main()
