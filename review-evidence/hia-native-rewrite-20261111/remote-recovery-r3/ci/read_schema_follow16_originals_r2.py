"""Read exact follow16 schema original evidence; never execute a native image.

Validates the complete original ZIP, complete inner member inventory and every
completed entry's content-addressed buffers before publishing a narrow diagnosis.
An observed SIGKILL remains a failed/incomplete large panel.
"""
from __future__ import annotations
import argparse,base64,collections,io,json,os,stat,tarfile,traceback,zipfile,zlib
from hashlib import sha256
from pathlib import Path,PurePosixPath

ZIP_BYTES=87932001
ZIP_SHA='cd2bac47b3abde483bc7a34498579859899df1efc0ac9d36e478bf4dfe510b6b'
INNER_BYTES=26819908
INNER_SHA='12dd38bc6bb0da09d941f669fa63444bf5175efcfa7ba32c93df19bcb1a4f537'
INDEX_BYTES=5695370
INDEX_SHA='6b4add9ad690f9e87f4d624c950b5bd6b4d098b9a97209cac5581d1c658138a5'
EXPECTED_MEMBERS=11810
EXPECTED_RAW_BYTES=208277293
HEAD='0363c98ea5d24a4f01772b811bb548ce453d30fb'
SCOPE='worker-complete-fixed-catalog-schema-remaining-development-r4'
COMPILER='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
SOURCE={'schema_scalar':'5437435e213179cc960de22c2ab9876cb35ae6be56197fd1901c5c9bce5e5ebf',
 'schema_logic':'aef36863fdc6df8b10b5e25a54f17df4a105316d332d2156142a83625e65dd09',
 'schema_containers':'b451db38c1f6b0f0e55a2f85f8912a6b443c52006ed58c7140d4906eebf54d93',
 'schema_errors':'21211df87499df1dc53da9c3152d816e603131e0068f68cf7c51787816ddf104',
 'scan':'c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3',
 'emit':'9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2',
 'patterns':'cdc4ac1f52e07b64196d604b27e894743a29842f6f4e946bbfaea14b8a21bb96'}
IMAGE={'schema_scalar':'e64a9541fa4bbe5e4f59d9e1d175148d66367a4c5854a5f16f7fb6c3c31da7c4',
 'schema_logic':'177d63863d7c89f1897c7d752211e625b4c1d4d03d406f8d762c393b97f13d40',
 'schema_containers':'40d13c3fa60af462262fd455ca325dc311fd140db6c6d23724a582836c5505f0',
 'schema_errors':'f994adfe05cab61f09ba8ddb8eedaab390756fde72c3fd6bdf2c95548c1869cc',
 'scan':'3545a6c60334b5f7e92eda8df582472a2a493c74b814e5ac9158cdd2e866b026',
 'emit':'9b69271adb5c3024842fc065e294b9a3550077801b76e43046c4eb09e3925a80',
 'patterns':'f80645aede2531f65ca26cd8f96e1ccba18b78bcb2c6b261cc2ac4998e050d24'}
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
    print(json.dumps(dict(event='SCHEMA16_ORIGINAL',name=name,bytes=len(raw),
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
    result=dict(scope='READ_ONLY_EXACT_SCHEMA_R4_ORIGINALS',status='FAIL',
        original_head=HEAD,run_id=43126608841,job_id=130880174175,artifact_id=13902464909,
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
        held={};cas={};incomplete_cas={};partial_ledgers={};seen=set();inner=[]
        def selected(name):
            return (name.startswith('run/steps/worker-complete-schema-large/')
                or name in ('run/summary.json','run/identity.json','run/steps.json')
                or name.startswith('run/complete-schema-compile/') and name.endswith(('.json','.harness.py'))
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
        complete_entries={};entry_counts={};case_counts={}
        def completed_lines(name,raw):
            lines=raw.splitlines(keepends=True)
            if lines and not lines[-1].endswith(b'\n'):
                tail=lines.pop()
                partial_ledgers[name]=dict(bytes=len(tail),sha256=digest(tail),
                    base64=base64.b64encode(tail).decode())
            return [json.loads(line) for line in lines if line.strip()]
        for name,raw in held.items():
            if not name.endswith('/entries.jsonl'):continue
            records=completed_lines(name,raw)
            root=name.rsplit('/',1)[0]
            counts=collections.Counter()
            for record in records:
                counts[record['role']]+=1
                assert record['input_and_canaries_unchanged'] is True
                for key in ('source','second_before','second_after','workspace_before','workspace_after'):
                    ref=record[key];path=root+'/cas/'+ref['sha256']+'.zlib'
                    assert path in cas and cas[path]==dict(bytes=ref['bytes'],sha256=ref['sha256'])
                assert record['source']['bytes']>=0
            complete_entries[root]=records;entry_counts[root]=dict(counts)
        for name,raw in held.items():
            if name.endswith('/cases.jsonl'):
                records=completed_lines(name,raw)
                assert all(r['status']=='PASS' for r in records)
                case_counts[name.rsplit('/',1)[0]]=records
        bundle=json.loads(held['run/complete-schema-compile/bundle.json'])
        assert bundle['status']=='PASS' and set(bundle['components'])==set(SOURCE)
        for role,row in bundle['components'].items():
            assert row['source_sha256']==SOURCE[role] and row['image_sha256']==IMAGE[role]
            assert row['compiler_sha256']==COMPILER
            for part in ('source','image'):
                matches=by_path[row[part+'_path']]
                assert matches and all((x['bytes'],x['sha256'])==(row[part+'_bytes'],row[part+'_sha256']) for x in matches)
            receipt_rows=by_path[row['receipt_path']]
            assert len(receipt_rows)==1
            receipt=json.loads(held[receipt_rows[0]['name']])
            assert receipt['image_sha256']==COMPILER
            assert receipt['input_sha256']==SOURCE[role] and receipt['produced_sha256']==IMAGE[role]
        original_row=json.loads(held['run/complete-schema-compile/schema_scalar_original_r2.manifest.json'])
        assert (original_row['source_bytes'],original_row['source_sha256'])==(190205,
            '2805ad32e5ef028b953b04fbafab432fc835f3847ee530334cb9ce474f47cf6d')
        assert (original_row['image_bytes'],original_row['image_sha256'])==(260706,
            '8440aa54d01e7406be38a502072d890e98b05af1e1f8398b08a08981efe376bd')
        for part in ('source','image'):
            matches=by_path[original_row[part+'_path']]
            assert matches and all((x['bytes'],x['sha256'])==
                (original_row[part+'_bytes'],original_row[part+'_sha256']) for x in matches)
        original_receipts=by_path[original_row['receipt_path']]
        assert len(original_receipts)==1
        original_receipt=json.loads(held[original_receipts[0]['name']])
        assert original_receipt['image_sha256']==COMPILER
        assert original_receipt['input_sha256']==original_row['source_sha256']
        assert original_receipt['produced_sha256']==original_row['image_sha256']
        assert all(set(counts)<=set(SOURCE)|{'schema_scalar_original_r2'}
                   for counts in entry_counts.values())
        large='complete-schema/development/actual-large-r4'
        pending_name=large+'/pending-native-entry.json'
        assert pending_name in held and large in complete_entries
        pending=json.loads(held[pending_name])
        process_name='run/steps/worker-complete-schema-large/process.json'
        process=json.loads(held[process_name])
        stdout=held['run/steps/worker-complete-schema-large/stdout.log']
        stderr=held['run/steps/worker-complete-schema-large/stderr.log']
        assert (len(stdout),digest(stdout))==(process['stdout_bytes'],process['stdout_sha256'])
        assert (len(stderr),digest(stderr))==(process['stderr_bytes'],process['stderr_sha256'])
        assert process['returncode']==-9 and process['timed_out'] is False
        assert (len(stdout),digest(stdout))==(876,'9e1836889c10ba61e47fe92fe216db8b9928e1edf80c21e48e21e99a2ab69b81')
        pending_counts=entry_counts[large]
        completed_native_ordinal=pending_counts.get(pending['role'],0)
        state=('actual_entry_not_completed' if pending['role_entry']==completed_native_ordinal+1
               else 'last_recorded_entry_completed_but_later_phase_unknown')
        assert pending['role_entry'] in (completed_native_ordinal,completed_native_ordinal+1)
        if state=='actual_entry_not_completed':
            for field,prefix in (('source','source'),('second','second'),('workspace_before','workspace')):
                value=pending[field+'_sha256']
                n=pending[prefix+'_bytes']
                matches=[v for v in cas.values() if v['sha256']==value and v['bytes']==n]
                # The pre-entry marker hashes before the call; persistence of
                # new raw buffers happens after return and is not assumed.
                pending[field+'_already_in_verified_cas']=bool(matches)
        large_cases=case_counts.get(large,[])
        assert large+'/summary.json' not in held
        original=json.loads(held['run/summary.json'])
        assert original['status']=='FAIL' and original['scope']==SCOPE
        result.update(status='PASS',original_large_status='FAIL_SIGKILL_NO_TERMINAL_SUMMARY',
            original_large_completed_cases=len(large_cases),original_large_planned_cases=5,
            large_completed_cases=large_cases,large_completed_entry_counts=pending_counts,
            last_completed_entry=complete_entries[large][-1] if complete_entries[large] else None,
            pending_entry=pending,pending_marker_interpretation=state,
            pending_component=bundle['components'][pending['role']],
            exact_large_process=process,zip_files=len(checked_zip),inner_members=len(inner),
            cas_objects=len(cas),logical_cas_bytes=sum(v['bytes'] for v in cas.values()),
            uncompleted_unreferenced_cas=incomplete_cas,partial_uncompleted_ledgers=partial_ledgers,
            all_completed_entry_buffers_verified=True,
            all_original_component_source_image_receipt_bindings_verified=True,
            all_case_counts={key:len(value) for key,value in case_counts.items()},
            all_entry_counts=entry_counts,
            diagnosis_limit='Pending means no completed entry ledger yet; it does not distinguish time inside native entry from post-return custody before ledger flush.',
            quota_changed=False)
        for name in (process_name,'run/steps/worker-complete-schema-large/stdout.log',
                     'run/steps/worker-complete-schema-large/stderr.log',pending_name,
                     large+'/cases.jsonl'):
            emit(name,held[name])
        emit('derived/last-completed-entry.json',
            (json.dumps(result['last_completed_entry'],sort_keys=True,indent=2)+'\n').encode())
        emit('derived/pending-component-binding.json',
            (json.dumps(result['pending_component'],sort_keys=True,indent=2)+'\n').encode())
        save(out/'summary.json',result)
        print(json.dumps(result,sort_keys=True),flush=True)
    except BaseException as exc:
        result.update(failure=dict(error_class=type(exc).__name__,error=str(exc)))
        save(out/'summary.json',result);traceback.print_exc();raise

if __name__=='__main__':main()
