"""Full R16-R3 failure custody; no product generation, tests or qualification."""
import collections,gzip,hashlib,json,pathlib,re,stat,tarfile,time,traceback,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
BASE=ROOT.parent/'v103-union-r16'
LOCAL=BASE/'source'
OUT=ROOT/'readback-r1'
TREE='d87a062aefd4813fdd1425e4653cfca2a202daf6'
ZIP_BYTES=338375665
ZIP_SHA='4c7e93f5f72c821917e85454743e6284ae0dfdadb398a9055421825e532313d3'

def unique(pairs):
    answer = {}
    for key, value in pairs:
        assert key not in answer, ('duplicate JSON key', key)
        answer[key] = value
    return answer

def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def check_pin(raw, expected):
    actual = pin(raw)
    assert actual['bytes'] == expected['bytes']
    assert actual['sha256'] == expected['sha256']
    assert actual['git_blob'] == expected.get('git_blob', expected.get('blob'))
    return actual

def safe(name):
    path = pathlib.PurePosixPath(name)
    assert name and not path.is_absolute() and '\\' not in name and '\0' not in name
    assert '..' not in path.parts and '.' not in path.parts and str(path) == name
    return path

def put(path, raw, mode=0o644):
    assert type(mode) is int and 0 <= mode <= 0o777
    path.parent.mkdir(parents=True, exist_ok=True)
    assert not path.is_symlink()
    if path.exists():
        assert path.is_file() and path.read_bytes() == raw
    else:
        with path.open('xb') as stream:
            stream.write(raw)
    path.chmod(mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode

def write_json(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

def tree(rows):
    direct, groups = [], {}
    for path, mode, oid in rows:
        name, sep, rest = path.partition('/')
        if sep:
            groups.setdefault(name, []).append((rest, mode, oid))
        else:
            direct.append((name, mode, oid, False))
    for name, children in groups.items():
        direct.append((name, '40000', tree(children), True))
    direct.sort(key=lambda row: row[0].encode() + (b'/' if row[3] else b''))
    raw = b''.join(mode.lstrip('0').encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
                   for name, mode, oid, _ in direct)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def stream_pin(stream,size):
    sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(size).encode()+b'\0');count=0
    for raw in iter(lambda:stream.read(1<<20),b''):
        count+=len(raw);sha.update(raw);git.update(raw)
    assert count==size
    return {'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()}


def main():
    started=time.monotonic();OUT.mkdir(exist_ok=False)
    original=ROOT/'ORIGINAL-ARTIFACT.zip'
    assert original.stat().st_size==ZIP_BYTES
    with original.open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==ZIP_SHA
    with zipfile.ZipFile(original) as archive:
        infos=archive.infolist();assert len(infos)==len({x.filename for x in infos})==6157
        outer={}
        for item in infos:
            safe(item.filename);mode=(item.external_attr>>16)&0xffff
            assert not item.is_dir() and stat.S_ISREG(mode) and not item.flag_bits&1
            with archive.open(item) as stream:actual=stream_pin(stream,item.file_size)
            outer[item.filename]={'path':item.filename,**actual,'crc32':item.CRC,
                'zip_unix_file_mode':mode,'permission_mode':stat.S_IMODE(mode),
                'external_attr':item.external_attr,'create_system':item.create_system}
        write_json(OUT/'OUTER-MEMBERS.json',list(outer.values()))
        manifest_raw=archive.read('EVIDENCE-MANIFEST.json');manifest=parse(manifest_raw)
        assert pin(manifest_raw)=={'bytes':2639909,'sha256':'2deca417efdfaa3e0e3dd18512c71ae93c936fb651b84da9efa388e6d6b91b0c','git_blob':'b217240f07520c7cc26548b9bcbe4965906e9297'}
        assert manifest['schema']=='hepta.combined-source-build-evidence.v2'
        assert parse(archive.read('EVIDENCE-PIN.json'))['full_readback_equal'] is True
        assert outer['FROZEN-SOURCE-EVIDENCE.tar.gz']['bytes']==manifest['bytes']==109873612
        assert outer['FROZEN-SOURCE-EVIDENCE.tar.gz']['sha256']==manifest['sha256']
        offset=0
        with archive.open('FROZEN-SOURCE-EVIDENCE.tar.gz') as stream:
            for index,chunk in enumerate(manifest['chunks']):
                assert chunk['index']==index and chunk['offset']==offset
                raw=stream.read(chunk['bytes']);check_pin(raw,chunk)
                assert chunk['full_readback_equal'] is True
                receipt=parse(archive.read('raw/upload-readbacks/'+chunk['blob']+'.json'))
                check_pin(raw,receipt);assert receipt['full_readback_equal'] is True
                offset+=len(raw)
            assert offset==manifest['bytes'] and stream.read()==b''
        assert len(manifest['chunks'])==210
        members={r['path']:r for r in manifest['members']};dirs={r['path']:r for r in manifest['directories']}
        assert len(members)==len(manifest['members'])==5097
        assert len(dirs)==len(manifest['directories'])==1287 and not members.keys()&dirs.keys()
        raw_root=OUT/'source-raw';raw_root.mkdir()
        seen=set();seen_dirs=set()
        with archive.open('FROZEN-SOURCE-EVIDENCE.tar.gz') as stream,gzip.GzipFile(fileobj=stream) as inflated:
            with tarfile.open(fileobj=inflated,mode='r|') as packed:
                for item in packed:
                    name=item.name;relative=safe(name)
                    if item.isdir():
                        assert name in dirs and name not in seen_dirs and item.mode==dirs[name]['mode']
                        (raw_root/relative).mkdir(parents=True,exist_ok=True);seen_dirs.add(name);continue
                    assert item.isfile() and name in members and name not in seen
                    assert item.mode==members[name]['mode']
                    raw=packed.extractfile(item).read();assert len(raw)==item.size
                    actual=check_pin(raw,members[name]);original_outer=outer['raw/'+name]
                    assert all(actual[key]==original_outer[key] for key in ('bytes','sha256','git_blob'))
                    put(raw_root/relative,raw,item.mode);seen.add(name)
            while inflated.read(1<<20):pass
        assert seen==set(members) and seen_dirs==set(dirs)
        for name,row in sorted(dirs.items(),key=lambda pair:pair[0].count('/'),reverse=True):
            (raw_root/name).chmod(row['mode']);assert stat.S_IMODE((raw_root/name).stat().st_mode)==row['mode']
        raw_root.chmod(manifest['root_mode'])
        assert stat.S_IMODE(raw_root.stat().st_mode)==manifest['root_mode']
    read=lambda name:parse((raw_root/name).read_bytes())
    result=read('RESULT.json');source=read('checks/SOURCE-TESTS.json')
    assert result==manifest['result']==parse((ROOT/'ORIGINAL-RESULT.json').read_bytes())['HIA_COMBINED_SOURCE_RESULT']
    assert result['status']=='SOURCE_FAIL' and not result['failures'] and result['python'].startswith('3.14.4 ')
    assert result['generation']=={'tree':TREE,'generator_count':134,'real_generation_passes':2,'physical_paths_retired_in_development_tree':55}
    assert result['syntax']=={'checked':1540,'failures':0} and result['product_tests_executed']==1357
    assert result['cold_qualifications']==result['native_qualification_jobs_executed']==0
    assert all(result[key] is False for key in ('default_changed','legacy_host_implementation_deleted','product_ref_changed','whole_native'))
    assert source==result['source_tests'] and source['status']=='FAIL' and source['complete'] is True
    assert type(source['expected']) is type(source['tests_run']) is int and source['expected']==source['tests_run']==1357
    assert len(source['failures'])==3 and len(source['errors'])==1
    assert {r['id'] for r in source['errors']}=={'tests.test_hia_candidate_evidence.NativeInventoryBoundary.test_actual_current_worker_manifest_matches_native_asset_inventory'}
    assert {r['id'] for r in source['failures']}=={
       'tests.test_hia_installed_fixture_resources.InstalledFixtureRoleInventoryTests.test_entry_assets_are_fresh_identity_inputs_and_missing_fails_before_backend',
       'tests.test_hia_installed_fixture_resources.InstalledFixtureRoleInventoryTests.test_standalone_entry_role_is_exact_disjoint_and_preflight_bounded',
       'tests.test_hia_linux_stdio_cold.LinuxStdioColdSourceTests.test_entry_resources_keep_all_four_predecessors_and_are_not_runtime_bridges'}
    expected=parse((BASE/'formal-preparation-r3/harness/inputs/FORMAL-EXPECTED-IDS.json').read_bytes())
    ids=source['ordered_ids'];assert ids==expected['r16_expected_ordered_ids']==source['actual_started_ids']==source['actual_stopped_ids']
    assert len(ids)==len(set(ids))==1357
    for key in ('skipped','expected_failures','unexpected_successes','duplicate_ids','missing_main_ids','missing_a733_ids','missing_frozen_main_ids','missing_frozen_a733_ids'):
        assert not source[key],key
    assert all(not x for x in source['loader_errors'].values())
    plan=read('harness/INPUTS.json');assert source['selectors']==plan['source_registration']['selectors'] and len(source['selectors'])==232
    assert (raw_root/'harness/INPUTS.json').read_bytes()==(BASE/'formal-preparation-r3/harness/inputs/MATERIALIZATION.json').read_bytes()
    assert (raw_root/'harness/DRIVER.py').read_bytes()==(BASE/'formal-preparation-r3/harness/tools/materialize_candidate_r16.py').read_bytes()
    projections={}
    for key,count in (('r15_expected_ordered_ids',1356),('r14_expected_ordered_ids',1353),('r13_expected_ordered_ids',1352),('r12_expected_ordered_ids',1342),('required_r11_ordered_projection',1329),('original_r10_r2_ordered_ids',1319)):
        original=expected[key];assert len(original)==count and [name for name in ids if name in set(original)]==original
        projections[key]=count
    events=[parse(line) for line in (raw_root/'checks/SOURCE-TESTS.events.jsonl').read_bytes().splitlines()]
    assert [(r['event'],r['id']) for r in events]==[(event,name) for name in ids for event in ('start','stop')]
    generations={}
    for phase in ('generate','reproduce'):
        found={}
        for path in (raw_root/'commands').glob('*.json'):
            match=re.search(r'-'+phase+r'-(\d+)-',path.name)
            if not match:continue
            index=int(match.group(1));assert index not in found;receipt=parse(path.read_bytes())
            assert type(receipt['returncode']) is int and receipt['returncode']==0 and receipt['timed_out'] is False
            for channel in ('stdout','stderr'):check_pin((raw_root/receipt[channel]['file']).read_bytes(),receipt[channel])
            found[index]=receipt['argv']
        assert sorted(found)==list(range(134));generations[phase]=found
    assert generations['generate']==generations['reproduce']
    inventory=read('sources/candidate-final.json');leaves={r['path']:r for r in inventory['entries'] if r['type']!='tree'}
    assert len(leaves)==inventory['files']==3133 and inventory['tree']==TREE
    assert tree([(name,r['mode'],r['oid']) for name,r in leaves.items()])==TREE
    before=read('checks/before-complete-source-tests-raw-worktree.json');after=read('checks/after-complete-source-tests-raw-worktree.json')
    assert not before['failures'] and not after['failures'] and before['files']==after['files']
    assert before['frozen_tree']==after['frozen_tree']==TREE and len(before['files'])==3133
    for row in before['files']:
        leaf=leaves[row['path']]
        assert row['expected_mode']==row['actual_mode']==leaf['mode'] and row['expected_blob']==row['actual_blob']==leaf['oid']
    terminal=read('terminal-worktree/INDEX.json');assert len(terminal['files'])==3133
    restored={};changes=[]
    for row in terminal['files']:
        name=row['path'];safe(name);leaf=leaves[name]
        assert row['kind']=='regular' and row['mode'] in (0o644,0o755) and row['blob']==leaf['oid']
        assert leaf['mode']==('100755' if row['mode']==0o755 else '100644')
        custody=row['content_custody'];raw=(raw_root/safe(custody['file'])).read_bytes() if 'file' in custody else (LOCAL/name).read_bytes()
        actual=check_pin(raw,row);local=(LOCAL/name).read_bytes()
        if local!=raw:changes.append({'path':name,'local':pin(local),'actual314':actual})
        put(OUT/'candidate-ci314'/name,raw,row['mode']);restored[name]={**actual,'mode':row['mode'],'git_mode':leaf['mode']}
    assert tree([(name,row['git_mode'],row['git_blob']) for name,row in restored.items()])==TREE
    assert {r['path'] for r in changes}<={'docs/HIA_NATIVE_REWRITE_INVENTORY.json','docs/HIA_SELFHOST_CORE_SUPPORT.json','hepta/hia_checker_identity.py'}
    write_json(OUT/'CANDIDATE-MANIFEST.json',restored);write_json(OUT/'LOCAL-VS-ACTUAL314-DIFF.json',changes)
    with (ROOT/'ORIGINAL-ARTIFACT.zip').open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==ZIP_SHA
    proof={'schema':'hepta.r16-r3-full-original-custody.v1','status':'CUSTODY_PASS_EXECUTION_SOURCE_FAIL',
        'run':43521833146,'job':132217759086,'artifact_id':14085836671,'head':'5217f8083876ed890a38c3f7291ba5a397c935b4',
        'original_zip':{'bytes':ZIP_BYTES,'sha256':ZIP_SHA},'outer_members':len(outer),'outer_raw_bytes':sum(r['bytes'] for r in outer.values()),
        'outer_file_modes':sorted({r['zip_unix_file_mode'] for r in outer.values()}),
        'outer_directory_modes':'not recorded; no fabricated ZIP directory mode',
        'frozen_archive_bytes':manifest['bytes'],'frozen_archive_sha256':manifest['sha256'],'frozen_chunks':len(manifest['chunks']),
        'inner_regular_files':len(members),'inner_directories':len(dirs),'inner_actual_modes_restored':True,
        'all_outer_crc_sha_git_verified':True,'all_inner_bytes_sha_git_modes_restored':True,'full_gzip_crc_verified':True,
        'source_files':len(restored),'source_tree':TREE,'local_vs_actual314_changes':changes,
        'source_test_count':1357,'source_passed_methods':1353,'source_failures':source['failures'],'source_errors':source['errors'],
        'source_wall_seconds':source['wall_seconds'],'source_events':len(events),'source_complete_ids':True,'source_before_after_equal':True,
        'ordered_prior_projections':projections,'real_generator_count':134,'generation_passes':2,'syntax_checked':1540,
        'bounded62_status':'SKIPPED_BY_SOURCE_DEPENDENCY','bounded62_executed':0,'cold_qualifications':0,'whole_native':False,
        'custody_product_tests_executed':0,'wall_seconds':time.monotonic()-started}
    write_json(OUT/'VERIFICATION.json',proof)
    print(json.dumps({key:proof[key] for key in ('status','outer_members','inner_regular_files','inner_directories','source_files','source_test_count','source_events','wall_seconds')}))


if __name__=='__main__':
    try:main()
    except BaseException:
        ROOT.mkdir(exist_ok=True)
        (ROOT/'READBACK-r1-ERROR.txt').write_text(traceback.format_exc())
        raise
