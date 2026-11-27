"""Run the complete retained Future campaign against the rebuilt complete Value.
Development fixture binding only; no product, original assertion or case is patched.
"""
from pathlib import Path
from hashlib import sha256
import argparse, ast, ctypes as C, importlib, json, os, shutil, struct, subprocess, sys
import concurrent.futures._base

ORIGINAL_DRIVER_SHA256 = '47d0a6edfee8251fcb55c8e3eb092dee28dd07e95d29892016b0eb98e2610cc1'
ORIGINAL_FUTURE_ORACLE_SHA256 = '3665aa676031ee09ed6db32db6227e66f56c96230cfd26a2db7c2d83da49b69d'

EXPECTED_FIXTURES = {
  "client-v3.py": "ab2a5521d0d354ffc80aec6d1403548e0e4bcdf1f212e58e3eba99781d544e4d",
  "iterable-client-v3.py": "eeb3c57b7c7d07ddb776a743a4d798cccc63ab3d5d9e45dd6efbaaaaaa2b32bb",
  "native-iterator-fixture-client-v1.py": "ce7640a3133bb7f7ff58c607b07f6c5b49cdd06b212f35cf36b0e9d326ba34c1",
  "observer-client-v4.py": "cd0828181a941eddf15c2e11afff2e8eda0a86a0879b090df889e2536a7eee59",
  "qualify-inherited-concurrency-v1.py": "65be8fca6c1232535c62d296cdd06811f018d6cb7063724db0cc8e8e2eb936ad",
  "qualify-inherited-private-v1.py": "556ec389729c37cf15f6f59effa860f8bf86ff57fa33d6b35aaf7f31a9d9cc00",
  "qualify-iterable-controls-v1.py": "b59bd8c8d89631b3548a8646445834b4a33ded58bddfda79302dca1c6ba24c77",
  "qualify-iterable-lifecycle-v1.py": "8792e3a82778f15fe2c80b522cf71a06b0e3f1485ec96c552d5dbd5a0697f6ba",
  "qualify-iterable-native-callback-v2.py": "c5133aebfaf5f1d20c582cf74168b420f134353b39f2842fd77640ccf04a0d27",
  "qualify-notify-v1.py": "f8a6794265d1cb1a666e79896e92555fcc01586693cfe486ed70106056891ad9",
  "qualify-original-matrix-v3.py": "df5566a32ff1c4c3df89ee60f0fe790a9011e6552ea74494e37a7001aa870b8b",
  "qualify-owner-controls-v4.py": "45eb4c106d3225bf3a46473c52d69321db223e9e3e7068c66725c40de0104633",
  "qualify-owner-original-v4.py": "13bbb2c96c57a18079b3a2129558605aaa67bffc541af346619cef6fa0df4c1c",
  "qualify-smoke-v2.py": "b16ab569ef5a23b568cc1fba5756a5476724b66582473de4fc5f3015d9692dd0",
  "qualify-waiters-v1.py": "75effe928a6d59dc2014a7c96e60aceb119300cf0eab2c5900fecac9f4bdaa6a",
  "regression-cleanup-v2.py": "b9ab8345104c74583cbc88437e31ebab420e542136f56f9401a3a3dd44e374cb",
  "regression-client-v1.py": "7d9b9b787a9ad15173ac8748bf5eb38206cd59a1f102fb8d616a8fb05c834544",
  "regression-concurrency-v3.py": "b52fe04f8d80383f26e2b6b4aa9266e37542a1cf3bf2e6e3445df0eb49b4bb9c",
  "regression-kernel-v2.py": "22b0eb1bc60d9932df874e1d14c4a4a3aa482a16b0962d8f60b0fea932872209",
  "regression-pack-v1.py": "4fd3150e5248d8ec40e22cfead58967b9953cc0160aeffd8087b906d8443b91d",
  "regression-private-v3.py": "e29f72e91823263b951c5c5e06e3b8eff7aa8335fb5873c0ca5ce6d65104e732",
  "regression-smoke-v5.py": "8c034624484bf7e4c32f05ac14d4cae04729648f7a0c14cb12410a4cc2257a82",
  "regression-value-kernel-v2.py": "2b616503de42994b8b7855667d5f446b9c9ab4690d5d9f7ca9a287c524e4e6b8",
  "run.py": "4c1f6c23ef846414fe4d6562c79cbd50f686369fb44391df25b8901813de81c8",
  "setter-kernel-22-pending.py": "2e5044abd0bdfcd26b84a36decaab086ea190e5ddf59ab2cdf6cf3f638b35a54",
  "setter-kernel-22-running.py": "3dd3f76a8079c4a290565c00a8fd79a491b8b4f124bdae6ab1b61ec331dbd58f",
  "setter-kernel-23-pending.py": "fa5bf454d7ff25e9a277115782d39ad36fd1fd4ec0a9a2720f9b25dcfbfd7257",
  "setter-kernel-23-running.py": "93a9ec8161fbf53e1e4f30466ea75ad33c5184bf27234be56c5fbaeed02eedc3",
  "value-fault-invalid-state.py": "71ee54e2bbd5956d6f567c3e80bec6bccbb9bbf7387e7dcc11306394d811fc1c",
  "value-fault-nonexception-result.py": "9ffb19841e6d6998d81268adb060eeac3102ce0a3d1483e54860c9d48d7d470e",
  "value-fault-strict-exception.py": "b853e5984fabad2a335d31173f97dda9ce4886a09f025fe196c10abeac7a2f57",
  "value-fault-strict-result.py": "242edb81f781cb53f0bc348dc3a856317f55f6d571c5a7b718438bfcfe12fb86",
  "value-fault-unexpected-running.py": "5d5fcdd184251e5d2a4107b062a37f946b5879953c025ccde5a48a9c08409b5c"
}
EXPECTED_HELPERS = {
  "future-public-client-v3.py": "48e28aeefd150c5ffe30642c7d47313a5fff9a909f24edcc4c9f54f9f83cefe4",
  "qualify-result-value-core-smoke-v1.py": "9dbbc2a3e7e19770b7c44128f9f732a0cd3eb4f2bcf1f6011e54ef8bc8c334ed"
}
OLD_VALUE_SHA = '6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c'
COMPILER_SHA = '494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'

def digest(raw): return sha256(raw).hexdigest()
def record(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=digest(raw))
def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle: handle.write(raw)
def put_json(path, value): write(path, (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--original-fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    assert sys.version_info[:2] == (3, 14), 'retained campaigns require the original Python 3.14 oracle'
    oracle_base = Path(concurrent.futures._base.__file__).resolve()
    assert digest(oracle_base.read_bytes()) == ORIGINAL_FUTURE_ORACLE_SHA256
    compiler = args.compiler.resolve()
    assert compiler.stat().st_size == 813129 and digest(compiler.read_bytes()) == COMPILER_SHA
    source, build, old, output = [p.resolve() for p in (args.source, args.build, args.original_fixtures, args.output)]
    receipt_path = args.receipt.resolve()
    receipt_path.relative_to(source)
    output.mkdir(mode=0o700)
    root = output / 'fixtures'; root.mkdir(mode=0o700)
    qrel = Path('future-public-inherited-qa')
    rrel = qrel / 'final-v5'
    old_final, final = old / rrel, root / rrel
    final.mkdir(parents=True)
    source_build_bytes = (build / 'build.json').read_bytes()
    result = json.loads(source_build_bytes)
    assert result['schema'] == 'hepta.hia.future-native-release-build.v1'
    assert result['status'] == 'BUILT_PENDING_FUTURE_BEHAVIOR'
    assert result['value_protocol'] in ('HIABVP04', 'HIABVP05', 'HIABVP09')
    assert result.get('public_protocol', 'HIABFPP2') in ('HIABFPP2', 'HIABFPP3')
    assert result['compiler']['sha256'] == COMPILER_SHA
    assert not result['inherited_behavior_requalified']
    products = result['products']
    for name, pin in products.items():
        raw = (build / name).read_bytes()
        assert len(raw) == pin['bytes'] and digest(raw) == pin['sha256'], name
    frozen = dict(result['source_files'])
    for name, pin in frozen.items(): assert digest((source / name).read_bytes()) == pin, name
    modules = {Path(row['source_path']).stem: row for row in result['modules']}
    for name, row in modules.items():
        raw = (build / (name + '.flat')).read_bytes()
        assert len(raw) == row['flat_bytes'] and digest(raw) == row['flat_sha256'], name

    sys.path.insert(0, str(source))
    from tools.hia_native_value_profiles import value_profile
    profile = value_profile(result['value_protocol'])
    assert result['value_roles'] == list(profile.roles)
    assert result['value_packer'] == profile.packer
    has_cleanup = result.get('public_has_cleanup', False)
    public_name = result.get('public_packer', 'background_optimizer_future_public_packer')
    public_author = importlib.import_module('tools.generate_hia_' + public_name)
    value_author = importlib.import_module('tools.generate_hia_' + result['value_packer'])
    assert tuple(result['public_roles']) == public_author.ROLES
    profile_bindings = []
    value_bridge_size = len(value_author.BRIDGE)
    assert 0 < value_bridge_size <= (1 << 20)
    value_sha = products['hia-result-value.core.bin']['sha256']
    bindings = []
    replacements = [(str(old), str(root)), (OLD_VALUE_SHA, value_sha)]
    # These are instruction-address custody bounds in ptrace fixtures, not semantic limits.
    if value_bridge_size != 577:
        replacements += [('+577]', '+'+str(value_bridge_size)+']'),
                         ('[:577]', '[:'+str(value_bridge_size)+']'),
                         ('<577 and reg.orig_rax==25', '<'+str(value_bridge_size)+' and reg.orig_rax==25')]
    def bind(relative, expected):
        original = old / relative
        raw = original.read_bytes(); assert digest(raw) == expected, str(relative)
        text = raw.decode('utf-8'); adapted = text; changes=[]
        for before, after in replacements:
            count = adapted.count(before)
            if count:
                adapted = adapted.replace(before, after)
                changes.append(dict(before=before, after=after, occurrences=count))
        if has_cleanup and relative == rrel / 'regression-pack-v1.py':
            # Only the explicit wire profile, count and relocated header fields
            # are rebound. Error/status/effect assertions remain byte exact.
            layout = [
                ('from tools.generate_hia_background_optimizer_future_public_packer import', 'from tools.generate_hia_background_optimizer_future_public_cleanup_packer import'),
                ("b'HIABFPP2'+struct.pack('<10Q',8,", "b'HIABFPP3'+struct.pack('<11Q',9,"),
                ("('header',raw[:87])", "('header',raw[:95])"),
                ('(8,7),(8,9),(80,2)', '(8,8),(8,10),(88,2)'),
                ('range(16,80,8)', 'range(16,88,8)'),
            ]
            for before, after in layout:
                assert adapted.count(before) == 1, before
                adapted = adapted.replace(before, after)
                changes.append(dict(before=before, after=after, occurrences=1, kind='exact-new-profile-wire-binding'))
            profile_bindings.extend(layout)
        reverse = adapted
        for change in reversed(changes): reverse = reverse.replace(change['after'], change['before'])
        assert reverse == text, ('non-fixture change', str(relative))
        assert ast.dump(ast.parse(reverse), include_attributes=False) == ast.dump(ast.parse(text), include_attributes=False)
        target = root / relative; write(target, adapted.encode('utf-8'))
        bindings.append(dict(source=record(original), target=record(target), changes=changes,
                             original_semantic_source_recovered_exactly=True))
    for name, pin in EXPECTED_FIXTURES.items(): bind(rrel / name, pin)
    for name, pin in EXPECTED_HELPERS.items(): bind(Path(name), pin)
    # The frozen original Python class is the oracle; current packer source is used
    # only by the original independent object/relocation comparison.
    old_oracle = old / 'future-public-inherited-source/hepta/hia_background_optimizer.py'
    new_oracle = source / 'hepta/hia_background_optimizer.py'
    assert new_oracle.read_bytes() == old_oracle.read_bytes()
    (root / 'future-public-inherited-source').symlink_to(source, target_is_directory=True)
    oracle_files = [record(old_oracle), record(new_oracle),
                    record(oracle_base)]

    def copy_product(name, target):
        raw = (build / name).read_bytes(); write(root / target, raw); return root / target
    value_path = copy_product('hia-result-value.core.bin', Path('result-value-native-v4/result-value.flat'))
    public_dir = root / qrel / 'public-native-v5'; public_dir.mkdir(parents=True)
    public_path = copy_product('hia-future-public.core.bin', qrel / 'public-native-v5/future-public.flat')
    public_object = (build / 'hia-future-public.o').read_bytes()
    write(public_dir / 'future-public.o', public_object)
    roles = []
    for role, name in zip(public_author.ROLES[:6], (
            'background_optimizer_future_public_owner','background_optimizer_future_public_carrier',
            'background_optimizer_future_public_timeout','background_optimizer_future_public_log',
            'multiversion_background_future_cell','multiversion_future'), strict=True):
        raw = (build / (name + '.flat')).read_bytes()
        path = public_dir / (role + '.flat'); write(path, raw)
        roles.append(dict(role=role, **record(path)))
    roles.append(dict(role='value', **record(value_path)))
    notify_path = copy_product('hia-future-notify.core.bin', qrel / 'public-native-v5/notify.flat')
    roles.append(dict(role='notify', **record(notify_path)))
    if has_cleanup:
        cleanup_path = public_dir / 'cleanup.flat'
        write(cleanup_path, (build / 'background_optimizer_future_public_cleanup.flat').read_bytes())
        roles.append(dict(role='cleanup', **record(cleanup_path)))
    assert tuple(row['role'] for row in roles) == public_author.ROLES
    role_bytes = [Path(row['path']).read_bytes() for row in roles]
    assert public_author.reference_flat(role_bytes) == public_path.read_bytes()
    assert public_author.reference_object(role_bytes) == public_object
    public_meta = dict(status='ACTUAL_CURRENT_NATIVE_BUILD_FOR_ORIGINAL_FIXTURES', qualified=False,
        roles=roles, products=[dict(format='flat', bytes=public_path.stat().st_size, sha256=digest(public_path.read_bytes())),
                              dict(format='object', bytes=len(public_object), sha256=digest(public_object))])
    put_json(public_dir / 'build.json', public_meta)
    write(public_dir / 'public-packer.flat', (build / (public_name+'.flat')).read_bytes())
    put_json(public_dir / 'packer-build.json', dict(flat_sha256=modules[public_name]['flat_sha256']))
    base_public_dir = root / 'future-public-native-v5'; base_public_dir.mkdir()
    write(base_public_dir / 'future-public.flat', public_path.read_bytes())
    put_json(base_public_dir / 'build.json', public_meta)

    bridge_dir = root / qrel / 'bridges-v1'; bridge_dir.mkdir()
    old_bridge_dir = old / qrel / 'bridges-v1'
    if has_cleanup:
        bridge_source = source / 'tools/hia_background_optimizer_future_public_cleanup_bridge.S'
        bridge_object = output / 'actual-public-bridge.o'
        bridge_binary = output / 'actual-public-bridge.bin'
        subprocess.run(['/usr/bin/as','--64',str(bridge_source),'-o',str(bridge_object)],check=True,capture_output=True,timeout=30)
        subprocess.run(['/usr/bin/objcopy','-O','binary','--only-section=.text',str(bridge_object),str(bridge_binary)],check=True,capture_output=True,timeout=30)
        assert bridge_binary.read_bytes() == public_author.BRIDGE
        symbols = subprocess.check_output(['/usr/bin/nm','-n',str(bridge_object)],text=True,timeout=30)
        entries = {}
        for line in symbols.splitlines():
            words = line.split()
            if len(words)==3 and words[1] in ('t','T'):
                entries[words[2]] = int(words[0],16)
        assert 0 <= entries['public_malloc'] < entries['public_deallocate'] < len(public_author.BRIDGE)
        write(bridge_dir / 'hia_background_optimizer_future_public.bin',public_author.BRIDGE)
        put_json(bridge_dir / 'bridge.json',dict(entries=entries,bytes=len(public_author.BRIDGE),source=record(bridge_source)))
    else:
        assert (old_bridge_dir / 'hia_background_optimizer_future_public.bin').read_bytes() == public_author.BRIDGE
        for name in ('hia_background_optimizer_future_public.bin', 'bridge.json'):
            write(bridge_dir / name, (old_bridge_dir / name).read_bytes())
    bridge_metadata = json.loads((bridge_dir / 'bridge.json').read_bytes())
    assert bridge_metadata['bytes'] == len(public_author.BRIDGE)

    observer_dir = root / qrel / 'owner-native-v1'; observer_dir.mkdir()
    observer_names = [('owner-policy','background_optimizer_future_public_observers'),
                      ('math','background_optimizer_future_public_observers_math'),
                      ('owner-packer','background_optimizer_future_public_observers_packer')]
    observer_roles = []
    for alias, name in observer_names:
        write(observer_dir / (alias+'.flat'), (build/(name+'.flat')).read_bytes())
        observer_roles.append(dict(name=name, flat_sha256=modules[name]['flat_sha256']))
    copy_product('hia-future-observers.core.bin', qrel/'owner-native-v1/observers.flat')
    put_json(observer_dir/'build.json', dict(flat_sha256=products['hia-future-observers.core.bin']['sha256'],
                                          roles=observer_roles))

    iterable_dir = root / qrel / 'iterable-native-v1'; iterable_dir.mkdir()
    iterable_names = [('iterable-policy','background_optimizer_future_public_observers_iterable'),
                      ('iterable-packer','background_optimizer_future_public_observers_iterable_packer')]
    iterable_roles = []
    for alias, name in iterable_names:
        write(iterable_dir / (alias+'.flat'), (build/(name+'.flat')).read_bytes())
        iterable_roles.append(dict(name=name, flat_sha256=modules[name]['flat_sha256']))
    copy_product('hia-future-observers.core.bin', qrel/'iterable-native-v1/array.flat')
    copy_product('hia-future-iterable.core.bin', qrel/'iterable-native-v1/iterable.flat')
    put_json(iterable_dir/'build.json', dict(flat_sha256=products['hia-future-iterable.core.bin']['sha256'],
                                          roles=iterable_roles))
    # This retained HIA iterator is a test fixture, never a product under test.
    producer_rel = Path('future-public-observers-qa/iterator-producer-native-v2')
    producer_meta = json.loads((old / producer_rel / 'build.json').read_bytes())
    producer = (old / producer_rel / 'producer.flat').read_bytes()
    assert producer_meta['fixture_only'] is True and producer_meta['semantic_callbacks_are_actual_HIA'] is True
    assert len(producer) == producer_meta['flat_bytes'] and digest(producer) == producer_meta['flat_sha256']
    for name in ('build.json','producer.flat'): write(root/producer_rel/name, (old/producer_rel/name).read_bytes())
    put_json(output/'fixture-bindings.json', dict(bindings=bindings, original_oracles=oracle_files,
        value_bridge_bytes=value_bridge_size, native_iterator_fixture=record(old/producer_rel/'producer.flat')))

    # The preserved eight-role wire domain is also executed against the original
    # unmodified packer gate. It is an independent compatibility construction,
    # never substituted for the new nine-role public product's behavior.
    legacy_report = None
    if has_cleanup:
        legacy = output / 'legacy-packer-fixtures'
        legacy_final = legacy / rrel
        legacy_final.mkdir(parents=True)
        (legacy / 'future-public-inherited-source').symlink_to(source, target_is_directory=True)
        for relative in [rrel/'regression-pack-v1.py',rrel/'regression-client-v1.py',
                         Path('future-public-client-v3.py'),Path('qualify-result-value-core-smoke-v1.py')]:
            original = old / relative
            expected = EXPECTED_FIXTURES.get(relative.name,EXPECTED_HELPERS.get(relative.name))
            raw = original.read_bytes(); assert digest(raw)==expected
            text = raw.decode(); bound=text.replace(str(old),str(legacy)).replace(OLD_VALUE_SHA,value_sha)
            assert bound.replace(str(legacy),str(old)).replace(value_sha,OLD_VALUE_SHA)==text
            write(legacy/relative,bound.encode())
        legacy_author = importlib.import_module('tools.generate_hia_background_optimizer_future_public_packer')
        legacy_source = source / 'examples/hia_bootstrap/background_optimizer_future_public_packer.hepta'
        inherited = json.loads((source/'docs/HIA_BACKGROUND_NATIVE_FUTURE_INHERITED.json').read_bytes())
        legacy_row = next(row for row in inherited['runtime_sources'] if row['path']==str(legacy_source.relative_to(source)))
        legacy_raw = legacy_source.read_bytes()
        assert len(legacy_raw)==legacy_row['bytes'] and digest(legacy_raw)==legacy_row['sha256']
        assert digest(compiler.read_bytes())==COMPILER_SHA
        compiled=[]
        for _ in range(2):
            p=subprocess.run([str(compiler),'compile'],input=legacy_raw,capture_output=True,timeout=30)
            assert p.returncode==0 and p.stdout and not p.stderr
            compiled.append(p.stdout)
        assert compiled[0]==compiled[1]
        legacy_public=legacy/qrel/'public-native-v5';legacy_public.mkdir(parents=True)
        legacy_packer=legacy_public/'public-packer.flat';write(legacy_packer,compiled[0])
        from tools.qualify_hia_multiversion_components import Image
        image=Image(legacy_packer)
        legacy_parts=role_bytes[:8]
        legacy_products=[]
        for mode,extension in ((0,'o'),(1,'flat')):
            wire=b'HIABFPP2'+struct.pack('<10Q',8,*map(len,legacy_parts),mode)+b''.join(legacy_parts)
            out=C.create_string_buffer(16<<20);work=C.create_string_buffer(512)
            size=image(wire,out,work)
            assert 0<size<len(out)
            raw=out.raw[:size]
            expected=legacy_author.reference_object(legacy_parts) if mode==0 else legacy_author.reference_flat(legacy_parts)
            assert raw==expected
            write(legacy_public/('future-public.'+extension),raw)
            legacy_products.append(dict(format='object' if mode==0 else 'flat',bytes=len(raw),sha256=digest(raw)))
        legacy_roles=[]
        for row,raw in zip(roles[:8],legacy_parts,strict=True):
            path=legacy_public/(row['role']+'.flat');write(path,raw)
            legacy_roles.append(dict(role=row['role'],**record(path)))
        legacy_meta=dict(roles=legacy_roles,products=legacy_products)
        put_json(legacy_public/'build.json',legacy_meta)
        put_json(legacy_public/'packer-build.json',dict(flat_sha256=digest(compiled[0])))
        write(legacy/'future-public-native-v5/future-public.flat',(legacy_public/'future-public.flat').read_bytes())
        put_json(legacy/'future-public-native-v5/build.json',legacy_meta)
        write(legacy/'result-value-native-v4/result-value.flat',value_path.read_bytes())
        for name in ('hia_background_optimizer_future_public.bin','bridge.json'):
            write(legacy/qrel/'bridges-v1'/name,(old_bridge_dir/name).read_bytes())
        env=dict(PATH='/usr/bin:/bin',PYTHONPATH=str(source),PYTHONDONTWRITEBYTECODE='1',LC_ALL='C')
        with (output/'legacy-packer.stdout').open('wb') as stdout,(output/'legacy-packer.stderr').open('wb') as stderr:
            process=subprocess.run([sys.executable,'-u',str(legacy_final/'regression-pack-v1.py')],
                                   cwd=source,env=env,stdout=stdout,stderr=stderr,timeout=400)
        assert process.returncode==0, 'original eight-role packer gate'
        legacy_report_path=legacy_final/'regression-pack-v1/report.json'
        legacy_report=json.loads(legacy_report_path.read_bytes())
        assert legacy_report['passed'] is True and legacy_report['fixed_product_roles']==list(legacy_author.ROLES)
        legacy_report=dict(report=record(legacy_report_path),source=record(legacy_source),
                           original_gate_sha256=EXPECTED_FIXTURES['regression-pack-v1.py'],
                           original_domain_and_assertions_unchanged=True,summary=legacy_report)

    source_snapshot = dict(frozen)
    env = dict(PATH='/usr/bin:/bin', PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE='1', LC_ALL='C')
    with (output/'campaign.stdout').open('wb') as stdout, (output/'campaign.stderr').open('wb') as stderr:
        process = subprocess.run([sys.executable, '-u', str(final/'run.py')],
                                 cwd=source, env=env, stdout=stdout, stderr=stderr, timeout=12000)
    status = json.loads((final/'status.json').read_bytes())
    if process.returncode != 0 or not status.get('passed'):
        put_json(output/'failed-campaign.json', dict(returncode=process.returncode, status=status,
            passed=False, whole_native_delivery_qualified=False))
        raise AssertionError(('complete retained Future campaign failed', process.returncode, status))
    assert len(status['rows']) == 27 and all(row['returncode'] == 0 for row in status['rows'])
    reports = []
    for path in sorted(final.glob('*/report.json')):
        doc = json.loads(path.read_bytes())
        assert doc.get('passed') is True or (path.parent.name == 'notify-qa-v1' and doc.get('status') == 'NATIVE_NOTIFY_COMPONENT_PASS'), str(path)
        reports.append(dict(name=path.parent.name, **record(path),
            summary={key:doc[key] for key in ('passed','status','count','controls','case_groups','pairs','calls','public_calls','actual_public_calls','value_calls','adapter_calls','checks_count','actual_notify_calls') if key in doc}))
    assert len(reports) == 27
    for name, pin in source_snapshot.items(): assert digest((source / name).read_bytes()) == pin, name
    assert (build / 'build.json').read_bytes() == source_build_bytes
    for name, pin in products.items(): assert digest((build / name).read_bytes()) == pin['sha256'], name
    for row in bindings:
        assert digest(Path(row['source']['path']).read_bytes()) == row['source']['sha256']
        assert digest(Path(row['target']['path']).read_bytes()) == row['target']['sha256']
    for row in oracle_files:
        assert digest(Path(row['path']).read_bytes()) == row['sha256']
    doc = dict(schema='hepta.hia.future-value-integration-qualification.v1', passed=True, groups=27,
        rows=status['rows'], reports=reports, products=products, source_files=source_snapshot,
        compiler_sha256=COMPILER_SHA, source_frozen_through_campaigns=True,
        original_domains_and_assertions_unchanged=True, fixture_bindings=bindings,
        new_public_wire_profile=result.get('public_protocol','HIABFPP2'),
        new_wire_fixture_bindings=profile_bindings, preserved_legacy_packer_qualification=legacy_report,
        original_oracles=oracle_files, python_version=sys.version,
        qualification_driver=record(Path(__file__).resolve()),
        original_qualification_driver_sha256=ORIGINAL_DRIVER_SHA256,
        native_iterator_fixture=record(old/producer_rel/'producer.flat'),
        whole_public_future_closed=False, final_unified_dispatcher_qualified=False,
        production_activated=False)
    put_json(output/'qualification.json', doc)
    encoded = (json.dumps(doc, indent=2, sort_keys=True)+'\n').encode()
    receipt_path.write_bytes(encoded)
    print(json.dumps(dict(passed=True, groups=27, reports=len(reports), receipt=str(receipt_path),
                          sha256=digest(encoded), products=products), indent=2), flush=True)

if __name__ == '__main__': main()

