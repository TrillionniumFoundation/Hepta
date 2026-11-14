"""Preserve terminal R19 failure, exact custody, and actual production owners."""
from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT.parent
WORK = AUDIT.parent
INPUT = AUDIT / 'v118-component-inputs'
COLLECTION = 'hia-v118-source1411-terminal-and-production-owner-audit-20261114-dda7'


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check(raw, expected):
    actual = pin(raw)
    assert actual['git_blob'] == (expected.get('git_blob') or expected.get('sha'))
    for key in ('bytes', 'sha256'):
        if key in expected:
            assert actual[key] == expected[key], key
    return actual


def put(name, raw):
    with (ROOT / name).open('xb') as stream:
        stream.write(raw)


def main():
    leaves, groups, used = [], [], set()

    def add(path, raw, expected=None):
        assert path not in used and not path.startswith('/') and '..' not in Path(path).parts
        used.add(path)
        value = check(raw, expected) if expected else pin(raw)
        leaves.append({'path': path, 'sha': value['git_blob'], 'mode': '100644', 'type': 'blob'})
        return value

    recipes = {
        'r19-complete': 'e8ccd461059b2aad6d9f455430290d3d30e7df53',
        'report-cleanup-complete': '73e41f6db07e7e8f6710dad4752e4af0f767b40d',
        'roundtrip-source-repair': '65d4f7281ab3deed1ec7d94d0eebf8c1ba7838ea',
        'explicit-profile-providers': '25bfd2b1d1de3e47797f42be2ed2e4742634b40d',
        'r8-review-r2': '112d30017c7f7f7e102ce2f0bbc56a8bc388bfb3',
        'owner-chain-r19': 'a415281fa436e4587a6759c85a1400e46ba34173',
    }
    binary_count = 0
    for scope, recipe_sha in recipes.items():
        directory = INPUT / scope
        recipe_raw = (directory / 'MOUNT-RECIPE.json').read_bytes()
        check(recipe_raw, {'git_blob': recipe_sha})
        recipe = json.loads(recipe_raw)
        chunk_records = None
        if scope == 'r19-complete':
            chunk_records = {row['git_blob']: row for row in json.loads(
                (directory / 'formal-r19/INNER-CHUNKS-READBACK.json').read_bytes())}
            assert len(chunk_records) == 214
        for row in recipe['entries']:
            assert row['mode'] == '100644' and row['type'] == 'blob'
            path = scope + '/' + row['path']
            local = directory / row['path']
            if local.is_file():
                add(path, local.read_bytes(), row)
            else:
                assert scope == 'r19-complete' and row['path'].endswith('.bin')
                original = chunk_records[row['sha']]
                assert original['bytes'] == row['bytes'] and original['sha256'] == row['sha256']
                assert original['producer_full_get'] is True and original['producer_receipt'].startswith('raw/upload-readbacks/')
                assert path not in used
                used.add(path)
                leaves.append({key: value for key, value in dict(row, path=path).items()
                               if key in ('path', 'sha', 'mode', 'type')})
                binary_count += 1
        add(scope + '/MOUNT-RECIPE.json', recipe_raw)
        groups.append({'scope': scope, 'recipe': pin(recipe_raw), 'leaves': len(recipe['entries'])})
    assert binary_count == 214

    for name, sha in {
        'SOURCE-DELTA.json': 'd72ea658f6fbcccb40223eb929c3a73a569d86db',
        'SPEC.json': 'a9e8ac89a2269f8fdc16cc74bcaf38484e828976',
        'STATIC.json': 'fb20ede9c080612e21f2d477451244c2a68fa018',
    }.items():
        add('sdist-support/' + name, (INPUT / 'sdist-support' / name).read_bytes(), {'git_blob': sha})
    add('native-execution-plan/CAPSULE.json', (INPUT / 'native-execution-plan/CAPSULE.json').read_bytes(),
        {'git_blob': 'b6c650cc7b7100eec82b1792a47751b91629a84e'})
    r8_intent = json.loads((INPUT / 'r8-core/PUBLICATION-INTENT.json').read_bytes())
    for row in r8_intent['files']:
        add('r8-actual-core/' + row['path'], Path(row['local_path']).read_bytes(), row)

    # A readable audit is a new leaf; its exact full text already exists in the
    # reviewed owner-chain capsule. It is published independently below.
    owner_raw = (INPUT / 'owner-chain-r19/REPORT.md').read_bytes()
    assert pin(owner_raw)['git_blob'] == 'ae62b93f614733a090277969eed54d9ba90be67c'
    put('PRODUCTION-OWNER-AUDIT.md', owner_raw)
    add('PRODUCTION-OWNER-AUDIT.md', owner_raw)

    records = {}
    paths = {Path(__file__).resolve()}
    for scope in recipes.keys() | {'r19-terminal', 'sdist-support', 'native-execution-plan', 'r8-core'}:
        for path in (INPUT / scope).rglob('*'):
            if path.is_file() and (path.name.startswith(('ROOT-', 'GET-')) or path.name == 'PUBLICATION-INTENT.json'):
                paths.add(path)
    paths.add(INPUT / 'ROOT-TOOLS-STATE-RECOVERY.json')
    for name in ('v118-verify-r19-formal-source.py', 'v118-verify-r19-formal-source-r2.py',
                 'v118-verify-r19-formal-source-r3.py', 'v118-r19-text-get.js'):
        paths.add(AUDIT / name)
    for path in (AUDIT / 'publication').iterdir():
        if path.is_file() and path.name.startswith('v118-r8-core-'):
            paths.add(path)
    prior = AUDIT / 'v117-joint-source-and-complete-custody'
    for path in prior.iterdir():
        if path.is_file() and (path.name.startswith(('COMMIT-', 'REF-', 'PR889-', 'MAIN-AFTER-'))
                              or path.name in ('MOUNT-RESULT.json', 'TREES-VERIFIED.json', 'ROOT-RECORDS-READBACK.json')):
            paths.add(path)
    for path in sorted(paths):
        assert path.is_file() and not path.is_symlink(), path
        raw = path.read_bytes()
        records[path.relative_to(WORK).as_posix()] = {'mode': stat.S_IMODE(path.stat().st_mode),
            **pin(raw), 'base64': base64.b64encode(raw).decode()}
    root_raw = encode({'schema': 'hia.root.complete-terminal-and-custody-records.v118', 'files': records,
        'logical_files': len(records), 'logical_bytes': sum(row['bytes'] for row in records.values()),
        'new_product_executions': 0, 'whole_native': False})
    put('ROOT-RECORDS.json', root_raw)
    wrapper = encode({'schema': 'hia.lossless.zlib-json.v1', 'decoded': pin(root_raw),
                      'payload': base64.b64encode(zlib.compress(root_raw, 6)).decode()})
    put('ROOT-RECORDS.zlib.json', wrapper)
    add('ROOT-RECORDS.zlib.json', wrapper)
    add('prepare_mount.py', Path(__file__).read_bytes())
    status = {
        'previous_audit_commit': '9ae08c27ed16c4cfdbb51eb49332066fa3d75ce2',
        'production_main': 'f33d8da316de8fdf27b504371f1a5310997ff548',
        'PR889_product_head': '4b19af89a766593f7d5f1cc2db256e81aba7afcb',
        'whole_native': False, 'matching_current_source_cold': False, 'production_legacy_deleted': False,
        'R19': {'run': 43544318748, 'job': 132291881222, 'attempt': 1,
            'commit': 'd2a88992381c2c7ab680b7c97bb7c8405c02c6c1', 'status': 'SOURCE_FAIL',
            'complete': True, 'tests_run': 1411, 'distinct_passed': 1407, 'failures': 3, 'errors': 1,
            'skipped': 0, 'events': 2822, 'wall_seconds': 1104.457327131,
            'generators_each_run_twice': 139, 'AST_checks': 1572, 'original62': 'SKIPPED_0_EXECUTED',
            'source_files': 3175, 'source_bytes': 97961656,
            'actual_source_tree': 'd15d7a476fc3f711b2729236e84b7a9573da7a3d',
            'prepared_source_tree': 'ab0514765fc819b921557b9d857a9a13a1a4f48b',
            'generated_metadata_differences': 3, 'Root_complete_source_readback': 'PASS',
            'Root_ordered_ID_and_event_readback': 'PASS', 'original_R16_test_files_exact': 616,
            'HIA_assets_exact': 257, 'default_resources': 210, 'optional_assets': 8},
        'R19_custody': {'inner_archive_bytes': 111712316, 'inner_files': 5215, 'inner_directories': 1290,
            'binary_chunks_with_original_producer_ACK_full_GET': 214, 'Root_binary_connector_GET': 0,
            'Root_text_connector_GET': 24, 'Root_decoded_metadata_files': 40,
            'Root_decoded_metadata_bytes': 10456189, 'outer_ZIP_bytes': 344034257,
            'outer_ZIP_complete_Git_copy': False, 'originals_deleted': 0},
        'cleanup': {'original': '1_METHOD_2_SUBFAIL_PRESERVED', 'successor': '12_PASS',
            'all_events': 26, 'raw_files': 46, 'raw_bytes': 4964778, 'runtime': '3.14.4',
            'seconds': 180, 'cleanup_seconds': 3, 'actual_cleanup_complete_and_ECHILD': True,
            'Native_compile_VM_calls': 0, 'qualification_transferred_to_union': False},
        'R8': {'actual_unique_compile': True, 'image_bytes': 562746, 'R5_image_bytes': 552050,
            'growth_bytes': 10696, 'remaining_allowance_bytes': 4096, 'excess_bytes': 6600,
            'functions': 107, 'blocks': 1456, 'ops': 6664, 'actual_ops_growth': 138,
            'image_sha256': '2138fd3f57a76e3ac5ad00fee9d2b1a3e36c0af24395b7c491a772d788a3ab21',
            'packed': False, 'VM_executions': 0, 'semantic_qualified': False, 'adopted': False,
            'Git_custody_scope_here': 'FOUR_CORE_RECORDS_AND_INDEPENDENT_STATIC_REVIEW_NOT_FULL_RAW_ARCHIVE'},
        'owner_audit': {'execution_chains': 15, 'reviewed_files': 60, 'scope': 'ACTUAL_CALLERS_AND_PROVIDERS',
            'all3175_dynamic_graph_claimed': False, 'Python_CLI_worker_SQLite_and_inspect_remain': True},
        'successors': {'four_source_repair_packets_authored': True, 'combined_Source_execution': False,
            'additional_linux_process_test_pin_migration': 'AUTHORING_PENDING_SEPARATE_PACKET',
            'inspect_HIA_strategy_component': 'AUTHORING_ONLY_NOT_INTEGRATED'},
        'preserved_blockers': ['Current Source1411 failed with 3 failures and 1 error.',
            'Original62 did not run after Source failure.', 'Original Native35 failures and103 skipped later steps remain.',
            'Original R5 10M-fuel failure remains; R6/R7/R8 are not adopted.',
            'Current matching cold, full Native workflow, report and roundtrip qualification remain open.',
            'Hosted production owners and whole-development-stack retirement remain open.']}
    index = {'schema': 'hia.additive-audit-checkpoint.v118', 'collection': COLLECTION, 'status': status,
             'recipes': groups, 'root_records': pin(root_raw), 'root_record_files': len(records),
             'existing_object_leaves': leaves, 'final_collection_leaves': len(leaves) + 2,
             'previous_review_children_preserved': 62, 'previous_nonreview_root_children_preserved': 19}
    raw = encode(index); put('INDEX.json', raw); add('INDEX.json', raw)
    readme = '''# R19 完整失败结果与真实生产执行方审计

本检查点保留此前全部审计树。全量 HIA 原生闭环、当前源码冷启动资格、生产切换及旧生产整套删除均未完成。

## 正式结果

R19 是 commit d2a88992381c2c7ab680b7c97bb7c8405c02c6c1，run43544318748、job132291881222、attempt1。139个生成器各运行两次通过，1572项语法检查通过。完整1411项 Source 全部加载、开始、停止，2822条事件逐项对应；结果为1407项通过、3项失败、1项错误，0跳过，耗时1104.457327131秒。后续原62项因 Source 失败跳过，实际执行0项。

四处失败分别是：可选 roundtrip 源被按默认 Core profile 检查；sdist 测试支持清单少登记8个真实可选资源；portable 夹具未按全部12个默认资源角色构造；两个显式可选应用 provider 被误列为默认机制角色，造成54/56而非原54/54。四份精确后继源码包均保存，尚不继承任何组件通过结果。合并核对另发现 Linux process qualifier 固定了安装资源测试文件的原全文哈希，该调用方的严格版本迁移仍在独立作者阶段。

实际生成后源为3175文件、97,961,656字节、tree d15d7a476fc3f711b2729236e84b7a9573da7a3d。Root 完整复核了实际源的字节、模式、SHA和Git身份、全部Source事件及旧ID有序投影。相对准备树仅三个生成元数据文件不同。R19原616个旧Python测试文件及257个HIA资产保持原字节。即将合并的sdist修复会明确改变其中一个文件的支持tuple和注释；其原方法、断言和顺序保持精确，不把它继续称为全文不变。

## 完整证据与独立结果

原始111,712,316字节内层档案由214个已获原生产端ACK和完整GET的二进制块保存；档案含5215文件和1290目录。完整外层ZIP及内层成员CRC、字节、SHA、Git身份、模式及生产端receipt由专门读取器核验。Root另对全部24文本叶作完整GET，解码并逐字比对40份终态元数据、10,456,189字节。Root没有通过UTF8连接器读取二进制块；344,034,257字节外层ZIP本身仍保存于本地与原90日Actions artifact，并未声称已有完整Git副本。

report清理修复保留了原版本1个方法中的2个真实子失败；后继12个Source方法全部通过。两次均为实际CPython3.14.4、180秒加3秒清理，3175文件前后守卫一致，清理完整并观察到ECHILD；无Native编译或VM调用。46份完整原始记录及4,964,778逻辑字节已经封存并由Root逐项回读。此组件通过不代表合并版本或当前冷链通过。

R8只做过一次授权固定B3编译，实际image562,746字节，比R5增加10,696字节，超过当时4096字节剩余空间6600字节。它没有被打包、没有执行VM、没有语义资格，也未被采用。本检查点保存四份核心记录和独立静态复核；不声称已经包含其完整原始档案。旧R5的10M燃料失败保持不变。

## 全量重写尚未闭合的真实边界

请先阅读同目录 PRODUCTION-OWNER-AUDIT.md。它逐条追踪15条实际执行链，并附60个已检查文件的身份与源码证据。普通hia入口仍走Python CLI；worker/service/SQLite事务、inspect、部分patch/impact与对象/外部provider边界仍有真实Python执行方。已经存在的HIA编译、Core、VM、后端、stdio/process/file与发行策略是实做部分，但不能代替未通过的全部公开入口。外部Rust MCP运行时需要实际部署版本证据；开发编排、打包、测试与作者链也必须单独闭合，才能满足只保留全HIA整套的要求。

下一步是完成精确调用方迁移、合成修复、重跑完整Source与原62，再用同源码冷启动产物跑原生123步工作流。旧35项Native失败和103个后续跳过步骤、旧R5燃料失败、当前冷链及生产执行方退休条件全部继续保留。没有删除生产旧实现。
'''.encode()
    put('README.md', readme); add('README.md', readme)
    put('MOUNT-LEAVES.json', encode(leaves))
    new_files = []
    for name in ('ROOT-RECORDS.zlib.json', 'prepare_mount.py', 'PRODUCTION-OWNER-AUDIT.md', 'INDEX.json', 'README.md'):
        path = ROOT / name
        new_files.append({'path': name, 'local_path': str(path), 'mode': '100644', **pin(path.read_bytes())})
    put('PUBLICATION-INTENT.json', encode({'schema': 'hia.audit-metadata-publication.v118',
        'collection': COLLECTION, 'files': new_files, 'new_product_executions': 0,
        'previous_audit_commit': status['previous_audit_commit'], 'whole_native': False}))
    print(json.dumps({'collection': COLLECTION, 'leaves': len(leaves), 'recipes': len(groups),
        'root_record_files': len(records), 'root_record_bytes': sum(row['bytes'] for row in records.values()),
        'new_metadata_bytes': sum(row['bytes'] for row in new_files), 'whole_native': False}))


if __name__ == '__main__':
    main()
