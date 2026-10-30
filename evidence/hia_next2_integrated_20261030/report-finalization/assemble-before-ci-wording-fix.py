"""Append validated evidence and documentation to the exact tested implementation."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT / 'hepta-integration'
OPS = ROOT / 'hia-next2-operations-20261030'
HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TREE = 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'
CONTRACT = '3ff0362f995c8341ab75fa32c19cc6bb9fc5d1bc1bbe932ab00d45409ef62faa'
DEST = REPO / 'evidence/hia_next2_integrated_20261030'


def read(path):
    return json.loads(path.read_bytes())


def identity(path):
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def copy_directory(source, target):
    if target.exists():
        raise ValueError('refuse existing delivery directory: ' + str(target))
    files = []
    for path in sorted(source.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or path.name.endswith('.partial'):
            raise ValueError('only complete regular evidence files may be copied')
        files.append((path.relative_to(source), identity(path), bool(info.st_mode & stat.S_IXUSR)))
    target.mkdir(parents=True)
    for relative, before, executable in files:
        origin, out = source / relative, target / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, out)
        if identity(origin) != before or identity(out) != before or bool(out.stat().st_mode & stat.S_IXUSR) != executable:
            raise ValueError('source or copied evidence changed')
    return {'source_directory': str(source), 'destination': target.relative_to(REPO).as_posix(),
            'files': len(files), 'bytes': sum(item['bytes'] for _, item, _ in files),
            'all_regular_bytes_and_owner_execute_bits_match': True}


def main():
    started = time.monotonic_ns()
    if DEST.exists() or (HERE / 'ASSEMBLY.json').exists():
        raise ValueError('refuse to overwrite an assembly attempt')
    sys.path.insert(0, str(REPO))
    from tools.qualify_hia_integrated import _source_state
    before = _source_state()
    if before['head'] != HEAD or before['tree'] != TREE or before['status'] or len(before['files']) != 6907:
        raise ValueError('exact clean tested source required')
    ci_dir = ROOT / 'hia-next2-ci-evidence-20261030'
    ci_all = read(ci_dir / 'VERIFY.json')
    ci = ci_all['runs']['953fa62']
    if (ci_all['passed'] is not True or ci_all['latest_required_source'] != HEAD
            or ci_all['latest_required_source_verified'] is not True or ci['head'] != HEAD
            or ci['tree'] != TREE or ci['all_eight_gates_passed'] is not True
            or ci['matrix_contract_sha256'] != CONTRACT or ci['matrix_tests'] != 527
            or ci['matrix_capabilities'] != 50):
        raise ValueError('official exact-source CI audit has not completed')
    pins = read(ci_dir / 'CI_PINS.json')['runs']['953fa62']
    resource = read(ROOT / 'p1-p2-scoped-cleanup-953-evidence-20261030/SUMMARY.json')
    cpp = read(ROOT / 'p3-p6-json-checkpoint-953fa62-evidence-20261030/SUMMARY.json')
    crc = read(ROOT / 'p4-p5-crc-linear-integrated-953fa62-evidence/VERIFICATION.json')
    p7_dir = ROOT / 'p7-v13-evidence-staging-20261030'
    p7, p7_readback = read(p7_dir / 'SUMMARY.json'), read(p7_dir / 'VERIFICATION.json')
    if (resource['source_head'] != HEAD or not resource['new_953_offline_readback_executed']
            or cpp['implementation_head'] != HEAD or not cpp['formal_collector_passed']
            or cpp['current_readback']['archive_independent_readback_returncode'] != 0
            or crc['source'] != HEAD or crc['passed'] is not True
            or p7['source_commit'] != HEAD or p7_readback['passed'] is not True):
        raise ValueError('missing final formal evidence or independent readback')
    if (crc['formal']['complete_cost_cold_gate_passed'] is not False
            or p7['calibration']['correct'] != 0 or p7['main']['generation_requests'] != 0):
        raise ValueError('observed negative outcomes differ from reviewed draft')
    for name in ('compiler-review.json', 'migration-review.json', 'optimization-review.json'):
        if not (OPS / 'reviews' / name).is_file():
            raise ValueError('missing report review')
    contract = read(REPO / 'docs/HIA_SAFETY_CONTRACT.json')
    canonical = json.dumps(contract, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if hashlib.sha256(canonical).hexdigest() != CONTRACT or any(contract['unproved_claims'].values()):
        raise ValueError('reviewed safety contract differs')
    report = (OPS / 'REPORT_DRAFT.zh.md').read_text()
    ci_text = f'''[最终实现的完整 GitHub CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41081527613)
已经 completed/success，job 为 `124151631902`。官方 artifact ID 为
`{pins['artifact_id']}`，ZIP {pins['bytes']:,} 字节，SHA-256 为
`{pins['sha256']}`。下载内容与官方摘要一致，独立 reader 已逐条核对
测试方法终态、Rust 结果块、矩阵、source/tool inventories 与四个 NDU 身份。

| 验收项 | 当前提交的实际结果 | 范围 |
| --- | --- | --- |
| Integrated gates | 8/8 passed | 工具和 Linux seals、四个原生 NDU 身份、Rust crate、完整回归和 critical coverage |
| Python discovery | {ci['python_tests']:,} 个不同方法；0 failures/errors/skips | 外层进程 {ci['python_process_seconds']:.9f} 秒 |
| Rust crate | {ci['rust_tests']} 个测试、{len(ci['rust_binary_footers'])} 个完整结果块；0 failures/ignored/filtered | 实际固定编译器与 locked/offline 依赖 |
| Canonical safety matrix | {ci['matrix_tests']}/{ci['matrix_tests']} selectors、{ci['matrix_capabilities']}/{ci['matrix_capabilities']} capabilities | 实际矩阵 {ci['matrix_wall_ns']/1e9:.9f} 秒；属于 full discovery 子集 |
| Critical coverage | {ci['critical_groups']} groups、{ci['critical_modules']} unique modules、{ci['critical_methods']:,} unique methods | full discovery 的精确子集，不加分母 |
| 输入身份 | {ci['tracked_source_files']:,} 个源码文件、{ci['external_files']} 项外部输入前后一致 | 源 tree/blob/mode 与记录的实际工具身份 |

Workflow 的替代 profile 和仅失败时上传步骤存在条件性 skip；上述零 skips
指实际测试结果。CI 不重跑完整经济研究或真实模型生成，也不改变它们的
负结果。四个 NDU 身份 probe 不等于新的算法增量实验。'''
    evidence_text = '''| 证据 | 仓库入口 |
| --- | --- |
| 同提交官方 CI、完整方法/矩阵与独立读回 | [hia_next2_ci_20261030](../evidence/hia_next2_ci_20261030/README.md) |
| Rust 清理：953 正式包与独立 3533/development 历史包 | [hia_next2_resource_20261030](../evidence/hia_next2_resource_20261030/README.md) |
| C++ 检查点、原始 Git 对象、两版故障与历史 reader 失败 | [hia_next2_cpp_checkpoint_20261030](../evidence/hia_next2_cpp_checkpoint_20261030/ARCHIVE_README.md) |
| CRC 全部样本、负对照、成本、四版源码和 reader 失败 | [hia_next2_crc_linear_20261030](../evidence/hia_next2_crc_linear_20261030/README.md) |
| V13 模型输出、实际 wire/GBNF、SSE 用量和 main 拒绝 | [hia_next2_agent_v13_20261030](../evidence/hia_next2_agent_v13_20261030/README.md) |
| 总账、报告审查、集成测试和源码发布回执 | [hia_next2_integrated_20261030](../evidence/hia_next2_integrated_20261030/README.md) |'''
    report = report.replace('@@CI_ACTUAL@@', ci_text).replace('@@P0_CI_STATUS@@',
        '本轮声明的候选收敛、精确源码验收与实现发布条件已闭合').replace('@@EVIDENCE_INDEX@@', evidence_text)
    if '@@' in report:
        raise ValueError('unresolved report placeholder')
    plans = [
        ('p1-p2-scoped-cleanup-953-evidence-20261030', 'evidence/hia_next2_resource_20261030/final-953'),
        ('p1-p2-scoped-cleanup-3533-evidence-20261030', 'evidence/hia_next2_resource_20261030/history-3533'),
        ('p3-p6-json-checkpoint-953fa62-evidence-20261030', 'evidence/hia_next2_cpp_checkpoint_20261030'),
        ('p4-p5-crc-linear-integrated-953fa62-evidence', 'evidence/hia_next2_crc_linear_20261030'),
        ('p7-v13-evidence-staging-20261030', 'evidence/hia_next2_agent_v13_20261030'),
        ('hia-next2-ci-evidence-20261030', 'evidence/hia_next2_ci_20261030'),
    ]
    copies = [copy_directory(ROOT / source, REPO / target) for source, target in plans]
    DEST.mkdir(parents=True)
    copies.append(copy_directory(OPS, DEST / 'operations'))
    copies.append(copy_directory(ROOT / 'compiler-next2-readonly-reviews-20261030', DEST / 'cross-phase-readonly-reviews'))
    publication = DEST / 'implementation-publication'
    publication.mkdir()
    for path in sorted((ROOT / 'hia-github-publication-20261030').iterdir()):
        if path.is_file() and any(short in path.name for short in ('953fa62', '3533b95')):
            shutil.copy2(path, publication / path.name)
    for name in ('prepare_exact_transfer.py', 'restore-f7cc872.py', 'hepta-object-transfer-f7cc872.yml'):
        shutil.copy2(ROOT / 'hia-github-publication-20261030' / name, publication / name)
    for name in ('assemble_delivery.py', 'verify_delivery.py', 'build_delivery_zip.py'):
        shutil.copy2(HERE / name, DEST / name)
    (REPO / 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md').write_text(report)
    (REPO / 'evidence/hia_next2_resource_20261030/README.md').write_text(
        '# Rust scoped cleanup: separate execution identities\n\n'
        'The current qualification is [final-953](final-953/README.md). '
        '[history-3533](history-3533/README.md) preserves the earlier whole-source execution '
        'and all development inputs, failed controls and old/new executed CLI bytes. '
        'Both are self-contained inert archives with independent manifests and readers. '
        'Their test/observation denominators and source identities must not be combined.\n')
    result = {
        'schema': 'hepta.hia.next2.strict-results.v1',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'implementation': {'commit': HEAD, 'tree': TREE, 'tracked_files': 6907,
            'branch': 'work/hia-p0-p7-integrated-20261030',
            'full_CI_and_current_formal_records_bind_this_commit': True},
        'delivery': {'parent': HEAD, 'branch': 'delivery/hia-p0-p7-953fa62-20261030',
            'scope': 'additive inert evidence and documentation only', 'qualified_as_new_execution_commit': False},
        'all_P0_P7_strict_conditions_met': False,
        'ci': ci,
        'stages': {
            'P0': {'status': 'closed_within_declared_candidate_scope', 'strict_gate_met_within_declared_scope': True,
                   'same_implementation_commit': HEAD, 'historical_results_relabelled': False},
            'P1': {'status': 'finite_abort_cleanup_added_and_observed', 'strict_full_condition_met': False,
                   'profile': resource['profile'], 'counts': resource['actual_counts'],
                   'all_observed_postcleanup_ledgers_zero': True, 'boundaries': resource['boundaries'],
                   'remaining': resource['strict_stages']['P1_resource_proof_chain']['remaining']},
            'P2': {'status': 'explicit_finite_Rust_profile_authoritative', 'strict_full_condition_met': False,
                   'default_source_nominal_native_authority_switched': False,
                   'remaining': resource['strict_stages']['P2_Rust_authority']['remaining']},
            'P3': {'status': 'fixed_CPP_checkpoint_reconstruction_observed', 'strict_full_condition_met': False,
                   'counts': cpp['counts'], 'scope': cpp['scope'],
                   'remaining': ['general C/C++ safe rewrite', 'general hardware ABI',
                       'long-term upstream maintenance', 'complete measured human/agent development cost']},
            'P4': {'status': 'complete_negative_cost_inclusive_observation', 'strict_full_condition_met': False,
                   'counts_and_costs': crc['formal'], 'performance_timing_qualified': False,
                   'remaining': ['valuable real application hotspots with positive necessary-cost-inclusive benefit']},
            'P5': {'status': 'NDU_independent_increment_not_established', 'strict_full_condition_met': False,
                   'current_NDU_decisions': 0, 'current_controls': 'six strong fixed candidates and known-polynomial static dispatch',
                   'historical_feedback_DP_NDU_results_reexecuted_here': False,
                   'remaining': ['exceed strong fixed, feedback greedy and light planning with matched information, budget and cache']},
            'P6': {'status': 'bounded_parent_checkpoint_preservation_and_reconstruction', 'strict_full_condition_met': False,
                   'foreign_SIGABRT_reclassified_as_in_process_recovery': False,
                   'remaining': ['general active calls', 'arbitrary foreign callbacks', 'general state migration',
                       'reclamation and failure recovery', 'external side-effect rollback']},
            'P7': {'status': 'real_model_calibration_failed_main_refused', 'strict_full_condition_met': False,
                   'capacity': p7['capacity'], 'calibration': p7['calibration'], 'main': p7['main'],
                   'adaptive_same_task_followup': True, 'independent_new_task_holdout': False,
                   'AI_development_or_maintenance_advantage_proved': False,
                   'remaining': ['model prerequisite qualification', 'independent real development/maintenance comparison against mature workflows']},
        },
        'unproved_claims': contract['unproved_claims'],
        'costs': {'resource': resource['cost'], 'CPP': cpp['costs'], 'CRC': crc['formal'], 'P7': p7['costs'],
                  'nested_intervals_or_overlapping_test_denominators_additive': False,
                  'full_human_and_agent_development_review_cost': None, 'unknown_treated_as_zero': False},
        'historical_failures_preserved': True, 'old_results_relabelled_as_current': False,
        'archived_payload_execution_added_by_delivery': False,
        'evidence_readback_grants_program_admission': False,
    }
    save(DEST / 'RESULT.json', result)
    (DEST / 'README.md').write_text(
        '# HIA next2 exact-source evidence delivery\n\n'
        'Tested implementation: `' + HEAD + '`; tree `' + TREE + '`. '
        'This child only adds documentation and inert evidence. All original tracked bytes and owner execute modes are preserved.\n\n'
        'See [the complete Chinese report](../../docs/HIA_NEXT2_STRICT_RESULTS_20261030.md) '
        'and [machine-readable results](RESULT.json). P0 candidate convergence is qualified within the declared scope; '
        'P1/P2/P3/P6 remain finite extensions, P4 cold benefit is false, P5 NDU increment is unestablished, '
        'and V13 model qualification is 0/3 with actual pre-engine main refusal. '
        'No full-language safety, universal C++ rewrite, global optimality, Rust superiority or AI productivity claim is promoted.\n\n'
        'Current and historical source identities, failed experiments, reader failures, exact costs and unknown costs are separate. '
        'Package readers are bounded offline consistency checks and never confer execution authority. '
        'DELIVERY_FILES.json binds all added files except itself; its external SHA is supplied in the final archive/publication receipt.\n')
    save(DEST / 'REPORT_REVIEW_RESOLUTION.json', {
        'schema': 'hepta.hia.next2.report-review-resolution.v1',
        'report': identity(REPO / 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md'),
        'resolutions': [
            '3533 had only P1/P2 and P3/P6 executions; CRC full economics and V13 model stages first executed on953.',
            'The protocol permits at most three submissions per cell; all three calibration cells actually used three.',
            'Rust cleanup follows child-to-parent loans then owners, with formal witnesses accounted separately.',
            'Unsupported or not conservatively bounded resource scopes refuse; scalar Unknown does not imply blanket refusal.',
            'Current CRC dispatch is static from known polynomials; feedback/DP/NDU comparisons remain historical.',
            'Cost-prefix repair applies to completed native deliveries before evidence writes, not preparation differential counting.',
            'CRC preparation cases have aggregate receipts and product identities, not invented per-case raw transcripts.',
            'Final CI rows are filled only from the completed official artifact and successful bounded audit.',
        ],
        'formal_records_or_source_changed_by_report_edits': False,
    })
    git_rows = subprocess.check_output(['git', '--no-replace-objects', 'ls-tree', '-r', '-z', HEAD], cwd=REPO).split(b'\0')
    for row in git_rows:
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = REPO / name.decode()
        raw = path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if kind != b'blob' or actual != oid.decode() or bool(path.stat().st_mode & stat.S_IXUSR) != (mode == b'100755'):
            raise ValueError('original implementation byte/mode changed during additive assembly')
    assembly = {'schema': 'hepta.hia.next2.additive-assembly.v1', 'implementation': HEAD,
        'tree': TREE, 'all_6907_original_files_and_owner_execute_modes_unchanged': True,
        'copies': copies, 'report': identity(REPO / 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md'),
        'native_model_or_test_execution_performed': False, 'wall_ns': time.monotonic_ns() - started}
    save(HERE / 'ASSEMBLY.json', assembly)
    save(DEST / 'ASSEMBLY.json', assembly)
    files = []
    for directory in sorted((REPO / 'evidence').glob('hia_next2_*')):
        for path in sorted(directory.rglob('*')):
            if path.is_file():
                files.append({'path': path.relative_to(REPO).as_posix(), **identity(path)})
    report_path = REPO / 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md'
    files.append({'path': report_path.relative_to(REPO).as_posix(), **identity(report_path)})
    save(DEST / 'DELIVERY_FILES.json', {'schema': 'hepta.hia.next2.delivery-files.v1',
        'implementation': HEAD, 'files': sorted(files, key=lambda x: x['path']),
        'total_bytes': sum(f['bytes'] for f in files), 'manifest_itself_excluded': True})
    print(json.dumps({'implementation': HEAD, 'added_files_except_manifest': len(files),
        'added_bytes_except_manifest': sum(f['bytes'] for f in files),
        'manifest': identity(DEST / 'DELIVERY_FILES.json'), 'all_strict_stages_closed': False}))


if __name__ == '__main__':
    main()
