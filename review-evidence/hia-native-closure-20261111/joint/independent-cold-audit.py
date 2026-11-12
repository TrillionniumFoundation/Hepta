"""Read-only independent replay of one retained HIA cold qualification.

Uses only Python's standard library. No project verification helper, compiler,
native image, ZIP receipt boolean, or prior audit substitutes for reading bytes.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import sys
import time
import zipfile


ROOT = Path('/workspace/scratch/e26ed3e2edcf')
REPO = ROOT / 'Hepta'
COLD = ROOT / 'joint-cold-r1/cold.json'
OUTPUT = ROOT / 'joint-cold-audit.json'
MANIFEST = 'HIA_ARCHIVE_MANIFEST.json'
FAMILIES = ('capacity', 'cfg', 'elf', 'chain', 'owned', 'bulk', 'loan',
            'resource', 'tail', 'select', 'effects', 'multi', 'keyword',
            'signed', 'scalar-casts', 'explicit-traps', 'cli', 'names', 'exports')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_read(path, *, keep=False):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'not an ordinary file: ' + str(path))
    digest, size, chunks = sha256(), 0, []
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), 'open race: ' + str(path))
        while raw := stream.read(1024 * 1024):
            digest.update(raw)
            size += len(raw)
            if keep:
                chunks.append(raw)
        require(identity(os.fstat(stream.fileno())) == identity(before), 'read race: ' + str(path))
    require(identity(path.lstat()) == identity(before), 'path changed: ' + str(path))
    require(size == before.st_size, 'extent changed: ' + str(path))
    return digest.hexdigest(), size, b''.join(chunks) if keep else None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON object key: ' + key)
        result[key] = value
    return result


def document(path):
    digest, size, raw = file_read(path, keep=True)
    return json.loads(raw, object_pairs_hook=unique_object), digest, size


def canonical_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_replay(base, pins):
    total = 0
    for name, expected in sorted(pins.items()):
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe source member')
        actual, size, _ = file_read(base / name)
        require(actual == expected, 'source mismatch: ' + str(base / name))
        total += size
    return {'files_read': len(pins), 'bytes_read': total, 'all_hashes_match': True}


def archive_replay(path, receipt, stage):
    before = identity(path.lstat())
    digest, compressed, _ = file_read(path)
    require(digest == receipt['archive_sha256'], 'ZIP compressed SHA mismatch: ' + str(path))
    require(compressed == receipt['packed_bytes'], 'ZIP packed extent mismatch')
    total = 0
    with path.open('rb') as held:
        require(identity(os.fstat(held.fileno())) == before, 'ZIP changed before open')
        with zipfile.ZipFile(held) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            require(len(names) == len(set(names)), 'duplicate ZIP member')
            require(MANIFEST in names, 'missing ZIP manifest')
            metadata = archive.getinfo(MANIFEST)
            require(0 <= metadata.file_size <= 32 << 20, 'oversize ZIP manifest')
            raw_manifest = archive.read(MANIFEST)
            require(len(raw_manifest) == metadata.file_size, 'manifest extent mismatch')
            manifest = json.loads(raw_manifest, object_pairs_hook=unique_object)
            require(manifest['schema'] == 'hepta.hia.lossless-evidence-archive.v1', 'manifest schema')
            require(manifest['source_directory'] == str(stage), 'manifest stage mismatch')
            require(canonical_digest(manifest) == receipt['manifest_sha256'], 'manifest SHA mismatch')
            files = manifest['files']
            require(set(names) == set(files) | {MANIFEST}, 'ZIP complete inventory mismatch')
            require(len(files) == receipt['files'] and len(files) <= 100000, 'ZIP file count mismatch')
            for info in infos:
                name = info.filename
                if name == MANIFEST:
                    continue
                relative = PurePosixPath(name)
                require(not relative.is_absolute() and '..' not in relative.parts,
                        'unsafe ZIP member: ' + name)
                require(not info.is_dir() and not (info.flag_bits & 1), 'directory/encrypted member')
                require(stat.S_ISREG(info.external_attr >> 16), 'nonregular ZIP payload')
                row = files[name]
                require(0 <= info.file_size <= 16 << 20 and info.file_size == row['bytes'],
                        'member extent: ' + name)
                require((info.external_attr >> 16) & 0o777 == row['mode'], 'member mode: ' + name)
                hasher, read_bytes = sha256(), 0
                with archive.open(info) as member:
                    while chunk := member.read(1024 * 1024):
                        hasher.update(chunk)
                        read_bytes += len(chunk)
                require(read_bytes == row['bytes'], 'member read extent: ' + name)
                require(hasher.hexdigest() == row['sha256'], 'member SHA: ' + name)
                total += read_bytes
            require(total == manifest['unpacked_bytes'] == receipt['unpacked_bytes'], 'archive total')
            require(total <= 512 << 20, 'archive total bound')
        require(identity(os.fstat(held.fileno())) == before, 'ZIP changed during member replay')
    after_digest, after_size, _ = file_read(path)
    require(identity(path.lstat()) == before and after_digest == digest and after_size == compressed,
            'ZIP changed after member replay')
    return {'archive': str(path), 'sha256': digest, 'manifest_sha256': receipt['manifest_sha256'],
            'packed_bytes': compressed, 'payload_members_read': len(files),
            'payload_uncompressed_bytes_read': total, 'manifest_member_bytes_read': len(raw_manifest),
            'complete_member_read_and_sha256_pass': True, 'mode_and_inventory_pass': True,
            'compressed_sha256_before_and_after_pass': True}


def main():
    started = time.monotonic_ns()
    audit = {'schema': 'hia.independent-joint-cold-audit.v1', 'status': 'FAIL',
             'audited_at_utc': datetime.now(timezone.utc).isoformat(),
             'audit_program': str(Path(__file__).resolve()),
             'audit_program_sha256': file_read(Path(__file__))[0],
             'auditor_python': platform.python_version(), 'cold_report': str(COLD),
             'project_verification_helpers_imported': False, 'native_execution_repeated': False,
             'whole_stack_native_completion_established': False}
    try:
        cold, cold_sha, _ = document(COLD)
        run = COLD.with_suffix('.cold')
        export = run / 'source'
        evidence = run / 'qualification.evidence'
        nested_path = Path(cold['nested_report'])
        require(nested_path == run / 'qualification.json', 'unexpected nested report path')
        nested, nested_sha, _ = document(nested_path)
        require(cold['nested_report_sha256'] == nested_sha, 'nested report SHA mismatch')
        require(cold['status'] == 'COLD_SELFHOST_REPLAY_PASS' and cold['returncode'] == 0, 'cold status')
        require(len(cold['checks']) == 11 and all(v is True for v in cold['checks'].values()), 'cold checks')
        require(nested['status'] == 'SELF_HOSTED_FIXED_CORE_PASS', 'nested status')
        require(len(nested['checks']) == 5049 and all(v is True for v in nested['checks'].values()), 'native checks')
        owner, owner_sha, _ = document(run / 'process-owner.json')
        require({**owner, 'receipt_sha256': owner_sha, 'supervisor_returncode': 0}
                == cold['process_owner'], 'process owner copy/receipt hash mismatch')
        require(owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
                and owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False
                and owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True,
                'owner completion/cleanup refusal')
        require(cold['qualification_wall_limit_seconds'] == owner['qualification_seconds'] == 180
                and cold['cleanup_wall_limit_seconds'] == owner['cleanup_seconds'] == 3, 'deadline changed')
        pins = cold['source_manifest']
        require(len(pins) == 575 and pins == nested['source_manifest'], 'source manifest mismatch')
        binding = canonical_digest(pins)
        current = source_replay(REPO, pins)
        exported = source_replay(export, pins)
        contract, contract_sha, _ = document(REPO / 'docs/HIA_SELFHOST_CORE_SUPPORT.json')
        require({**contract['source_identity']['files'], 'docs/HIA_SELFHOST_CORE_SUPPORT.json': contract_sha}
                == pins, 'declared current source inventory differs')
        require(cold['profile'] == nested['profile'] == contract['profile'], 'profile mismatch')
        tree = ast.parse((REPO / 'tools/hia_selfhost_contract.py').read_bytes())
        source_files = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                            and any(isinstance(t, ast.Name) and t.id == 'SOURCE_FILES' for t in n.targets))
        expected_sources = set(source_files) | {p.relative_to(REPO).as_posix() for p in (REPO/'hepta').rglob('*.py')}
        require(expected_sources == set(contract['source_identity']['files']), 'omitted/additional source inventory')
        chains = {}
        for key in ('generations', 'modified_generations'):
            require(len(nested[key]) == 3, 'wrong chain length')
            rows = []
            for index, record in enumerate(nested[key]):
                label = ('B' if key == 'generations' else 'M') + str(index + 1)
                require(record['case'] == label, 'generation order')
                path = Path(record['produced_image'])
                require(path == evidence / (label + '.image.bin'), 'generation path')
                digest, size, _ = file_read(path)
                require(digest == record['produced_sha256'] and size == record['produced_bytes'], 'image binding')
                require(record['status'] == 'returned' and record['abi_status'] == 0
                        and record['source_unchanged'] is True and not record['forbidden_compiler_modules_loaded'],
                        'generation receipt refusal')
                rows.append({'generation': label, 'sha256': digest, 'bytes': size})
            chains[key] = rows
        b = [row['sha256'] for row in chains['generations']]
        m = [row['sha256'] for row in chains['modified_generations']]
        require(b == cold['generation_sha256'] and m == cold['modified_generation_sha256'], 'outer chain mismatch')
        require(b[0] == b[1] == b[2] and m[0] != m[1] and m[1] == m[2] and m[2] != b[2], 'fixed points')
        index, index_sha, _ = document(evidence / 'phase-index.json')
        expected_phases = {(family, label) for family in FAMILIES for label in ('original', 'modified')}
        require(index['completed'] == 38 and index['exceptions'] == 0 and len(index['phases']) == 38,
                'phase count/status')
        seen, checks, pids, intervals, archives = set(), set(), set(), [], []
        archive_started = time.monotonic_ns()
        for phase in index['phases']:
            key = phase['family'], phase['compiler_label']
            require(key in expected_phases and key not in seen, 'duplicate/unknown phase')
            seen.add(key)
            require(phase['state'] == 'completed' and phase['report_status'] == 'PASS', 'phase incomplete')
            process, process_sha, _ = document(phase['process_receipt'])
            report, report_sha, _ = document(phase['report'])
            request, request_sha, _ = document(phase['request'])
            require(report_sha == process['report_sha256'], 'phase report hash')
            require(all((doc['family'], doc['compiler_label']) == key for doc in (request, process, report)), 'phase labels')
            require(report['status'] == 'PASS' and process['returncode'] == 0, 'phase did not pass')
            require(report['source_manifest_sha256'] == request['source_manifest_sha256'] == binding,
                    'phase source binding')
            require(report['input_sha256'] == {k: v['sha256'] for k, v in request['inputs'].items()}, 'phase input pins')
            for item in request['inputs'].values():
                require(file_read(Path(item['path']))[0] == item['sha256'], 'phase input bytes changed')
            require(report['input_sha256']['compiler'] == (b[2] if key[1] == 'original' else m[2]), 'phase compiler')
            require(report['fresh_host_oracle_process'] is True and report['successor_process_reuse'] is False,
                    'phase isolation declaration')
            require(report['worker_pid'] == process['worker_pid'] and report['worker_pid'] not in pids,
                    'phase PID reused/mismatched')
            pids.add(report['worker_pid'])
            phase_checks = report['checks']
            require(phase_checks and all(v is True for v in phase_checks.values())
                    and not (checks & set(phase_checks)), 'phase checks invalid/overlapping')
            require(all(nested['checks'].get(k) is v for k, v in phase_checks.items()), 'phase checks not merged')
            checks.update(phase_checks)
            start, end = process['started_monotonic_ns'], process['completed_monotonic_ns']
            require(start <= end <= process['archive_completed_monotonic_ns'], 'phase/archive ordering')
            intervals += [(start, 1), (end, -1)]
            receipt = process['raw_artifacts']
            stage = Path(request['directory'])
            require(stage == evidence / 'phase-runs' / ('-'.join(key)), 'unexpected phase stage')
            retained, _, _ = document(stage / 'ARCHIVED.json')
            require(receipt == retained, 'retained archive receipt differs')
            path = Path(receipt['archive'])
            require(path == stage.with_suffix('.zip'), 'unexpected archive path')
            row = archive_replay(path, receipt, stage)
            archives.append({**row, 'family': key[0], 'compiler': key[1],
                             'checks': len(phase_checks), 'report_sha256': report_sha,
                             'process_receipt_sha256': process_sha, 'request_sha256': request_sha})
        archive_elapsed = time.monotonic_ns() - archive_started
        require(seen == expected_phases, 'missing phase')
        active = peak = 0
        for _, change in sorted(intervals):
            active += change
            peak = max(peak, active)
        require(active == 0 and peak <= 2, 'oracle concurrency exceeds two')
        current_after = source_replay(REPO, pins)
        export_after = source_replay(export, pins)
        require(current_after == current and export_after == exported, 'source extent changed')
        require(file_read(COLD)[0] == cold_sha and file_read(nested_path)[0] == nested_sha
                and file_read(evidence/'phase-index.json')[0] == index_sha, 'reports changed during audit')
        audit.update(status='PASS', profile=cold['profile'], cold_report_sha256=cold_sha,
            nested_report_sha256=nested_sha, process_owner_sha256=owner_sha, phase_index_sha256=index_sha,
            qualification_wall_seconds=cold['wall_elapsed_ns']/1e9,
            cold_checks={'passed': 11, 'total': 11}, native_checks={'passed': 5049, 'total': 5049},
            cold_python=nested['seed']['python'],
            source={'manifest_entries': 575, 'manifest_sha256': binding, 'contract_sha256': contract_sha,
                    'current_repository': str(REPO), 'isolated_export': str(export),
                    'current_before': current, 'current_after': current_after,
                    'export_before': exported, 'export_after': export_after,
                    'full_declared_inventory_matches_current': True},
            compiler_images=chains, fixed_points={'B1_eq_B2_eq_B3': True,
                'M1_ne_M2': True, 'M2_eq_M3': True, 'M3_ne_B3': True,
                'all_six_image_files_actually_read_and_hashed': True},
            phases={'completed': 38, 'expected': 38, 'exceptions': 0,
                    'phase_checks': len(checks), 'unique_host_oracle_pids': len(pids),
                    'observed_peak_phase_processes': peak, 'source_and_input_pins_rehashed': True},
            archive_replay={'archives': 38, 'payload_members_read': sum(x['payload_members_read'] for x in archives),
                'manifest_members_read': 38,
                'all_zip_members_read': sum(x['payload_members_read'] for x in archives)+38,
                'payload_uncompressed_bytes_read': sum(x['payload_uncompressed_bytes_read'] for x in archives),
                'manifest_uncompressed_bytes_read': sum(x['manifest_member_bytes_read'] for x in archives),
                'all_zip_uncompressed_bytes_read': sum(x['payload_uncompressed_bytes_read']+x['manifest_member_bytes_read'] for x in archives),
                'packed_archive_bytes': sum(x['packed_bytes'] for x in archives),
                'every_member_independently_opened_and_fully_read': True,
                'every_payload_sha256_mode_size_and_inventory_verified': True,
                'compressed_hashes_checked_before_and_after_member_replay': True,
                'receipt_boolean_used_as_substitute_for_member_read': False,
                'project_archive_verification_helper_used': False,
                'payload_read_method': 'zipfile.ZipFile.open; read 1 MiB chunks through EOF; independent hashlib.sha256; CRC checked by zipfile',
                'elapsed_seconds_including_phase_report_and_input_checks': archive_elapsed/1e9,
                'per_archive': archives},
            process_completion={'owned_process_completed': True, 'exit_observed_before_180_seconds': True,
                'cleanup_complete_and_kernel_echild_observed': True,
                'historical_descendant_inventory_claimed_complete': owner['historical_descendant_inventory_complete']},
            scope={'establishes_retained_joint_cold_evidence_integrity': True,
                'reruns_native_qualification': False, 'establishes_downstream_application_suite_results': False,
                'establishes_github_ci_pass': False, 'establishes_whole_native_delivery': False})
    except Exception as exc:
        audit['error'] = {'type': type(exc).__name__, 'message': str(exc)}
    audit['audit_elapsed_seconds'] = (time.monotonic_ns() - started)/1e9
    with OUTPUT.open('x') as stream:
        json.dump(audit, stream, indent=2, sort_keys=True)
        stream.write('\n')
    summary = {key: audit.get(key) for key in ('status', 'error', 'profile', 'qualification_wall_seconds', 'audit_elapsed_seconds')}
    summary['output'] = str(OUTPUT)
    if audit['status'] == 'PASS':
        summary['archive_replay'] = {k: v for k, v in audit['archive_replay'].items() if k != 'per_archive'}
    print(json.dumps(summary, indent=2))
    return 0 if audit['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
