"""One sequential consumer of ten existing evidence artifacts. No product code."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parent.parent
def load(name):
    spec = importlib.util.spec_from_file_location('full32_stream_' + name, ROOT / 'control' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
io = load('local_io')
formats = load('stream_format')

def document(path, maximum=16 << 20):
    pin, raw = io.seal(path, maximum, body=True)
    return io.json_value(raw), pin, raw

def input_records(policy, deadline=None):
    actual = {}
    for name, pin in policy['inputs'].items():
        path = ROOT / name
        value = io.seal(path, 64 << 20, deadline=deadline)
        io.require(value['bytes'] == pin['bytes'] and value['sha256'] == pin['sha256'],
                   'frozen local reader input changed')
        actual[name] = value
    return actual

def bind_historical(policy):
    final, _, final_raw = document(ROOT / 'inputs/receiver-final.original.json')
    previous, _, _ = document(ROOT / 'inputs/worker.original.json')
    guardian, _, _ = document(ROOT / 'inputs/current--guard--guardian.json')
    config, _, _ = document(ROOT / 'inputs/current--guard--request.json')
    context, _, _ = document(ROOT / 'inputs/current--context.json')
    life = guardian['lifecycle']; cleanup = life.get('cleanup', {})
    io.require(final['status'] == previous['status'] == 'FULL_ZIP_CUSTODY_HOLD'
               and final['artifact'] == previous['artifact'] == policy['original_artifact']
               and final['closed_echild'] is True and final['source_inputs_preserved'] is True,
               'historical actual result or artifact identity differs')
    io.require(context['run_id'] == policy['receiver']['run_id'] and context['run_attempt'] == 1
               and context['actual_workflow_commit'] == policy['receiver']['head']
               and context['policy_sha256'] == policy['receiver']['policy_sha256']
               and guardian['schema'] == 'hepta.hia.external-qualification-guardian.v1'
               and guardian['command'] == config['command'] and guardian['cwd'] == config['cwd']
               and guardian['external_controller_seconds'] == config['controller_seconds'] == 900
               and life['qualification_seconds'] == 900 and life['cleanup_seconds'] == 3
               and guardian['source_identities_before'] == config['source_identities'] == guardian['source_identities_after']
               and guardian['input_identity_preserved'] is True
               and guardian['lifecycle_implementation_sha256'] == policy['lifecycle_implementation_sha256'],
               'historical original guardian/config identity differs')
    io.require(life.get('subreaper_enabled') is True and life.get('event_overflow') is False
               and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
               and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
               and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
               and life.get('returncode') == 1 and life.get('exit_observed_before_deadline') is True
               and life.get('timed_out') is False and life.get('interrupted_signals') == []
               and life.get('owner_error') is None
               and not any(x.get('kind') == 'owned_child_sigkill' for x in life.get('events', [])),
               'historical failure was not the bound natural nonzero closure')
    io.require(previous['partition']['encoding'] == 'INDEPENDENT_SINGLE_GZIP_STREAM_PER_FIXED_RAW_RANGE'
               and previous['partition']['exact_contiguous_partition'] is True
               and previous['partition']['total_bytes'] == policy['original_artifact']['bytes']
               and previous['partition']['concatenated_sha256'] == policy['original_artifact']['sha256'],
               'original range seal or complete denominator differs')
    return final, final_raw, previous

class Parts:
    def __init__(self, policy, references, operation, budget, deadline, final, final_raw, report):
        self.policy, self.references, self.operation, self.budget = policy, references, operation, budget
        self.deadline, self.final, self.final_raw, self.report = deadline, final, final_raw, report
        self.complete = []
    def chunks(self):
        for item, reference in zip(self.policy['parts'], self.references):
            ordinal = item['ordinal']
            self.report['current_part'] = ordinal
            directory = self.operation / ('part-%02d' % ordinal)
            directory.mkdir(mode=0o700)
            row = {'ordinal': ordinal, 'artifact': item['artifact'], 'expected_range': item['range'],
                   'status': 'HOLD', 'members': [], 'gzip': {}, 'temporary_original_deleted': False}
            successful = False
            try:
                path, row['download'] = io.download(reference['url'], item['artifact'], directory, self.budget, self.deadline)
                before = path.lstat()
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as original:
                    io.require(io.ident(os.fstat(original.fileno())) == io.ident(before), 'downloaded part open identity differs')
                    with zipfile.ZipFile(original) as archive:
                        infos = archive.infolist()
                        io.require(14 <= len(infos) <= 16 and len({x.filename for x in infos}) == len(infos),
                                   'part original directory population differs')
                        by_name = {x.filename: x for x in infos}
                        control_names = ['controls/' + x['name'].replace('/', '--') for x in self.final['captured_controls']]
                        regular = {x.filename for x in infos if not x.is_dir()}
                        required = set(control_names) | {'FINAL.json', 'PART.json', 'unverified-range.bin.gz'}
                        io.require(regular == required and len(regular) == 14
                                   and all(x.filename == 'controls/' and x.file_size == 0 for x in infos if x.is_dir())
                                   and sum(x.file_size for x in infos) <= 320 << 20,
                                   'fixed complete part-member set differs')
                        for info in infos:
                            formats.safe_name(info.filename)
                            io.require(info.flag_bits & (1 | 0x40 | 0x2000) == 0
                                       and info.compress_type in (0, 8)
                                       and (info.external_attr >> 16) & 0o170000 in (0, 0o100000, 0o040000),
                                       'part encryption/type/compression refused')
                        for info in infos:
                            if info.filename == 'unverified-range.bin.gz':
                                continue
                            io.check_deadline(self.deadline)
                            io.require(info.file_size <= 3 << 20, 'part control whole-file bound exceeded')
                            with archive.open(info) as source:
                                raw = source.read((3 << 20) + 1)
                            io.require(len(raw) == info.file_size, 'part complete control body length differs')
                            record = {'name': info.filename, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                      'crc32': '%08x' % info.CRC, 'whole_body_read': True}
                            if info.filename == 'FINAL.json':
                                io.require(raw == self.final_raw, 'all ten original FINAL byte copies must match small artifact')
                            elif info.filename == 'PART.json':
                                part = io.json_value(raw)
                                io.require(part['schema'] == 'hia.v88-original-zip-part.v1'
                                           and part['artifact'] == self.policy['original_artifact']
                                           and part['expected'] == item['range']
                                           and part['observed'] == self.final['parts'][ordinal]
                                           and part['status'] == self.final['status']
                                           and part['run_id'] == self.policy['receiver']['run_id'] and part['run_attempt'] == 1
                                           and part['workflow_commit'] == self.policy['receiver']['head']
                                           and part['control_commit'] == self.policy['receiver']['control_commit']
                                           and part['policy_sha256'] == self.policy['receiver']['policy_sha256']
                                           and part['qualification_executed'] is False, 'PART current carrier/range binding differs')
                            elif info.filename in control_names:
                                name = info.filename.removeprefix('controls/')
                                _, expected_raw = io.seal(ROOT / 'inputs' / ('current--' + name), 8 << 20, body=True)
                                io.require(raw == expected_raw, 'original copied receiver control bytes differ')
                            io.create(directory / (info.filename.replace('/', '--') or 'directory'), raw,
                                      raw=True, budget=self.budget)
                            row['members'].append(record)
                        info = by_name['unverified-range.bin.gz']
                        io.require(info.file_size == item['gzip']['bytes'], 'whole compressed range size differs')
                        with archive.open(info) as source:
                            yield from formats.gzip_chunks(source,
                                compressed_bytes=item['gzip']['bytes'], compressed_sha256=item['gzip']['sha256'],
                                raw_limit=item['range']['bytes'], raw_bytes=item['range']['bytes'],
                                raw_sha256=item['raw_sha256'], state=row['gzip'],
                                check=lambda: io.check_deadline(self.deadline))
                        io.require(row['gzip'].get('complete') is True, 'whole range stream did not complete')
                        row['members'].append({'name': info.filename, 'bytes': info.file_size,
                            'sha256': row['gzip']['compressed_sha256'], 'crc32': '%08x' % info.CRC,
                            'whole_body_read': True, 'raw_bytes': row['gzip']['raw_bytes'],
                            'raw_sha256': row['gzip']['raw_sha256']})
                    io.require(io.ident(os.fstat(original.fileno())) == io.ident(before), 'part changed during complete member read')
                after = io.seal(path, 320 << 20, deadline=self.deadline)
                io.require(after['identity'] == io.ident(before) and after['bytes'] == item['artifact']['bytes']
                           and after['sha256'] == item['artifact']['sha256'] and len(row['members']) == len(infos),
                           'part full post-read transport seal/member count differs')
                row['post_read_transport'] = after
                row['status'] = 'PART_FULL_PHYSICAL_READ_ONLY'
                io.create(directory / 'PART-READBACK.json', row, budget=self.budget)
                # Independent artifact-level proof is durable before releasing its
                # temporary local ZIP. This is not a complete original-ZIP claim.
                if ordinal < 9:
                    io.dispose_verified_temporary(path, after, directory, self.budget)
                    row['temporary_original_deleted'] = True
                self.complete.append(row)
                successful = True
            except BaseException as error:
                row['status'] = 'HOLD'; row['error'] = io.safe_error(error)
                if type(error) is formats.Refusal:
                    row['error']['fixed_refusal'] = str(error)
                raise
            finally:
                # On failure the current whole or partial official file remains.
                row['completed_before_cleanup'] = successful
                io.create(directory / 'PART-ATTEMPT-TERMINAL.json', row, budget=self.budget)
        self.report['current_part'] = None

def main():
    policy, policy_pin, _ = document(ROOT / 'POLICY.json')
    io.require(len(sys.argv) == 3 and sys.argv[1] == '--provider-references', 'fixed provider-reference argument required')
    refs_path = Path(sys.argv[2])
    io.require(str(refs_path) == policy['provider_references_path'], 'private reference path differs')
    refs_pin, private_raw = io.seal(refs_path, 65536, body=True)
    io.require(refs_pin['identity'][3] == os.geteuid() and stat.S_IMODE(refs_pin['identity'][2]) == 0o600,
               'provider references must remain private')
    refs = io.json_value(private_raw)
    references = refs['parts']
    io.require(refs['schema'] == 'hia.full32.ten-official-provider-references.v1'
               and refs['receiver_run_id'] == policy['receiver']['run_id']
               and len(references) == 10
               and [x['ordinal'] for x in references] == list(range(10))
               and [x['artifact_id'] for x in references] == [x['artifact']['id'] for x in policy['parts']],
               'exact ten ordered provider references required')
    for item in references:
        io.require(set(item) == {'ordinal', 'artifact_id', 'url'}, 'private provider reference fields differ')
        io.provider_host(item['url'])
    operation = Path(policy['operation_root'])
    io.require(operation.is_dir() and stat.S_IMODE(operation.lstat().st_mode) == 0o700
               and operation.lstat().st_uid == os.geteuid(), 'fresh private operation directory required')
    for name in ('captured-originals', 'readback'):
        (operation / name).mkdir(mode=0o700)
    budget = io.Budget(operation, policy)
    began = time.monotonic(); deadline = began + policy['limits']['worker_seconds']
    report = {'schema': 'hia.full32.ten-range-stream-consumer.v1', 'status': 'HOLD',
              'started_monotonic': began, 'deadline_monotonic': deadline,
              'policy': policy_pin, 'historical_receiver_status': 'FULL_ZIP_CUSTODY_HOLD',
              'historical_full32_status': 'HOLD', 'historical_results_reclassified': False,
              'new_product_execution': False, 'project_code_imported': False,
              'full_original_ZIP_saved_locally': False, 'all_ten_provider_bytes_permanently_retained_locally': False,
              'original_bytes_or_compression_changed': False, 'all_parts_complete': False,
              'all_original_ZIP_members_physically_read': False, 'all_inner_members_physically_read': False,
              'captured_originals': [], 'errors': [], 'progress': {}, 'provider_references':
                  {'path': str(refs_path), 'bytes': refs_pin['bytes'], 'sha256': refs_pin['sha256'],
                   'content_never_published': True}}
    outer = io.Journal(operation / 'readback/OUTER-ACTUAL.jsonl', budget, 4 << 20)
    inner = io.Journal(operation / 'readback/INNER-ACTUAL.jsonl', budget, 32 << 20)
    parts = None; chunks = None
    try:
        before = input_records(policy, deadline)
        io.create(operation / 'INPUTS-BEFORE.json', before, budget=budget)
        previous_final, final_raw, previous_worker = bind_historical(policy)
        directory, _, _ = document(ROOT / 'inputs/directory.original.json')
        inventory, _, _ = document(ROOT / 'inputs/outer-inventory.original.json')
        _, catalog_raw = io.seal(ROOT / 'inputs/typed-catalog.original.json', 16 << 20, body=True)
        custody, _, _ = document(ROOT / 'inputs/custody.original.json')
        expected_captures = {x['path']: x for x in policy['capture_whole_originals']}
        captures_seen = set()
        def capture(name, row):
            if name not in expected_captures:
                return None
            wanted = expected_captures[name]
            io.require(name not in captures_seen and row['bytes'] == wanted['bytes'] and row['sha256'] == wanted['sha256'],
                       'fixed omitted-original pin differs')
            captures_seen.add(name)
            return io.OriginalCapture(operation / 'captured-originals' / wanted['local_name'], wanted,
                                      budget, deadline, report['captured_originals'])
        def consume(name, body, expected):
            if name == formats.TAR_NAME:
                report['inner'] = formats.inner_tar(body, catalog_raw, custody, inner.add, capture,
                    report['progress'], check=lambda: io.check_deadline(deadline))
            else:
                while body.read(formats.CHUNK):
                    io.check_deadline(deadline)
        parts = Parts(policy, references, operation, budget, deadline, previous_final, final_raw, report)
        chunks = parts.chunks()
        original = formats.ChunkReader(chunks, policy['original_artifact']['bytes'], lambda: io.check_deadline(deadline))
        report['outer'] = formats.original_zip(original, directory, inventory, consume, outer.add, report['progress'])
        io.require(original.count == policy['original_artifact']['bytes']
                   and original.digest.hexdigest() == policy['original_artifact']['sha256']
                   and [x['ordinal'] for x in parts.complete] == list(range(10)),
                   'complete original ZIP or ten-part aggregate seal differs')
        io.require(captures_seen == set(expected_captures) and len(report['captured_originals']) == 2
                   and report['inner']['whole_original_namespace_complete'] is True
                   and report['inner']['TAR_members'] == policy['expected_inner']['members']
                   and report['inner']['regular_files'] == policy['expected_inner']['regular_files']
                   and report['inner']['regular_bytes'] == policy['expected_inner']['regular_bytes'],
                   'all actual typed body reads or selected whole originals incomplete')
        after = input_records(policy, deadline)
        io.create(operation / 'INPUTS-AFTER.json', after, budget=budget, deadline=deadline)
        io.require(before == after, 'reader frozen inputs changed')
        report.update(all_parts_complete=True, all_original_ZIP_members_physically_read=True,
                      all_inner_members_physically_read=True, source_inputs_preserved=True,
                      status='COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32')
    except BaseException as error:
        report['status'] = 'HOLD'; item = io.safe_error(error)
        if type(error) is formats.Refusal:
            item['fixed_refusal'] = str(error)
        report['errors'].append(item)
    finally:
        if chunks is not None:
            try:
                chunks.close()
            except BaseException as error:
                report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
        report['parts'] = [] if parts is None else parts.complete
        for journal, key in ((outer, 'outer_actual_records'), (inner, 'inner_actual_records')):
            try:
                report[key] = journal.finish(deadline if report['status'] == 'COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32' else None)
            except BaseException as error:
                report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
        try:
            io.check_deadline(deadline)
            report['elapsed_seconds'] = time.monotonic() - began
            io.require_elapsed(report['elapsed_seconds'], 720)
        except BaseException as error:
            report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
            report['elapsed_seconds'] = time.monotonic() - began
        report['storage_budget'] = {'metadata_reserved': budget.metadata_reserved,
            'metadata_written': budget.metadata_written, 'original_reserved': budget.original_reserved,
            'original_written': budget.original_written}
        try:
            io.create(operation / 'WORKER-RESULT.json', report, budget=budget,
                      deadline=deadline if report['status'] == 'COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32' else None)
            if report['status'] == 'COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32':
                io.check_deadline(deadline)
        except BaseException as error:
            report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
            report['elapsed_seconds'] = time.monotonic() - began
            # Preserve a late failed publication separately; do not overwrite
            # an already-created result or let it authorize a successful exit.
            io.create(operation / 'WORKER-FINALIZATION-HOLD.json', report, budget=budget)
    print(json.dumps({'status': report['status'], 'parts_complete': len(report['parts']),
                      'historical_receiver_status': report['historical_receiver_status'],
                      'original_product_results_changed': False, 'output': str(operation)}))
    return 0 if report['status'] == 'COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32' and not report['errors'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
