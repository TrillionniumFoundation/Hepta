"""Read and seal the one completed compiler-pair diagnostic, without execution."""
from pathlib import Path
from hashlib import sha256
import io
import json
import os
import stat
import tarfile

ROOT = Path(__file__).resolve().parent
RUN = Path('/tmp/hia-publication-compiler-pair-v85-r1')
OUT = ROOT / 'compiler-pair-actual-r1'
config = json.loads((ROOT / 'compiler-pair-control-r2/CONFIG.json').read_bytes())
pre = json.loads((ROOT / 'compiler-pair-control-r2/PREEXEC.json').read_bytes())
checks = []
def check(name, value):
    checks.append({'name': name, 'passed': bool(value)})
    if not value:
        raise ValueError(name)
def digest(raw):
    return sha256(raw).hexdigest()
def read(path):
    before = path.lstat()
    check('regular no-symlink original:' + str(path), stat.S_ISREG(before.st_mode))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(fd)
        check('held leaf identity:' + str(path), held == before)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read()
        check('original unchanged:' + str(path), os.fstat(fd) == held and path.lstat() == held and len(raw) == held.st_size)
    finally:
        os.close(fd)
    return raw

owner_raw = read(RUN / 'owner.json'); owner = json.loads(owner_raw); cleanup = owner['cleanup']
check('closed before reading child data', cleanup['complete'] and cleanup['observed_echild'] and
      cleanup['leader_reaped'] and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == [] and
      not cleanup['deadline_exceeded'])
check('natural diagnostic owner, no cleanup signals', owner['status'] == 'OWNED_PROCESS_COMPLETED' and
      owner['returncode'] == 0 and not owner['timed_out'] and owner['exit_observed_before_deadline'] and
      not owner['event_overflow'] and owner['interrupted_signals'] == [] and owner.get('owner_error') is None and
      owner['subreaper_enabled'] and len(owner['events']) == 4 and
      [event['kind'] for event in owner['events']] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'])
request_raw = read(RUN / 'owner.json.request.json'); request = json.loads(request_raw)
final = json.loads(read(RUN / 'FINAL.json')); worker_raw = read(RUN / 'worker/REPORT.json'); worker = json.loads(worker_raw)
check('actual request and returned receipt', owner['request_sha256'] == digest(request_raw) and
      final['owner_returned'] == dict(owner, supervisor_returncode=0, receipt_sha256=digest(owner_raw)) and
      request['command'] == final['command'] and request['env'] == final['env'] and request['cwd'] == pre['cwd'] and
      request['qualification_seconds'] == owner['qualification_seconds'] == 180 and
      request['cleanup_seconds'] == owner['cleanup_seconds'] == 3 and
      request['implementation_sha256'] == config['source_pins']['tools/hia_selfhost_process_owner.py']['sha256'])
check('full worker binding', final['worker'] == worker and final['worker_report_sha256'] == digest(worker_raw) and
      final['status'] == worker['status'] == 'DEVELOPMENT_COMPILER_PAIR_READBACK_COMPLETE')
check('38 sources and32 imported modules unchanged', worker['source_before'] == worker['source_after'] == config['source_pins'] and
      worker['repository_modules_before'] == worker['repository_modules_after'] == config['imported_repository_modules'] and
      len(worker['source_before']) == 38 and len(worker['repository_modules_before']) == 32 and
      worker['controller_inputs_before'] == worker['controller_inputs_after'])
added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format', 'runner_sha256', 'wall_elapsed_ns'}
compile_added = {'produced_image', 'produced_bytes', 'produced_sha256'}
sources = ('artifact_publication_policy', 'artifact_publication_packer', 'sha256_stream')
outputs = {}; invocations = []
for variant in ('v79', 'v82'):
    folder = RUN / 'worker' / variant
    compiler = read(folder / 'B3.image.bin')
    check('actual compiler:' + variant, {'bytes': len(compiler), 'sha256': digest(compiler)} == config['compilers'][variant])
    outputs[variant] = {}
    for label in (*sources, 'pack'):
        receipt = json.loads(read(folder / (label + '.receipt.json')))
        child = json.loads(read(folder / (label + '.stdout.log')))
        stderr = read(folder / (label + '.stderr.log'))
        full = read(folder / (label + '.output.bin')); source = read(folder / (label + '.input.bin'))
        image = compiler if label != 'pack' else read(folder / 'artifact_publication_packer.image.bin')
        check('actual child/provenance/limits:' + variant + '/' + label,
              {k: v for k, v in receipt.items() if k not in (added | (compile_added if label != 'pack' else set()))} == child and
              stderr == b'' and child['status'] == 'returned' and child['abi_status'] == 0 and child['source_unchanged'] is True and
              child['forbidden_compiler_modules_loaded'] == [] and child['image_sha256'] == digest(image) and
              child['source_sha256'] == digest(source) and child['output_sha256'] == digest(full) and len(full) == 1 << 20 and
              child['limits'] == {'cpu_seconds': 10, 'address_bytes': 256 << 20, 'core_dumpable': False,
                                  'stack_bytes': 8 << 20, 'output_capacity': 1 << 20, 'workspace_bytes': 1 << 20})
        output = read(folder / (label + '.image.bin' if label != 'pack' else 'hia-artifact'))
        check('complete output prefix:' + variant + '/' + label, output == full[:child['core_u32']] and 0 < len(output) <= 1 << 20)
        name = label if label != 'pack' else 'hia-artifact'; outputs[variant][name] = output
        invocations.append({'variant': variant, 'label': label, 'native_elapsed_ns': child['native_elapsed_ns'],
                            'wall_elapsed_ns': receipt['wall_elapsed_ns'], 'full_output_bytes': len(full),
                            'full_output_sha256': digest(full), 'output_bytes': len(output), 'output_sha256': digest(output)})
check('exact six compiler calls and two packer calls', len(invocations) == 8 and sum(v['label'] == 'pack' for v in invocations) == 2)
comparisons = {}
for name in (*sources, 'hia-artifact'):
    left = outputs['v79'][name]; right = outputs['v82'][name]
    comparison = {'bytes': len(left), 'v79_sha256': digest(left), 'v82_sha256': digest(right), 'all_bytes_equal': left == right}
    comparisons[name] = comparison
    check('full paired byte result:' + name, comparison['all_bytes_equal'] == worker['comparisons'][name]['all_bytes_equal'] and
          comparison['v79_sha256'] == worker['comparisons'][name]['v79_sha256'] and comparison['v82_sha256'] == worker['comparisons'][name]['v82_sha256'])

roots = [('run', RUN), ('receiver', OUT)]
rows = []
contents = {}
for prefix, root in roots:
    for path in sorted(root.rglob('*')):
        value = path.lstat()
        if stat.S_ISDIR(value.st_mode):
            continue
        raw = read(path); relative = prefix + '/' + path.relative_to(root).as_posix()
        row = {'path': relative, 'original_path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
               'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid, 'gid': value.st_gid,
               'dev': value.st_dev, 'ino': value.st_ino, 'nlink': value.st_nlink, 'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}
        rows.append(row); contents[relative] = raw
check('complete original source namespace stable', all(Path(r['original_path']).stat().st_size == r['bytes'] for r in rows))
manifest = (json.dumps(rows, sort_keys=True, indent=2) + '\n').encode()
archive_path = ROOT / 'compiler-pair-actual-originals-r1.tar.gz'
with archive_path.open('xb') as stream:
    with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.PAX_FORMAT, compresslevel=1) as archive:
        for row in rows:
            info = tarfile.TarInfo(row['path']); info.size = row['bytes']; info.mode = row['mode']
            info.uid = row['uid']; info.gid = row['gid']; info.mtime = 0
            archive.addfile(info, io.BytesIO(contents[row['path']]))
        info = tarfile.TarInfo('ORIGINALS-MANIFEST.json'); info.size = len(manifest); info.mode = 0o600
        archive.addfile(info, io.BytesIO(manifest))
    stream.flush(); os.fsync(stream.fileno())
seen = []
with tarfile.open(archive_path, 'r:gz') as archive:
    for member in archive:
        check('archive ordinary member:' + member.name, member.isreg())
        raw = archive.extractfile(member).read()
        if member.name == 'ORIGINALS-MANIFEST.json':
            check('manifest roundtrip', raw == manifest); continue
        row = next(r for r in rows if r['path'] == member.name)
        check('original archive roundtrip:' + member.name, raw == contents[member.name] and
              member.mode == row['mode'] and member.uid == row['uid'] and member.gid == row['gid'])
        seen.append(member.name)
check('all original archive members exact', seen == [r['path'] for r in rows])
archive_raw = archive_path.read_bytes()
report = {'schema': 'hia.publication-compiler-pair-actual-audit.v1', 'status': 'READONLY_DIAGNOSTIC_EVIDENCE_PASS',
          'checks': checks, 'comparisons': comparisons, 'actual_native_calls': invocations,
          'owner': {'sha256': digest(owner_raw), 'events': owner['events'], 'cleanup': cleanup},
          'actual_elapsed_ns': owner['events'][2]['monotonic_ns'] - owner['events'][0]['monotonic_ns'],
          'raw_members': rows, 'archive': {'path': str(archive_path), 'bytes': len(archive_raw), 'sha256': digest(archive_raw)},
          'publication_application_calls': 0, 'original39_calls': 0, 'fresh_cold_replay': False,
          'old_CI_publication_app_recovered': False, 'original60s_timeout_cause_established': False,
          'scope': 'one same-environment diagnostic; actual old/new B3 produced byte-identical policy/packer/SHAstream images and ET_EXEC here; original deleted CI app remains unavailable'}
with (ROOT / 'COMPILER-PAIR-ACTUAL-AUDIT.json').open('x') as stream:
    json.dump(report, stream, sort_keys=True, indent=2); stream.write('\n')
print(json.dumps({'status': report['status'], 'checks': len(checks), 'originals': len(rows),
                  'raw_bytes': sum(r['bytes'] for r in rows), 'archive': report['archive'], 'comparisons': comparisons}))
