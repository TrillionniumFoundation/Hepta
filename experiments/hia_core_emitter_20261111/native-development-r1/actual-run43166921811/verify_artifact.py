"""Read the fixed failed-run ZIP and join its actual bytes to decoded logs."""
import base64
import json
from pathlib import Path
import stat
import zipfile
from decode_small import pin, wire, require, decode

root = Path(__file__).resolve().parent
archive = (root / 'original-artifact.zip').read_bytes()
require(pin(archive)['bytes'] == 73643 and pin(archive)['sha256'] ==
        '3ac51b1b57d8bc11766a1343bf0a0179dbf41789d5cd2c913a0ee0ea253a4cb7', 'official ZIP pin differs')
originals, manifest, result, audit, stream = decode((root / 'job.log').read_bytes())
mapping = {
    'hia-core-emitter-native-prepare.stdout.log': originals['stage/prepare.stdout.log'],
    'hia-core-emitter-native-prepare.stderr.log': originals['stage/prepare.stderr.log'],
    'hia-core-emitter-native-finalize.stdout.log': originals['stage/finalize.stdout.log'],
    'hia-core-emitter-native-finalize.stderr.log': originals['stage/finalize.stderr.log'],
    'hia-core-emitter-native-full-diagnostics.stderr.log': originals['diagnostic-control/full-diagnostics.stderr.log'],
    'hia-core-emitter-native-small-diagnostics.stdout.log': stream,
    'hia-core-emitter-native-small-diagnostics.derived.json': originals['derived/development-summary.json'],
    'hia-core-emitter-native-small-diagnostics.manifest.json': wire(manifest),
    'hia-core-emitter-native-small-diagnostics.RESULT.json': wire(result),
}
full_name = 'hia-core-emitter-native-full-diagnostics.stdout.log'
destination = root / 'artifact-members'
destination.mkdir(mode=0o700, exist_ok=False)
members = []
with zipfile.ZipFile(root / 'original-artifact.zip') as archive_reader:
    entries = archive_reader.infolist()
    require(len(entries) == 10 and len({x.filename for x in entries}) == 10
            and {x.filename for x in entries} == set(mapping) | {full_name}, 'actual ZIP member set differs')
    require(archive_reader.testzip() is None, 'ZIP CRC differs')
    for entry in entries:
        require('/' not in entry.filename and not entry.is_dir()
                and stat.S_ISREG(entry.external_attr >> 16), 'nonregular ZIP member')
        raw = archive_reader.read(entry)
        if entry.filename == full_name:
            wanted = manifest['full_diagnostic']['stream_original']
            require(pin(raw) == {key: wanted[key] for key in pin(raw)}, 'full-stream original pin differs')
        else:
            require(raw == mapping[entry.filename], 'actual ZIP versus log reconstruction mismatch')
        with (destination / entry.filename).open('xb') as handle:
            handle.write(raw)
        require((destination / entry.filename).read_bytes() == raw, 'local member readback differs')
        members.append({'path': entry.filename, **pin(raw), 'posix_mode': (entry.external_attr >> 16) & 0o7777,
                        'crc32': format(entry.CRC, '08x')})
report = {'schema': 'hia.core-emitter-native-failed-artifact-readback.v1',
          'status': 'EXACT_FAILED_RUN_ORIGINALS_PRESERVED', 'run_id': 43166921811,
          'job_id': 131010828922, 'artifact_id': 13919614808, 'archive': pin(archive),
          'member_count': len(members), 'member_bytes': sum(x['bytes'] for x in members),
          'members': members, 'all_zip_crc_and_actual_readback_equal': True,
          'result_and_manifest_actual_artifact_bytes_match_log_reconstruction': True,
          'actual_failed_step': 6, 'cause': 'installed distribution metadata rejected by runtime-file predicate',
          'exact_distribution_path_uid_mode_and_linkcount_not_observed': True,
          'preparation_owner_started': False, 'native_compilation_executed': False,
          'complete_116_executed': False, 'source_contract_regenerated': False,
          'prior_failure_unchanged': True, 'no_retry_or_product_rerun': True}
with (root / 'ARTIFACT-READBACK.json').open('xb') as handle:
    handle.write(wire(report))
with (root / 'original-artifact.zip.base64').open('x', encoding='ascii', newline='') as handle:
    handle.write(base64.b64encode(archive).decode('ascii') + '\n')
print(json.dumps({key: report[key] for key in ('status', 'member_count', 'member_bytes', 'archive')}, sort_keys=True))
