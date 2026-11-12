"""Retain the six actual new bridge binaries from their own receipts.

This external post-run evidence helper does not execute a bridge, change an
existing prerequisite receipt, run qualification, or grant source/cold/native
admission. It copies only receipt-named binaries inside this preparation.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROLES = (
    ('ranking', 'core-controls-ndu-original-prerequisite-01/build-receipt.json',
     'hepta.hia.ndu-build.v1'),
    ('raw', 'core-retained-ndu-raw-model-prerequisite-01/build-receipt.json',
     'hepta.hia.ndu-build.v1'),
    ('dynamic', 'core-controls-ndu-dynamic-prerequisite-01/build-receipt.json',
     'hepta.hia.ndu-build.v1'),
    ('recursive', 'ndu-recursive-build-01/identity.json', 'hepta.hia.ndu.build.v1'),
    ('finite', 'ndu-finite-build-01/identity.json', 'hepta.hia.ndu.build.v1'),
    ('stream', 'ndu-stream-build-01/identity.json', 'hepta.hia.ndu.build.v1'),
)


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate receipt field: ' + key)
        result[key] = value
    return result


def facts(value):
    return {'device': value.st_dev, 'inode': value.st_ino,
            'bytes': value.st_size, 'mode': stat.S_IMODE(value.st_mode),
            'uid': value.st_uid, 'gid': value.st_gid, 'links': value.st_nlink,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}


def open_regular(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        observation = os.fstat(descriptor)
        if not stat.S_ISREG(observation.st_mode):
            raise ValueError('retained input is not a regular file: ' + str(path))
        if facts(path.lstat()) != facts(observation):
            raise ValueError('retained path changed during open: ' + str(path))
        return descriptor, observation
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path):
    descriptor, before = open_regular(path)
    try:
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            raw = stream.read()
            if facts(os.fstat(stream.fileno())) != facts(before):
                raise ValueError('retained input changed during read: ' + str(path))
        if len(raw) != before.st_size or facts(path.lstat()) != facts(before):
            raise ValueError('retained input path or extent changed: ' + str(path))
        return raw, facts(before)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_new(path, raw, mode=0o400):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def save_json(path, value):
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def file_hash(path):
    descriptor, before = open_regular(path)
    try:
        total = 0
        digest = sha256()
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                digest.update(chunk)
                total += len(chunk)
            if facts(os.fstat(stream.fileno())) != facts(before):
                raise ValueError('binary changed while hashing: ' + str(path))
        if total != before.st_size or facts(path.lstat()) != facts(before):
            raise ValueError('binary path or length changed while hashing: ' + str(path))
        return {'bytes': total, 'sha256': digest.hexdigest(), 'stat': facts(before)}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def copy_binary(source, destination, expected_digest):
    """Stream actual bytes; leave a marked partial file if any check fails."""
    descriptor, before = open_regular(source)
    partial = destination.with_name(destination.name + '.partial')
    try:
        if not stat.S_IMODE(before.st_mode) & 0o111:
            raise ValueError('receipt-named bridge has no executable mode')
        total = 0
        digest = sha256()
        with os.fdopen(descriptor, 'rb') as incoming:
            descriptor = None
            with partial.open('xb') as outgoing:
                for chunk in iter(lambda: incoming.read(1 << 20), b''):
                    outgoing.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            if facts(os.fstat(incoming.fileno())) != facts(before):
                raise ValueError('bridge changed during copy')
        actual = digest.hexdigest()
        if (total != before.st_size or actual != expected_digest
                or facts(source.lstat()) != facts(before)):
            raise ValueError('actual bridge bytes/identity differ from receipt')
        # This is another real content read, not a timestamp-only cache.
        again = file_hash(source)
        if (again['sha256'] != expected_digest or again['bytes'] != total
                or again['stat'] != facts(before)):
            raise ValueError('bridge changed before retention publication')
        saved = file_hash(partial)
        if saved['sha256'] != expected_digest or saved['bytes'] != total:
            raise ValueError('saved bridge differs from consumed input')
        if destination.exists() or destination.is_symlink():
            raise FileExistsError('retained bridge already exists')
        partial.rename(destination)
        destination.chmod(0o500)
        return {'bytes': total, 'sha256': actual, 'source_stat': facts(before),
                'saved_mode': 0o500}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def retain(prepared, output):
    prepared = Path(prepared).resolve()
    output = Path(output).resolve()
    if output == prepared or output.is_relative_to(prepared) or prepared.is_relative_to(output):
        raise ValueError('retention directory must be independent of preparation')
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.six-bridge-evidence-retention.v1',
              'status': 'INCOMPLETE', 'prepared': str(prepared), 'output': str(output),
              'expected_roles': [row[0] for row in ROLES], 'roles': [],
              'started_unix_ns': time.time_ns(), 'source_files_modified_by_helper': False,
              'original_receipts_modified_by_helper': False, 'bridges_executed': False,
              'qualification_executed': False, 'prerequisite_admission_changed': False,
              'whole_native_delivery_qualified': False}
    preparation_record = None
    preparation_raw = None
    preparation_path = prepared / 'CI-PREPARATION.json'
    try:
        preparation_raw, preparation_stat = read_regular(preparation_path)
        write_new(output / 'CI-PREPARATION.original.json', preparation_raw)
        preparation_record = json.loads(preparation_raw, object_pairs_hook=strict_pairs)
        if type(preparation_record) is not dict:
            raise ValueError('preparation observation is not an object')
        report['preparation_observation'] = {
            'path': str(preparation_path), 'bytes': len(preparation_raw),
            'sha256': sha256(preparation_raw).hexdigest(), 'stat': preparation_stat,
            'status': preparation_record.get('status'),
            'source_head': preparation_record.get('source_head'),
            'source_tree': preparation_record.get('source_tree')}
    except Exception as error:
        report['preparation_observation_error'] = {'type': type(error).__name__, 'message': str(error)}
    for index, (label, relative, schema) in enumerate(ROLES, 1):
        row = {'role': label, 'status': 'NOT_RETAINED'}
        folder = output / label
        folder.mkdir(mode=0o700)
        receipt_path = prepared / 'prerequisites/evidence' / relative
        try:
            receipt_raw, receipt_stat = read_regular(receipt_path)
            receipt_name = Path(relative).name
            write_new(folder / receipt_name, receipt_raw)
            row['receipt'] = {'original_path': str(receipt_path),
                              'saved_path': str(folder / receipt_name),
                              'bytes': len(receipt_raw), 'sha256': sha256(receipt_raw).hexdigest(),
                              'source_stat': receipt_stat}
            value = json.loads(receipt_raw, object_pairs_hook=strict_pairs)
            if type(value) is not dict or value.get('schema') != schema:
                raise ValueError('bridge receipt schema differs: ' + label)
            binary_name, expected_digest = value.get('binary'), value.get('binary_sha256')
            if (type(binary_name) is not str or type(expected_digest) is not str
                    or re.fullmatch('[0-9a-f]{64}', expected_digest) is None):
                raise ValueError('bridge receipt lacks exact binary identity')
            binary = Path(binary_name)
            if not binary.is_absolute():
                raise ValueError('new bridge receipt must identify its absolute binary path')
            private = (prepared / 'prerequisites').resolve(strict=True)
            resolved = binary.resolve(strict=True)
            if not resolved.is_relative_to(private) or binary.is_symlink():
                raise ValueError('bridge receipt binary is outside this preparation')
            row['binary'] = {'original_path': binary_name, 'resolved_path': str(resolved),
                             'receipt_sha256': expected_digest}
            destination = folder / 'bridge.bin'
            captured = copy_binary(binary, destination, expected_digest)
            repeated_receipt, repeated_stat = read_regular(receipt_path)
            if repeated_receipt != receipt_raw or repeated_stat != receipt_stat:
                raise ValueError('bridge receipt changed after actual binary copy')
            verified = file_hash(destination)
            if verified['sha256'] != expected_digest or verified['bytes'] != captured['bytes']:
                raise ValueError('retained bridge readback differs')
            row['binary'].update(captured, saved_path=str(destination))
            row['source_commit_in_receipt'] = (
                value.get('upstream', {}).get('commit') if label in ('ranking', 'raw', 'dynamic')
                else value.get('identity', {}).get('source_commit'))
            pins = preparation_record.get('upstream_pins') if type(preparation_record) is dict else None
            row['receipt_matches_preparation_pin'] = (
                row['source_commit_in_receipt'] == pins[label]
                if type(pins) is dict and type(pins.get(label)) is str else None)
            # Retention attests byte custody only. READY and source/profile
            # admission continue to belong to the unchanged original preparer.
            row['status'] = 'RECEIPT_AND_BINARY_BYTES_RETAINED'
        except Exception as error:
            row['error'] = {'type': type(error).__name__, 'message': str(error)}
        report['roles'].append(row)
        save_json(output / ('progress-%02d.json' % index), report)
    report['retained_roles'] = [row['role'] for row in report['roles']
                               if row['status'] == 'RECEIPT_AND_BINARY_BYTES_RETAINED']
    if preparation_raw is not None:
        try:
            after, _ = read_regular(preparation_path)
            report['preparation_observation_unchanged'] = after == preparation_raw
        except Exception as error:
            report['preparation_observation_unchanged'] = False
            report['preparation_readback_error'] = {'type': type(error).__name__, 'message': str(error)}
    else:
        report['preparation_observation_unchanged'] = False
    report['status'] = ('SIX_BRIDGE_RECEIPT_BYTES_RETAINED'
                        if len(report['retained_roles']) == 6
                        and type(preparation_record) is dict
                        and 'preparation_observation_error' not in report
                        and report['preparation_observation_unchanged']
                        else 'INCOMPLETE_BRIDGE_RETENTION')
    report['finished_unix_ns'] = time.time_ns()
    save_json(output / 'RETENTION.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = retain(args.prepared, args.output)
    print(json.dumps({'status': result['status'], 'retained_roles': result['retained_roles'],
                      'report': str(args.output / 'RETENTION.json')}), flush=True)
    raise SystemExit(0 if result['status'] == 'SIX_BRIDGE_RECEIPT_BYTES_RETAINED' else 1)


if __name__ == '__main__':
    main()
