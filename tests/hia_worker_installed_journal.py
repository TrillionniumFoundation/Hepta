"""Actual installed journal snapshots with the service's namespaced request key.

This is evidence capture outside the installed worker. It never changes a
request, a database row, a worker command, or an original state assertion.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import time


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _create_json(path, value):
    raw = canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return pin(raw)


class JournalSnapshots:
    """Capture after each actual worker terminal and before fixture teardown."""
    def __init__(self, output, database, labels, digest, commands):
        self.output = Path(output).absolute()
        self.database = Path(database).absolute()
        self.directory = self.output / 'journal-snapshots'
        self.directory.mkdir(mode=0o700, exist_ok=False)
        self.labels = tuple(labels)
        if (not self.labels or len(set(self.labels)) != len(self.labels)
                or any(type(label) is not str or not label
                       or any(c not in 'abcdefghijklmnopqrstuvwxyz-' for c in label)
                       for label in self.labels)):
            raise ValueError('invalid closed installed journal observation inventory')
        self.digest = digest
        self.commands = commands
        self.records = []
        self.inputs = {}
        self.finished = False

    def capture(self, request):
        if self.finished or len(self.records) >= len(self.labels):
            raise ValueError('unexpected installed journal observation')
        ordinal = len(self.records)
        label = self.labels[ordinal]
        command_path = self.output / (label + '.result.json')
        command_raw = command_path.read_bytes()
        if not self.commands or json.loads(command_raw) != self.commands[-1]:
            raise ValueError('journal observation is not after its actual worker receipt')
        # Immutable arguments captured at this original observation boundary.
        request_raw = canonical(request)
        arguments = json.loads(request_raw)
        if type(arguments) is not dict or type(arguments.get('request_key')) is not str:
            raise ValueError('journal request lacks the original string key')
        key = self.digest({'tool': 'hia_verify', 'key': arguments['request_key']})
        request_digest = self.digest({'tool': 'hia_verify', 'arguments': arguments})
        start = time.monotonic_ns()
        name = str(ordinal).zfill(2) + '-' + label
        snapshot_path = self.directory / (name + '.sqlite3')
        # Reserve a new output; SQLite backup reads the original complete
        # committed snapshot (including WAL) without changing source rows.
        with snapshot_path.open('xb'):
            pass
        source = sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)
        try:
            target = sqlite3.connect(snapshot_path)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        snapshot_raw = snapshot_path.read_bytes()
        snapshot = sqlite3.connect(snapshot_path.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            snapshot.row_factory = sqlite3.Row
            row = snapshot.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
            raw_key_row = snapshot.execute('SELECT * FROM requests WHERE key=?',
                                           (arguments['request_key'],)).fetchone()
            state = {'request': None if row is None else (row['state'],),
                     'artifacts': snapshot.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                     'costs': snapshot.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}
            schema = [list(item) for item in snapshot.execute(
                'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')]
            record = {
                'schema': 'hepta.hia.installed-journal-observation.v1',
                'id': label, 'ordinal': ordinal,
                'source_database': str(self.database),
                'started_monotonic_ns': start,
                'completed_monotonic_ns': time.monotonic_ns(),
                'tool': 'hia_verify', 'arguments': arguments,
                'arguments_bytes': pin(request_raw),
                'raw_request_key': arguments['request_key'],
                'storage_key': key, 'request_digest': request_digest,
                'namespace': 'sha256(canonical({"tool":tool,"key":request_key}))',
                'raw_key_row': None if raw_key_row is None else dict(raw_key_row),
                'namespaced_row': None if row is None else dict(row),
                'state': state, 'database_schema': schema,
                'snapshot': {'path': snapshot_path.name, **pin(snapshot_raw)},
                'worker_receipt': {'path': command_path.name, **pin(command_raw)},
                'original_database_modified': False,
            }
        finally:
            snapshot.close()
        if snapshot_path.read_bytes() != snapshot_raw or command_path.read_bytes() != command_raw:
            raise ValueError('installed journal input changed during capture')
        record_path = self.directory / (name + '.json')
        record_pin = _create_json(record_path, record)
        self.inputs[str(snapshot_path)] = snapshot_raw
        self.inputs[str(command_path)] = command_raw
        self.inputs[str(record_path)] = record_path.read_bytes()
        self.records.append({'id': label, 'record': record_path.name, **record_pin})
        # Publish immutable progress snapshots; a failed original assertion
        # still leaves the exact database that was read before teardown.
        _create_json(self.directory / (name + '.progress.json'), {
            'schema': 'hepta.hia.installed-journal-progress.v1',
            'planned': list(self.labels), 'completed': [row['id'] for row in self.records],
            'records': list(self.records), 'qualification': False})
        return state

    def finish(self):
        if self.finished or tuple(row['id'] for row in self.records) != self.labels:
            raise ValueError('incomplete installed journal snapshot inventory')
        for path, raw in self.inputs.items():
            if Path(path).read_bytes() != raw:
                raise ValueError('installed journal evidence changed: ' + path)
        value = {'schema': 'hepta.hia.installed-journal-capture.v1',
                 'status': 'CAPTURE_COMPLETE', 'planned': list(self.labels),
                 'records': self.records, 'source_database': str(self.database),
                 'original_database_modified': False,
                 'old_raw_key_lookup_replaced': True,
                 'qualified_whole_native': False}
        identity = _create_json(self.directory / 'index.json', value)
        self.finished = True
        return {'schema': value['schema'], 'path': 'journal-snapshots/index.json', **identity}
