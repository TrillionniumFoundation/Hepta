"""Append-only experiment records and explicit, optional cost observations."""
from __future__ import annotations

import datetime
import json
import math
import os
from pathlib import Path
import uuid

from .tasks import canonical, digest


def seal_record(value):
    record = {k: v for k, v in value.items() if k != 'record_sha256'}
    return {**record, 'record_sha256': digest(canonical(record))}


def verify_record(record):
    if not isinstance(record, dict) or seal_record(record)['record_sha256'] != record.get('record_sha256'):
        raise ValueError('E_RECORD_STALE: record content identity is missing or changed')
    return record


def write_append_only(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return str(path.resolve())


def cost_record(run, *, human_seconds=None, monetary_cost_usd=None, human_observer=None, price_source=None, note=''):
    verify_record(run)
    if run.get('schema') != 'hepta.crossfile_run.v1': raise ValueError('E_COST: cost must identify one exact run record')
    for name, value in (('human_seconds', human_seconds), ('monetary_cost_usd', monetary_cost_usd)):
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
            raise ValueError('E_COST: ' + name + ' must be null or finite and nonnegative')
    if human_seconds is not None and (not isinstance(human_observer, str) or not human_observer.strip()):
        raise ValueError('E_COST: measured human time requires an observer/source')
    if monetary_cost_usd is not None and (not isinstance(price_source, str) or not price_source.strip()):
        raise ValueError('E_COST: monetary cost requires a receipt or explicit price source')
    return seal_record({'schema': 'hepta.crossfile_cost.v1', 'event_id': str(uuid.uuid4()),
                        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'run_record_sha256': run['record_sha256'], 'sample_id': run.get('sample_id'),
                        'run_kind': run['run_kind'], 'model': run['model'], 'arm': run['arm'], 'task_id': run['task_id'],
                        'human_seconds': human_seconds, 'human_observer': human_observer,
                        'monetary_cost_usd': monetary_cost_usd, 'price_source': price_source, 'note': note,
                        'scope': 'one_total_cost_observation_per_exact_run_not_incremental',
                        'provider_usage': run.get('usage'), 'usage_complete': run.get('usage_complete', False)})
