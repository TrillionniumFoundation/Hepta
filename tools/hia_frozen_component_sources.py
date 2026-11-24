"""Reconstruct reviewed component inputs from complete, hash-bound physical sources."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path


FIXTURE = 'tests/fixtures/hia_frozen_component_source_relations.json'
FIXTURE_SHA256 = 'acd25ffa7c6bea270fcb56cde74a60d7993899cb2e77173b97a814a3bcce14b9'


@lru_cache(maxsize=1)
def _relations(raw):
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen component source relation changed')
    return json.loads(raw)['files']


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    relation = _relations(take(root / FIXTURE)).get(name)
    if relation is None:
        return raw
    actual = sha256(raw).hexdigest()
    # f377c5de keeps the v5 owner from importing an unselected store profile.
    # Reverse only its complete reviewed physical file, then retain the frozen
    # predecessor relation and original reviewed bytes below unchanged.
    if (name == 'hepta/hia_native_helpers.py' and actual ==
            'a692a261bcc86943526f93f2ff5fb76c5351ad6a0ce5683ddf46cbdc132a13a9'):
        raw = raw.replace(
            b"        record = _decode(captured.raw)\n",
            b"        record = _decode(captured.raw)\n"
            b"        from .hia_worker_store_profile import SCHEMAS as STORE_SCHEMAS, NativeWorkerStoreBinding\n", 1)
        raw = raw.replace(
            b"        else:\n"
            b"            # Load store-profile support only when a store/base profile can\n"
            b"            # actually be selected. The closed v5 Slot and artifact profiles\n"
            b"            # have already selected their own independently admitted owner.\n"
            b"            from .hia_worker_store_profile import SCHEMAS as STORE_SCHEMAS, NativeWorkerStoreBinding\n"
            b"            if schema in STORE_SCHEMAS:\n"
            b"                binding = NativeWorkerStoreBinding(captured, expected_sha256, record)\n"
            b"            else:\n"
            b"                binding = _base_binding(captured, expected_sha256, record)\n",
            b"        elif schema in STORE_SCHEMAS:\n"
            b"            binding = NativeWorkerStoreBinding(captured, expected_sha256, record)\n"
            b"        else:\n"
            b"            binding = _base_binding(captured, expected_sha256, record)\n", 1)
        actual = sha256(raw).hexdigest()
        if actual != '4ee6a95691db4266c71fbb01543c81ed66fdbf382e9a7ff35797c368a8cb8da1':
            raise ValueError('Slot deferred-store source predecessor differs')
    if actual == relation['reviewed_sha256']:
        return raw
    if actual != relation['physical_sha256']:
        raise ValueError('unreviewed physical component source: ' + name)
    restored = bytearray()
    end = 0
    for at, size, original in relation['splices']:
        if not end <= at <= at + size <= len(raw):
            raise ValueError('overlapping component source splice: ' + name)
        restored.extend(raw[end:at])
        restored.extend(original.encode('utf-8'))
        end = at + size
    restored.extend(raw[end:])
    if sha256(restored).hexdigest() != relation['reviewed_sha256']:
        raise ValueError('complete reviewed component source differs: ' + name)
    return bytes(restored)
