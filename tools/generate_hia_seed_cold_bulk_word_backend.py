"""Compose the cold bulk emitter with the original bounded LE word store.

This is a separate profile. The original bulk, word, cold-bulk and cold-endian
sources remain unchanged. Resource 26 has the word profile's mutable view,
three inputs, no result and complete full-u64 eight-byte bounds checks before
its sole store. Bulk move/fill, cold parallel edges and compact immediates
are retained from the exact cold-bulk parent. The author uses only v1 ops.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_cold_backend import program as cold_program
from tools.hia_seed_word_store import add_word_store

ROOT = Path(__file__).resolve().parents[1]


def program():
    return add_word_store(cold_program('bulk'), expected_entry='seed_cold_bulk_backend',
                          new_entry='seed_cold_bulk_word_backend')


def main():
    name = 'seed_cold_bulk_word_backend'
    result = render_assembly(document(program(), name)).encode()
    path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
    path.write_bytes(result)
    print('COLD_BULK_WORD_SOURCE', name, len(result))


if __name__ == '__main__':
    main()
