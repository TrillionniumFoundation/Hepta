"""Compose the existing unsigned div/rem and bounded LE word-store profiles.

The original div, word and v1 sources remain unchanged. This development
author produces a separately named native seed profile, with no new opcode
semantics beyond the two existing, independently bounded extensions.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_div_backend import program as div_program
from tools.hia_seed_word_store import add_word_store

ROOT = Path(__file__).resolve().parents[1]


def program():
    return add_word_store(div_program(), expected_entry='seed_div_backend',
                          new_entry='seed_div_word_backend')


def main():
    raw = render_assembly(document(program(), 'seed_div_word_backend')).encode()
    (ROOT/'examples/hia_bootstrap/seed_div_word_backend.hepta').write_bytes(raw)
    print('SEED_DIV_WORD_SOURCE', len(raw))


if __name__ == '__main__':
    main()
