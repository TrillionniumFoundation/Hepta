"""Author a separate independent v1 seed profile adding bounded word stores.

The original v1 source and profile stay byte-for-byte unchanged. Resource 26
requires a mutable view, exactly three input values and no result. Both complete
range checks precede the sole eight-byte store, including full-u64 indices.
The author is compiled by the original independent v1 profile.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_backend import program as base_program
from tools.hia_seed_word_store import add_word_store
ROOT=Path(__file__).resolve().parents[1]


def program():
    return add_word_store(base_program(), expected_entry='seed_backend',
                          new_entry='seed_word_backend')


def main():
    doc=document(program(),'seed_word_backend');raw=render_assembly(doc).encode()
    path=ROOT/'examples/hia_bootstrap/seed_word_backend.hepta';path.write_bytes(raw)
    print(path.name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
if __name__=='__main__':main()
