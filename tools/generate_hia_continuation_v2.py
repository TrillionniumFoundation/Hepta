"""Explicit Core v2 native scheduling without widening the v1 protocol."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_continuation as prior
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
META_MAGIC = int.from_bytes(b'HIACTN02', 'little')
PACK_MAGIC = int.from_bytes(b'HIACTPK2', 'little')
LOW_MAGIC = int.from_bytes(b'HIALOW02', 'little')


def _replace(source, before, after):
    if source.count(before) != 1:
        raise ValueError('Core v2 continuation predecessor differs')
    return source.replace(before, after)


def policy_source():
    source = prior.POLICY
    for before, after in (
        ('number != i + 1 or arity > 4', 'number != i + 1 or arity > 6'),
        ('if phase == 2 or phase == 5:', 'if phase == 2 or phase == 5 or phase == 8:'),
        ('opcode > 18 or count > 8 or results > 3', 'opcode > 19 or count > 8 or results > 4'),
        ('if uint(s, 16, 8) != 19 or unit >= get(w, 24):',
         'if uint(s, 16, 8) != 21 or unit >= get(w, 24):'),
        ('        if status == 2:\n', '''        if status == 3:
            if uint(s, 16, 8) != 20:
                return bad(w)
            put(w, 0, 8)
            return event(o, w, 4, 128)
        if status == 2:
'''),
    ):
        source = _replace(source, before, after)
    source += prior.HELPERS
    for name, value in dict(META_MAGIC=META_MAGIC, POOL_MAGIC=prior.POOL_MAGIC,
                            LOW_MAGIC=LOW_MAGIC, RPC_MAGIC=prior.RPC_MAGIC).items():
        source = source.replace(name, str(value))
    return source


def packer_source():
    source = prior.packer_source(in_process=True)
    source = _replace(source, 'uint(s, 0, 8) != ' + str(prior.PACK_MAGIC),
                      'uint(s, 0, 8) != ' + str(PACK_MAGIC))
    source = _replace(source, 'i * 16 + 8, 8) > 4:', 'i * 16 + 8, 8) > 6:')
    source = _replace(source, ', ' + str(prior.META_MAGIC) + ', 8)',
                      ', ' + str(META_MAGIC) + ', 8)')
    return source


def main():
    for name, source in (
        ('continuation_policy_v2', policy_source()),
        ('continuation_inprocess_packer_v2', packer_source()),
    ):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
