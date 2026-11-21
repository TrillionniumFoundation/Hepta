"""Author the sealed native Context manifest and public receipt codec."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import (
    CONTEXT_MANIFEST,
    CONTEXT_RECEIPT,
    MAGIC,
    SOURCE as IDENTITY_POLICY,
    receipt_template,
)
from tools.generate_hia_artifact_publication import document

SOURCE = Path('examples/hia_bootstrap/worker_context_record.hepta')


def program():
    # The positional fragments retain the existing identity image's protocol.
    policy = f'''
def context_record(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or read_word(s, 0) != {MAGIC}:
        return 4294967293
    mode = read_word(s, 8)
    if mode == 21:
        return manifest(s, o)
    if mode == 22:
        return receipt(s, o)
    return 4294967293

def manifest(s:readbuf, o:mutbuf) -> u64:
    size = context_manifest(s, o, 0)
    if size > length(o):
        return size
    return context_manifest(s, o, 1)

def receipt(s:readbuf, o:mutbuf) -> u64:
    size = context_receipt(s, o, 0)
    if size > length(o):
        return size
    return context_receipt(s, o, 1)
'''
    for name in ('receipt_fragment_size', 'receipt_literal', 'receipt_fragment', 'read_word'):
        signature = '\ndef ' + name + '('
        start = IDENTITY_POLICY.index(signature)
        end = IDENTITY_POLICY.index('\ndef ', start + len(signature))
        policy += IDENTITY_POLICY[start:end] + '\n'
    return (policy + receipt_template('context_manifest', CONTEXT_MANIFEST)
            + receipt_template('context_receipt', CONTEXT_RECEIPT))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
