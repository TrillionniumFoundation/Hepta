"""Author HIA Emit receipt transfer from evidence already pinned to physical products."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import (
    BUILD_RECORD, BUILD_RESULT, receipt_template, source_program as identity_source,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

SOURCE = Path('examples/hia_bootstrap/worker_emit_receipt.hepta')
OBJECT_METADATA = ('{"core_sha256":{},"installation":{},"machine_plan_sha256":{},'
                   '"schema":"hepta.hia.agent.build-object.v1"}')
NATIVE_METADATA = ('{"candidate":{},"codegen":{},"context":{},"core_sha256":{},'
                   '"foreign_buffer_exports":{},"installation":{},"machine_plan":{},'
                   '"object_artifact":{},"object_sha256":{},"output_kind":{},"signatures":{}}')
BUILD_FACTS = ('{"artifact_bytes":{},"artifact_sha256":{},"core_sha256":{},'
               '"foreign_buffer_exports":{},"implementation_sha256":{},"input_sha256":{},'
               '"kind":{},"machine_plan_sha256":{},"object_sha256":{}}')
PLAN_SUBJECT = ('{"backend_profile":{},"kind":"agent_machine_plan","plan":{},"plan_profile":{}}')
TEMPLATES = (
    ('object_metadata', OBJECT_METADATA),
    ('native_metadata', NATIVE_METADATA),
    ('retained_build', BUILD_RECORD),
    ('object_result', BUILD_RESULT.replace('"linker_used":{}', '"linker_used":false')),
    ('shared_result', BUILD_RESULT.replace('"linker_used":{}', '"linker_used":true')),
    ('physical_facts', BUILD_FACTS),
    ('plan_subject', PLAN_SUBJECT),
)

POLICY = r'''
# Frames: [tag:u64, kind:u64, repeat (extent:u64, admitted fragment)].
# Every fragment is from the request argument, authenticated stored material
# or the independently checked build observation. The platform owns fds only.
def emit_receipt(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(s) > 4194304 or length(o) < 64:
        return 4294967293
    if input_word(s, 0) != RECEIPT:
        return 4294967293
    kind = input_word(s, 8)
    extent = render_emit(s, o, kind, 0)
    if extent >= 4294967292:
        return extent
    return render_emit(s, o, kind, 1)
'''


def program():
    lines = ['def render_emit(s:readbuf, o:mutbuf, kind:u64, mode:u64) -> u64:']
    for ordinal, (name, _) in enumerate(TEMPLATES, 1):
        lines.extend((f'    if kind == {ordinal}:', f'        return {name}(s, o, mode)'))
    lines.append('    return 4294967293')
    identity = identity_source()
    return '\n'.join((
        POLICY.replace('RECEIPT', str(int.from_bytes(b'HIAERR01', 'little'))),
        '\n'.join(lines),
        *(receipt_template(name, template) for name, template in TEMPLATES),
        function(INSPECTION, 'input_word'),
        *(function(identity, name).replace('read_word(', 'input_word(')
          for name in ('receipt_fragment_size', 'receipt_literal', 'receipt_fragment')),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
