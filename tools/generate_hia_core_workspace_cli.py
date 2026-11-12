"""HIA packer for the native primitive workspace-to-ELF pipeline.

The new application's bundle profile is 2 MiB, not a change to any compiler
source/output/workspace cap. Each embedded compiler/application image <=1 MiB.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_cli import template as pipeline_template,source_program as core_packer_source
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

MAGIC=int.from_bytes(b'HIAWCLI1','little')
BUNDLE_LIMIT=2<<20
MATERIALIZER_ARENA=88<<20
MATERIALIZER_SCRATCH=(16<<20)+8192


def template():
    return pipeline_template(output_bytes=MATERIALIZER_ARENA,arena_bytes=MATERIALIZER_SCRATCH,
                             require_elf=True,legacy_frontend_errors=False)


def source_program():
    prefix,holes=template()
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 2097152 or read_word(s, 0) != {MAGIC}:
        return 4294967295
    frontend = read_word(s, 8)
    compiler = read_word(s, 16)
    profile = read_word(s, 24)
    if frontend == 0 or frontend > 1048576 or compiler == 0 or compiler > 1048576 or profile != 1:
        return 4294967295
    if length(s) != 32 + frontend + compiler:
        return 4294967295
    size = {len(prefix)} + frontend + compiler
    if size > 2097152 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8]
        if len(chunk)==8:text+=f'    put_word(o, {at}, {int.from_bytes(chunk,"little")})\n'
        else:
            for j,value in enumerate(chunk):text+=f'    store(o, {at+j}, {value})\n'
    text+=f'''    put_word(o, 96, size)
    put_word(o, 104, size)
    put_four(o, {holes['profile']}, 1)
    put_four(o, {holes['frontend']}, {len(prefix)-holes['frontend']-4})
    put_four(o, {holes['compiler']}, {len(prefix)-holes['compiler']-4} + frontend)
    i = 32
    while i < length(s):
        store(o, {len(prefix)} + i - 32, byte(s, i))
        i = i + 1
    return size
'''
    helpers=core_packer_source();return text+helpers[helpers.index('\ndef read_word('):]


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_workspace_cli_packer','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_cli_packer.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
