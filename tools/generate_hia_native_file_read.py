"""HIA-owned bounded file reader for the separate Linux file process profile.

This first executable is an observation entry, not the old 15-action CLI.
It writes a fixed 32-byte outcome record to stderr and, on success, file bytes
to stdout. Python Path's string lexical rules are implemented in HIA. The new
reader closes every successfully opened capability, including directories;
the original CPython fdopen directory leak remains a documented difference.
"""
from pathlib import Path
import ast
import hashlib
import inspect
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.generate_hia_selfhost import total_scalar_functions, compact_authoring_cfg
from tools.generate_hia_native_cli_process import CliProcessBuilder
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_linux_file import PROFILE, MODULE

SOURCE=r'''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 0 or length(o) != 8388609 or length(w) != 1048576:
        return 126
    count = argc()
    if count != 2 and count != 3:
        return 64
    raw_size = arglen(1)
    if raw_size > 524287:
        return 65
    got = argcopy(w, 524288, 1, 0, raw_size)
    if got != raw_size:
        return 126
    path_size = path(w, 524288, raw_size, 256)
    if path_size > 262143:
        return 65
    limit = 8388608
    if count == 3:
        limit_size = arglen(2)
        if limit_size == 0 or limit_size > 7:
            return 64
        copied = argcopy(w, 131584, 2, 0, limit_size)
        if copied != limit_size:
            return 126
        limit = 0
        i = 0
        while i < limit_size:
            c = byte(w, 131584 + i)
            if c < 48 or c > 57:
                return 64
            limit = limit * 10 + c - 48
            i = i + 1
        if limit > 8388608:
            return 64
    fill_range(w, 0, 128, 0)
    write(w, 0, RESULT_MAGIC, 8)
    write(w, 64, path_size, 8)
    status = bounded_read(o, w, limit)
    write(w, 8, status, 8)
    sent = send(w, 0, 32, 2)
    if sent != 0:
        return 121
    if status != 0:
        return status
    size = uint(w, 24, 8)
    sent = send(o, 0, size, 1)
    if sent != 0:
        return 120
    return 0

def path(w:mutbuf, start:u64, size:u64, destination:u64) -> u64:
    # PurePosixPath's string lexical rules: empty/dot -> '.', repeated slash
    # collapse, exactly two leading slash preserved, '..' never resolved.
    at = 0
    out = 0
    while at < size and byte(w, start + at) == 47:
        at = at + 1
    if at != 0:
        store(w, destination, 47)
        out = 1
        if at == 2:
            store(w, destination + 1, 47)
            out = 2
    while at < size:
        end = at
        while end < size and byte(w, start + end) != 47:
            end = end + 1
        span = end - at
        if span != 0 and (span != 1 or byte(w, start + at) != 46):
            if out != 0 and byte(w, destination + out - 1) != 47:
                store(w, destination + out, 47)
                out = out + 1
            i = 0
            while i < span:
                store(w, destination + out, byte(w, start + at + i))
                out = out + 1
                i = i + 1
        at = end
        while at < size and byte(w, start + at) == 47:
            at = at + 1
    if out == 0:
        store(w, destination, 46)
        out = 1
    store(w, destination + out, 0)
    return out

def bounded_read(o:mutbuf, w:mutbuf, limit:u64) -> u64:
    if limit > 8388608 or length(o) < limit + 1:
        return 4
    result = signed_zero()
    opened = 0
    while opened == 0:
        result = file_open(w, 256, uint(w, 64, 8) + 1)
        if result != eintr():
            opened = 1
    if result < signed_zero():
        write(w, 16, 0 - raw_word(result), 8)
        return 1
    write(w, 56, raw_word(result), 8)
    status = 0
    result = file_fdflags()
    if result < signed_zero():
        write(w, 16, 0 - raw_word(result), 8)
        status = 1
    else:
        write(w, 40, raw_word(result), 8)
        if (raw_word(result) & 1) == 0:
            status = 4
    if status == 0:
        result = file_statusflags()
        if result < signed_zero():
            write(w, 16, 0 - raw_word(result), 8)
            status = 1
        else:
            write(w, 48, raw_word(result), 8)
            if (raw_word(result) & 133123) != 133120:
                status = 4
    # Model the early FileIO directory classification separately from the
    # explicit regular-file/size admission. This is a new owned-fd lifetime:
    # every successfully opened fd closes, unlike the old constructor leak.
    if status == 0:
        result = file_stat(w, 262144, 144)
        if result == signed_errno(9):
            write(w, 16, 9, 8)
            status = 1
        else:
            if result == signed_zero() and (uint(w, 262168, 4) & 61440) == 16384:
                write(w, 16, 21, 8)
                status = 1
    if status == 0:
        result = file_stat(w, 262144, 144)
        if result < signed_zero():
            write(w, 16, 0 - raw_word(result), 8)
            status = 1
        else:
            mode = uint(w, 262168, 4) & 61440
            if mode != 32768:
                status = 2
            else:
                size = signed_word(uint(w, 262192, 8))
                if size > signed_word(limit):
                    status = 2
    have = 0
    done = 0
    while status == 0 and done == 0:
        result = file_read(o, have, limit + 1 - have)
        if result != eintr():
            if result < signed_zero():
                write(w, 16, 0 - raw_word(result), 8)
                status = 1
            else:
                if result == signed_zero():
                    done = 1
                else:
                    have = have + raw_word(result)
                    if have == limit + 1:
                        done = 1
    # Close before length rejection. The new policy never retries close,
    # including EINTR; a close error takes precedence over an earlier result.
    result = file_close()
    if result < signed_zero():
        write(w, 16, 0 - raw_word(result), 8)
        status = 1
    if status == 0:
        if have > limit:
            status = 3
        else:
            write(w, 24, have, 8)
    return status

def send(b:mutbuf, start:u64, size:u64, fd:u64) -> u64:
    at = 0
    while at < size:
        result = signed_zero()
        if fd == 1:
            result = write_io(b, start + at, size - at)
        else:
            result = stderr_io(b, start + at, size - at)
        if result != eintr():
            if result <= signed_zero():
                return 1
            at = at + raw_word(result)
    return 0
'''


def author_source():
    text=SOURCE.replace('RESULT_MAGIC',str(int.from_bytes(b'HRDFIL1\x00','little')))
    helpers=[]
    for n in ast.parse(LINK_SOURCE).body:
        if isinstance(n,ast.FunctionDef) and n.name in ('uint','write'):
            if n.name=='uint':n.args.args[0].annotation.id='mutbuf'
            helpers.append(ast.unparse(n))
    return text+'\n'+'\n\n'.join(helpers)+'\n'


class FileBuilder(CliProcessBuilder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
            name=node.func.id
            if name in ('file_open','file_stat','file_read'):
                args=[self.expr(v) for v in node.args]
                assert len(args)==3 and not node.keywords
                return self.op('linux.file.'+name[5:],args[:1]+[self.cast(v,'usize') for v in args[1:]],'i64')
            if name in ('file_close','file_fdflags','file_statusflags'):
                assert not node.args and not node.keywords
                return self.op('linux.file.'+name[5:],[],'i64')
            if name=='signed_word':return self.cast(self.expr(node.args[0]),'i64')
            if name=='signed_errno':
                assert len(node.args)==1 and isinstance(node.args[0],ast.Constant)
                return self.c(-node.args[0].value,'i64')
        return super().expr(node)


def document():
    nodes=ast.parse(author_source()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=FileBuilder(n,names,signatures,total);b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap','linux_io','linux_startup','linux_file'],
            'entry':'b0','blocks':b.blocks})
    doc={'schema':'hepta.hia.program.v8','module':MODULE,'functions':functions}
    # Exact existing CFG transformation, with only its explicit verifier port
    # rebound. Every typed operation stays in the original execution order.
    tree=ast.parse(inspect.getsource(compact_authoring_cfg));changed=0
    for n in ast.walk(tree):
        if isinstance(n,ast.ImportFrom) and n.module=='hepta.hia_program':
            assert [(v.name,v.asname) for v in n.names]==[('verify_program',None)]
            n.module='hepta.hia_linux_file';n.names=[ast.alias(name='verify_linux_file_program',asname='verify_program')];changed+=1
    assert changed==1;ast.fix_missing_locations(tree)
    namespace={'TYPES':__import__('tools.generate_hia_selfhost',fromlist=['TYPES']).TYPES}
    exec(compile(tree,'<reviewed-linux-file-author-CFG>','exec'),namespace)
    result=namespace['compact_authoring_cfg'](doc)
    for before,after in zip(doc['functions'],result['functions'],strict=True):
        assert [op for b in before['blocks'] for op in b['ops']]==[op for b in after['blocks'] for op in b['ops']]
    return result


def generated():return render_assembly(document(),profile=PROFILE)


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true')
    args=p.parse_args(argv);doc=document();raw=render_assembly(doc,profile=PROFILE).encode()
    target=ROOT/'examples/hia_bootstrap/native_file_read.hepta'
    if args.check:
        if target.read_bytes()!=raw:raise SystemExit('Native file reader source differs')
    else:target.write_bytes(raw)
    print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),
        'ops':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
        'matching_cold':False,'whole':False},sort_keys=True))

if __name__=='__main__':main()
