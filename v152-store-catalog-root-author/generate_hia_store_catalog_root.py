"""Author an HIA ten-family catalogue root codec and complete-root transition.

No generation has been run for this author.  This is not a SQL adapter and
does not select a Store backend.  The file/locking/catalogue integrations are
explicit unfinished prerequisites in CONTRACT.md, not Python fallbacks.
"""
from __future__ import annotations
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).absolute().parent
BASE=Path('/workspace/hia-cli-as-dict-generation-r1-dda7/source')
MAGICS={'REQUEST_MAGIC':int.from_bytes(b'HIACRQ01','little'),
        'CATALOG_MAGIC':int.from_bytes(b'HIACAT01','little'),
        'EMPTY_MAGIC':int.from_bytes(b'HIATBL01','little')}


def require(value,message):
    if not value:raise AssertionError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def bound_read(path,expected=None,limit=16777216):
    """Read one fixed author input through held, no-follow directories.

    This selected-input check does not replace the execution owner's full
    source/runtime guards.  No captured descriptor or payload is cached.
    """
    path=Path(path);require(path.is_absolute() and '..' not in path.parts,'absolute fixed input required')
    directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptors=[];links=[];file_fd=None
    def identity(info):return (info.st_dev,info.st_ino,info.st_mode)
    def seven(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        parent=os.open('/',directory_flags);descriptors.append(parent)
        for name in path.parts[1:-1]:
            before=os.stat(name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode),'input ancestor is not an ordinary directory')
            child=os.open(name,directory_flags,dir_fd=parent);descriptors.append(child)
            require(identity(os.fstat(child))==identity(before),'input ancestor binding changed')
            links.append((parent,name,child,identity(before)));parent=child
        leaf=path.name
        file_fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        before=os.fstat(file_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,
                'bounded ordinary independent input required')
        chunks=[];remaining=before.st_size+1
        while remaining:
            block=os.read(file_fd,min(remaining,1048576))
            if not block:break
            chunks.append(block);remaining-=len(block)
        raw=b''.join(chunks)
        require(len(raw)==before.st_size and seven(os.fstat(file_fd))==seven(before)
                and seven(os.stat(leaf,dir_fd=parent,follow_symlinks=False))==seven(before),
                'input bytes or named descriptor binding changed')
        for parent,name,child,expected_directory in reversed(links):
            require(identity(os.fstat(child))==expected_directory
                    and identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==expected_directory,
                    'input directory chain changed')
        if expected is not None:
            require(pin(raw)==expected['pin'] and stat.S_IMODE(before.st_mode)==expected['posix_mode'],
                    'fixed input complete identity changed')
        return raw
    finally:
        if file_fd is not None:os.close(file_fd)
        for descriptor in reversed(descriptors):os.close(descriptor)


def once(source,before,after,edits):
    require(source.count(before)==1,'exact retained SHA projection preimage differs')
    edits.append({'before':before,'after':after})
    return source.replace(before,after,1)


def hash_program(original):
    """Use the retained SHA algebra on one 64-byte empty-table or 544-byte catalogue prefix.

    All compression rounds/constants and padding algebra remain retained.
    SHA scratch and digest are in the distinct OUTPUT owner, not workspace.
    The returned proof is made only during a real, separately authorized run.
    """
    source=original;edits=[]
    source=once(source,'def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        'def sha256(s:mutbuf, w:mutbuf, start:u64, n:u64) -> u64:',edits)
    count=source.count('length(s)');require(count>0,'retained length uses missing')
    previous=source;source=source.replace('length(s)','n')
    edits.append({'replace_all_count':count,'literal_before':'length(s)','literal_after':'n',
        'before_whole_base64':base64.b64encode(previous.encode()).decode(),
        'after_whole_base64':base64.b64encode(source.encode()).decode()})
    source=once(source,'    if n > 8388608 or length(o) < 32 or length(w) < 1088:',
        '    if (n != 64 and n != 544) or start > length(s) or n > length(s) - start or length(w) < 1120:',edits)
    source=once(source,'padded_byte(s, block + i * 4 + j, padded)',
        'padded_byte(s, block + i * 4 + j, padded, start, n)',edits)
    source=once(source,'def padded_byte(s:readbuf, index:u64, total:u64)',
        'def padded_byte(s:mutbuf, index:u64, total:u64, start:u64, n:u64)',edits)
    source=once(source,'return byte(s, index)','return byte(s, start + index)',edits)
    source=once(source,'store(o, i * 4 + j,','store(w, 1088 + i * 4 + j,',edits)
    names=[node.name for node in ast.parse(source).body]
    require(names==['sha256','padded_byte','rotate','get','put'],'complete retained SHA function list differs')
    for name in names:
        require('h_'+name not in source,'new SHA prefix already exists')
        pattern=r'\b'+re.escape(name)+r'\b';count=len(re.findall(pattern,source))
        edits.append({'identifier_before':name,'identifier_after':'h_'+name,'count':count})
        source=re.sub(pattern,'h_'+name,source)
    inverse=source
    for edit in reversed(edits):
        if 'identifier_before' in edit:
            pattern=r'\b'+re.escape(edit['identifier_after'])+r'\b'
            require(len(re.findall(pattern,inverse))==edit['count'],'SHA inverse identifier count differs')
            inverse=re.sub(pattern,edit['identifier_before'],inverse)
        elif 'replace_all_count' in edit:
            before=base64.b64decode(edit['before_whole_base64'],validate=True).decode()
            after=base64.b64decode(edit['after_whole_base64'],validate=True).decode()
            require(before.count(edit['literal_before'])==edit['replace_all_count']
                    and before.replace(edit['literal_before'],edit['literal_after'])==after==inverse,
                    'SHA inverse complete length projection differs')
            inverse=before
        else:
            require(inverse.count(edit['after'])==1,'SHA inverse exact fragment differs')
            inverse=inverse.replace(edit['after'],edit['before'],1)
    require(inverse==original,'complete retained SHA source inverse differs')
    return source,{'before':pin(original.encode()),'after':pin(source.encode()),
        'edits':edits,'whole_inverse_equal':True,'ordinary_SHA_algebra_retained':True}


def source_program():
    from tools.generate_hia_sha256 import source_program as retained_sha
    source=bound_read(HERE/'catalog_root_policy.py.txt').decode('utf-8')
    for key,value in MAGICS.items():source=source.replace('@'+key+'@',str(value))
    require('@' not in source,'unresolved policy author literal')
    sha,projection=hash_program(retained_sha())
    return source+'\n'+sha,projection


def document():
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_program import verify_program
    source,projection=source_program();nodes=ast.parse(source).body
    require(all(isinstance(node,ast.FunctionDef) for node in nodes),'only authored HIA functions permitted')
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    require(len(names)==len(nodes) and names['catalog_root']=='f0','unique entry/function names required')
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    value=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'store_catalog_root_v1','functions':functions})
    verify_program(value)
    return value,projection


def check_authority():
    authority=json.loads(bound_read(HERE/'AUTHORITY.json'))
    require(authority['source']==str(BASE) and authority['source_tree']=='7f694b80c7ab76eb9d62402aeea4c331503ddc16',
            'fixed actual source authority required')
    for relative,row in authority['read_sources'].items():
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts,'fixed relative source required')
        bound_read(BASE/relative,row)
    return authority


def main(output,report,check):
    require(sys.implementation.name=='cpython' and sys.version_info[:3]==(3,14,4)
            and sys.flags.isolated and sys.flags.dont_write_bytecode,'actual3.14.4 -I -B generator required')
    check_authority();sys.path.insert(0,str(BASE))
    from hepta.hia_agent_assembly import render_assembly
    value,projection=document();raw=render_assembly(value).encode()
    check_authority()
    output=Path(output);report=Path(report)
    require(output.is_absolute() and report.is_absolute() and not output.is_relative_to(BASE)
            and not report.is_relative_to(BASE) and not output.is_relative_to(HERE)
            and not report.is_relative_to(HERE),'new independent outputs outside frozen source/author required')
    for path in (output,report):
        require('..' not in path.parts,'no parent traversal in generated output')
        for parent in path.parents:
            require(stat.S_ISDIR(parent.lstat().st_mode),'actual non-symlink output ancestors required')
    if check:require(output.read_bytes()==raw,'complete generated asset differs')
    else:
        with output.open('xb') as stream:stream.write(raw)
        os.chmod(output,0o644);require(output.read_bytes()==raw,'generated output readback differs')
    result={'schema':'hepta.hia.store-catalog-root-generation.v1','status':'GENERATED_AND_CORE_VERIFIED_ONLY',
        'asset':pin(raw),'functions':len(value['functions']),
        'blocks':sum(len(f['blocks']) for f in value['functions']),
        'ops':sum(len(b['ops']) for f in value['functions'] for b in f['blocks']),
        'SHA_projection':projection,'native_compile':False,'kernel_execution':False,
        'sqlite_backend_replaced':False,'default_activated':False,
        'catalogue_graph_verified':False,'transaction_row_semantics_verified':False}
    with report.open('xb') as stream:stream.write(encoded(result))
    return 0


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--report',required=True);parser.add_argument('--check',action='store_true')
    args=parser.parse_args();raise SystemExit(main(args.output,args.report,args.check))
