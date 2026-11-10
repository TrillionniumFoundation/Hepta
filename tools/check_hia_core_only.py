"""Check the actual Core-only tree, package entry and deleted-language boundary."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_MODULES=frozenset({
    'ast','lexer','parser','checker','backend','pipeline','protocol','protocol_v3',
    'core','modules','packages','workspace','cfg','hsir','ssa','semantic_ir',
    'resource_ir','resource_lowering','resource_source','executable_core',
    'hia_core','hia_program_source','hia_source_bridge','hia_migrate',
    'hia_source_lexer_native','hia_source_types_native',
    'hia_source_expressions_native','hia_source_parser_native','hia_type_parser_native',
})

def check(root=ROOT):
    root=Path(root); problems=[]
    for p in root.rglob('*.hepta'):
        if '.git' not in p.parts:problems.append('removed source extension: '+str(p.relative_to(root)))
    for name in FORBIDDEN_MODULES:
        if (root/'hepta'/f'{name}.py').exists():problems.append('removed module: '+name)
    files={}
    for directory in ['hepta','tools','tests','experiments','benchmarks']:
        for p in sorted((root/directory).rglob('*.py')):
            if '__pycache__' in p.parts:continue
            files[p.relative_to(root).as_posix()]=sha256(p.read_bytes()).hexdigest()
            tree=ast.parse(p.read_bytes(),filename=str(p))
            # Removed-language fixtures can survive even when imports and all
            # their former helpers have been deleted. HIA assembly has no
            # semicolon-terminated module declaration; retain its Core tests.
            for n in ast.walk(tree):
                if (isinstance(n,ast.Constant) and isinstance(n.value,str)
                        and re.search(r'\bmodule\s+[A-Za-z_]\w*\s*;',n.value)
                        and re.search(r'\bfn\s+\w+\s*\(',n.value)):
                    problems.append(f'{p.relative_to(root)}:{n.lineno}: removed high-level source fixture')
            # Negative import-refusal strings in tests are intentionally legal.
            for n in ast.walk(tree):
                names=[]
                if isinstance(n,ast.Import):names=[a.name for a in n.names]
                elif isinstance(n,ast.ImportFrom):
                    if n.level and directory=='hepta':names=['hepta.'+(n.module or '')]
                    else:names=[n.module or '']
                    if n.module=='hepta':names+=['hepta.'+a.name for a in n.names]
                for name in names:
                    parts=name.split('.')
                    if len(parts)>1 and parts[0]=='hepta' and parts[1] in FORBIDDEN_MODULES:
                        problems.append(f'{p.relative_to(root)}:{n.lineno}: deleted-language import {name}')
    import tomllib
    metadata=tomllib.loads((root/'pyproject.toml').read_text())
    if metadata['project']['scripts']!={'hia':'hepta.cli:hia_main'}:
        problems.append('installed entries must be HIA only')
    if metadata['project']['name']!='hia-core':problems.append('obsolete language distribution')
    scope=json.loads((root/'docs/HIA_CORE_ONLY_SCOPE.json').read_text())
    if scope.get('high_level_source_language')!='removed':problems.append('scope mismatch')
    if scope.get('whole_native_delivery_qualified') is not False:problems.append('unqualified native closure claim')
    if problems:raise ValueError('\n'.join(problems))
    return {'schema':'hepta.hia.core-only-source-check.v1','status':'PASS',
            'python_source_files':len(files),'package_python_files':len(list((root/'hepta').glob('*.py'))),
            'source_manifest_sha256':sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
            'high_level_source_language':'removed','whole_native_delivery_qualified':False}

if __name__=='__main__':print(json.dumps(check(),sort_keys=True))
