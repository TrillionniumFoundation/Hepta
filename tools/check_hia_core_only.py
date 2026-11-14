"""Check the actual Core-only tree, package entry and deleted-language boundary."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
FORBIDDEN_MODULES=frozenset({
    'ast','lexer','parser','checker','backend','pipeline','protocol','protocol_v3',
    'core','modules','packages','workspace','cfg','hsir','ssa','semantic_ir',
    'resource_ir','resource_lowering','resource_source','executable_core',
    'hia_core','hia_program_source','hia_source_bridge','hia_migrate',
    'hia_source_lexer_native','hia_source_types_native',
    'hia_source_expressions_native','hia_source_parser_native','hia_type_parser_native',
})

# These trees contain current examples, test inputs and formal/benchmark
# programs. Frozen experiment output and receipt trees retain their recorded
# names; changing those names would not be a source migration.
ACTIVE_SOURCE_ROOTS = frozenset({'examples', 'tests', 'formal', 'benchmarks'})
CORE_SOURCE_SCHEMA = re.compile(r'hepta\.hia\.(?:program|composite)\.v[0-9]+\Z')

# Explicit source roles select an existing checked HIA profile. No header,
# effect, filename pattern or environment value infers profile authority.
EXPLICIT_SOURCE_PROFILES = {
    'tests/fixtures/hia_linux_stdio_bounded-copy.hepta': 'hepta.hia.linux-stdio.v1',
    'tests/fixtures/hia_linux_stdio_out-of-bounds.hepta': 'hepta.hia.linux-stdio.v1',
    'tests/fixtures/hia_linux_stdio_read-ebadf-exact.hepta': 'hepta.hia.linux-stdio.v1',
    'tests/fixtures/hia_linux_stdio_write-ebadf-exact.hepta': 'hepta.hia.linux-stdio.v1',
    'tests/fixtures/hia_linux_stdio_zero-transfer.hepta': 'hepta.hia.linux-stdio.v1',
    'examples/hia_bootstrap/native_cli_process.hepta': 'hepta.hia.linux-cli-process.v1',
    'examples/hia_bootstrap/native_file_read.hepta': 'hepta.hia.linux-file.v1',
    'examples/hia_bootstrap/native_file_render.hepta': 'hepta.hia.linux-file-render.v3',
}


# Optional standalone components have a separate explicit profile domain.
# These paths still receive complete program verification; installation and
# source headers do not grant profile authority or expand the worker profile.
OPTIONAL_SOURCE_PROFILES = {
    'examples/hia_bootstrap/native_file_roundtrip.hepta': 'hepta.hia.linux-file-roundtrip.v2',
}


def _is_active_json_source(path, relative):
    if (not relative.parts or relative.parts[0] not in ACTIVE_SOURCE_ROOTS
            or path.suffix.lower() != '.json' or not path.is_file() or path.is_symlink()):
        return False
    try:
        document = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        return False
    return (type(document) is dict and type(document.get('schema')) is str
            and CORE_SOURCE_SCHEMA.fullmatch(document['schema']) is not None)

def _checked_hia_sources(root, problems):
    """Check physical source files; archived path strings are not live sources."""
    sources = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if '.git' in relative.parts:
            continue
        lower = path.name.lower()
        if lower.endswith(('.hia', '.hiaasm', '.hia.json')):
            problems.append('legacy HIA source suffix: ' + str(relative) + ' (required .hepta)')
            continue
        if _is_active_json_source(path, relative):
            problems.append('noncanonical HIA source suffix: ' + str(relative) + ' (required .hepta)')
            continue
        if not lower.endswith('.hepta'):
            continue
        if not path.name.endswith('.hepta'):
            problems.append('noncanonical HIA source suffix: ' + str(relative) + ' (required .hepta)')
            continue
        if path.is_symlink() or not path.is_file():
            problems.append('HIA source must be a regular non-symlink file: ' + str(relative))
            continue
        try:
            raw = path.read_bytes()
            profile = EXPLICIT_SOURCE_PROFILES.get(relative.as_posix())
            if profile is None:
                profile = OPTIONAL_SOURCE_PROFILES.get(relative.as_posix())
            # The extension selects checked HIA, not a restored high-level
            # frontend. Both entry points verify the complete program.
            if raw.lstrip().startswith((b'{', b'[')):
                from hepta.hia_program import verify_program
                if profile is None:
                    verify_program(raw)
                else:
                    verify_program(raw, profile=profile)
            else:
                from hepta.hia_agent_assembly import assemble_program
                if profile is None:
                    assemble_program(raw)
                else:
                    assemble_program(raw, profile=profile)
        except (OSError, ValueError, RecursionError) as exc:
            problems.append('invalid HIA source content: ' + str(relative) + ': ' + str(exc))
            continue
        sources[relative.as_posix()] = sha256(raw).hexdigest()
    return sources

def check(root=ROOT):
    root=Path(root); problems=[]
    hia_sources = _checked_hia_sources(root, problems)
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
                    if n.level and directory=='hepta':
                        names=['hepta.'+(n.module or '')]
                        if not n.module:names+=['hepta.'+a.name for a in n.names]
                    else:names=[n.module or '']
                    if n.module=='hepta':names+=['hepta.'+a.name for a in n.names]
                for name in names:
                    parts=name.split('.')
                    if len(parts)>1 and parts[0]=='hepta' and parts[1] in FORBIDDEN_MODULES:
                        problems.append(f'{p.relative_to(root)}:{n.lineno}: deleted-language import {name}')
                # Historical gate inventories used strings, not Python imports.
                # Validate the authored selectors; never filter missing tests at run time.
                if directory=='tools' and isinstance(n,ast.Constant) and type(n.value)is str:
                    if re.fullmatch(r'tests\.test_\w+(?:\.\w+)*',n.value):
                        target=root.joinpath(*n.value.split('.')[:2]).with_suffix('.py')
                        if not target.is_file():problems.append(f'{p.relative_to(root)}:{n.lineno}: absent test selector {n.value}')
    for directory in ['docs','examples']:
        for p in (root/directory).rglob('*.md'):
            text=p.read_text()
            # A source suffix is not an executable token, and adjacent
            # commands on separate lines do not form one removed CLI call.
            # A genuine ./hepta or /path/hepta invocation remains forbidden.
            if re.search(r'(?<![\w.])hepta[ \t]+(?:hia|check|build|run|lower)\b',text):
                problems.append('removed CLI instruction: '+str(p.relative_to(root)))
            for reference in re.findall(r'\b(?:tools|tests)/[\w/.-]+\.py\b',text):
                if not (root/reference).is_file():
                    problems.append(f'{p.relative_to(root)}: absent documented script {reference}')
    for name in ['docs/HIA_SOURCE_SCALAR_EXPORTS_20261028.md',
                 'docs/HIA_SCALAR_ORACLE_V0.md','examples/hia_migration/README.md',
                 'tools/qualify_hia_linux_tests.py']:
        if (root/name).exists():problems.append('removed source-only asset: '+name)
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
            'hia_source_suffix':'.hepta','hia_source_files':len(hia_sources),
            'hia_source_manifest_sha256':sha256(json.dumps(hia_sources,sort_keys=True).encode()).hexdigest(),
            'python_source_files':len(files),'package_python_files':len(list((root/'hepta').glob('*.py'))),
            'source_manifest_sha256':sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
            'high_level_source_language':'removed','whole_native_delivery_qualified':False}

if __name__=='__main__':print(json.dumps(check(),sort_keys=True))
