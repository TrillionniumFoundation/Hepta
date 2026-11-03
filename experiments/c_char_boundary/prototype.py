"""Experimental native-char adapter. Not wired into the compiler or CLI.

Only this live preparation session can compile its context. No serialized
receipt or sidecar authorizes a special lowering. Foreign contracts stay assumed.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tempfile

from hepta.ast import Type
from hepta.c_backend import CEmitter, SCALARS
from hepta.c_import import HeaderParser, import_header
from hepta.checker import check
from hepta.modules import load_project
from hepta.parser import parse

PROFILE = 'experimental_plain_char_v1'
MODES = {'default': (), 'signed': ('-fsigned-char',), 'unsigned': ('-funsigned-char',)}
SEMANTIC_ENV = ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
                'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH')


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, 'native command rejected: ' + result.stderr)
    return result.stdout


def compiler_identity(cc, runner=run):
    require(not any(os.environ.get(k) for k in SEMANTIC_ENV), 'unrecorded compiler search environment')
    path = Path(shutil.which(cc) or cc).resolve()
    require(path.is_file(), 'compiler is unavailable')
    version = runner([path, '--version'])
    triple = runner([path, '-dumpmachine']).strip()
    require('gcc' in version.lower() and platform.system() == 'Linux'
            and platform.machine() in {'x86_64', 'aarch64'}, 'unqualified native profile')
    return str(path), digest(path.read_bytes()), version, triple


def compiler_driver(directory, cc, mode):
    """Private invocation shim for the existing importer's fixed command API.

    Records the actual compiler separately; never accepts arbitrary extra flags.
    """
    require(mode in MODES, 'unqualified char mode')
    target = Path(directory)/'probe-driver'
    target.write_text('#!/bin/sh\nexec ' + shlex.quote(str(cc)) + ' '
                      + ' '.join(shlex.quote(x) for x in MODES[mode]) + ' "$@"\n')
    target.chmod(0o700)
    return target


@dataclass(frozen=True)
class NativeType:
    spelling: str
    mapped: Type
    plain_char: bool


@dataclass(frozen=True)
class Boundary:
    symbol: str
    adapter: str
    result: NativeType
    arguments: tuple[NativeType, ...]


@dataclass(frozen=True)
class Context:
    profile: str
    entry: str
    identities: tuple[tuple[str, str], ...]
    header: str
    header_hash: str
    compiler: tuple[str, str, str, str]
    char_mode: str
    bindings_hash: str
    source_hash: str
    boundaries: tuple[Boundary, ...]
    typedefs: tuple[tuple[str, str], ...]
    char_signed: bool


def native_type(parser, tokens, *, result=False):
    name, mapped = parser.declaration(list(tokens), allow_unnamed=True)
    tokens = list(tokens)
    if name:
        require(tokens[-1] == name, 'complex declarator')
        tokens.pop()
    for _ in range(32):
        alias = next((t for t in tokens if t in parser.aliases), None)
        if alias is None:
            break
        expansion = parser.aliases[alias]
        require('*' not in expansion, 'pointer typedef outside profile')
        index = tokens.index(alias)
        tokens[index:index+1] = expansion
    else:
        raise Rejected('recursive typedef')
    require(tokens.count('*') <= 1 and not any(t in tokens for t in ['[',']','volatile','_Atomic']),
            'declarator outside profile')
    if '*' in tokens:
        star = tokens.index('*')
        require(star == len(tokens)-1, 'top-level pointer qualifiers outside profile')
        base = [t for t in tokens[:star] if t != 'const']
        require(base == ['char'], 'only single-level plain-char pointers qualify')
        spelling = ('const ' if 'const' in tokens[:star] else '') + 'char *'
        require(mapped.name in {'raw_const','raw_mut'} and mapped.args[0].name in {'i8','u8'},
                'native/Hepta pointer mapping mismatch')
        require((mapped.name == 'raw_const') == ('const' in tokens[:star]), 'const erasure')
        return NativeType(spelling, mapped, True)
    base = [t for t in tokens if t != 'const']
    require(mapped.name in SCALARS and (mapped.name != 'Unit' or result), 'scalar outside profile')
    return NativeType(' '.join(base), mapped, base == ['char'])


class Prepared:
    """Live, single-profile experimental session; close removes private inputs."""
    def __init__(self, entry, *, cc='gcc', char_mode='default',
                 _runner=run, _importer=import_header, _project=None, _locked=False,
                 _context=None):
        require(char_mode in MODES, 'unqualified char mode')
        self.run, self.importer = _runner, _importer
        self.loaded_project, self.locked = _project, _locked
        require(_context is None or _project is None or getattr(_project, 'context', None) is _context,
                'supplied project does not belong to request context')
        self.load = load_project if _context is None else _context.load
        self.read = (lambda path, role=None: Path(path).read_bytes()) if _context is None else _context.read
        self.text = (lambda path, role=None: Path(path).read_text()) if _context is None else (
            lambda path, role=None: self.read(path, role).decode('utf-8').replace('\r\n', '\n').replace('\r', '\n'))
        self.parse = (lambda text, path: parse(text)) if _context is None else _context.parse
        self.metadata = (lambda data, path: json.loads(data.decode('utf-8'))) if _context is None else _context.json
        self._temporary = tempfile.TemporaryDirectory(prefix='hepta-char-prototype-')
        self.directory = Path(self._temporary.name)
        try:
            self._prepare(Path(entry).resolve(), cc, char_mode)
        except BaseException:
            self.close()
            raise

    def close(self):
        self._temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _prepare(self, entry, cc, mode):
        compiler = compiler_identity(cc, self.run)
        project = self.loaded_project or self.load(entry, locked=self.locked)
        require(len(project.c_imports) == 1, 'prototype requires exactly one imported header')
        item = project.c_imports[0]
        bindings = Path(item['source'])
        manifest = self.metadata(self.read(Path(item['manifest']), 'sidecar'), item['manifest'])
        original = Path(manifest['header'])
        if manifest.get('header_path_kind') == 'relative_to_manifest':
            original = Path(item['manifest']).parent/original
        original = original.resolve()
        require(original.is_file(), 'original header is unavailable')
        raw = self.read(original, 'header')
        require(digest(raw) == manifest['header_sha256'], 'original header identity changed')
        self.snapshot = self.directory/'original.h'
        self.snapshot.write_bytes(raw)
        self.snapshot.chmod(0o400)
        parsed_bindings = self.parse(self.text(bindings, 'source'), str(bindings))
        contracts = {f.name: set(f.effects) for f in parsed_bindings.functions}
        driver = compiler_driver(self.directory, compiler[0], mode)
        self.driver_hash = digest(driver.read_bytes())
        fresh = self.importer(self.snapshot, cc=str(driver), module=parsed_bindings.name,
                              contracts=contracts)
        require(fresh.source == self.text(bindings, 'source'), 'fresh native declarations differ from binding source')
        require(fresh.manifest['primitive_types'] == manifest['primitive_types'], 'native facts differ from manifest')
        require(fresh.manifest['target'] == manifest['target'], 'native target differs from manifest')
        parser = HeaderParser(raw.decode('utf-8'))
        require(not parser.structs and not parser.macros, 'records/constants outside initial profile')
        require(all('*' not in v for v in parser.aliases.values()), 'pointer typedef outside initial profile')
        parser.primitive_types = {k: Type(v['hepta']) for k,v in fresh.manifest['primitive_types'].items()}
        namespaces = set(parser.aliases) | {decl[-1] for decl,_ in parser.prototypes}
        namespaces |= set(re.findall(r'^\s*#\s*define\s+(\w+)', raw.decode(), re.M))
        boundaries = []
        for declaration, parameters in parser.prototypes:
            symbol = declaration[-1]
            native_result = native_type(parser, declaration, result=True)
            args = () if parameters == [['void']] else tuple(native_type(parser,t) for t in parameters)
            require(native_result.plain_char or any(a.plain_char for a in args),
                    'non-char-only APIs use the existing path, not this prototype')
            index = len(boundaries)
            adapter = f'__hepta_char_adapter_{index}'
            while adapter in namespaces:
                index += 1
                adapter = f'__hepta_char_adapter_{index}'
            namespaces.add(adapter)
            boundaries.append(Boundary(symbol,adapter,native_result,args))
        checked = check(project.program)
        require(checked.ok, 'project frontend rejected: ' + str(checked.diagnostics))
        externs = {f.name:f for f in project.program.functions if f.extern_c}
        require(set(externs) == {b.symbol for b in boundaries}, 'manual/unbound extern outside prototype')
        for b in boundaries:
            f = externs[b.symbol]
            require(f.return_type == b.result.mapped and tuple(p.type for p in f.params) == tuple(a.mapped for a in b.arguments),
                    'assembled declaration does not match fresh native boundary')
            require(all(p.mode == 'value' for p in f.params), 'borrowed foreign parameter outside profile')
        identities = dict(project.sources)
        identities[str(original)] = digest(raw)
        self.program, self.checked = project.program, checked
        self.context = Context(PROFILE,str(entry),tuple(sorted(identities.items())),str(original),digest(raw),
                               compiler,mode,digest(self.read(bindings, 'source')),project.identity,
                               tuple(boundaries),tuple((k,' '.join(v)) for k,v in parser.aliases.items()),
                               fresh.manifest['primitive_types']['char']['signed'])
        self._bound_context = self.context
        self._assert_current()

    def _assert_current(self):
        ctx = self._bound_context
        require(self.context == ctx, 'context was replaced')
        require(compiler_identity(ctx.compiler[0], self.run) == ctx.compiler, 'compiler identity changed')
        require(self.snapshot.is_file() and digest(self.read(self.snapshot, 'header')) == ctx.header_hash, 'private header snapshot changed')
        require(digest((self.directory/'probe-driver').read_bytes()) == self.driver_hash, 'probe driver changed')
        for name, expected in ctx.identities:
            path = Path(name)
            require(path.is_file() and digest(self.read(path)) == expected, 'prepared source identity changed: ' + name)
        current = self.load(ctx.entry, locked=self.locked)
        require(current.identity == ctx.source_hash, 'assembled project changed')
        # Reconstruct rather than trust a caller-mutated retained AST/check result.
        self.program = current.program
        self.checked = check(self.program)
        require(self.checked.ok, 'fresh frontend rejected')

    def assertions(self):
        ctx = self.context
        rows = ['#include ' + json.dumps(str(self.snapshot)),
                '_Static_assert(CHAR_BIT==8 && sizeof(char)==1, "char width");',
                '_Static_assert(__builtin_types_compatible_p(int8_t,signed char), "i8 character representation");',
                '_Static_assert(__builtin_types_compatible_p(uint8_t,unsigned char), "u8 character representation");',
                '_Static_assert(_Alignof(char)==_Alignof(int8_t) && _Alignof(char)==_Alignof(uint8_t), "character alignment");',
                '_Static_assert(((char)-1 < (char)0) == ' + ('1' if ctx.char_signed else '0') + ', "char signedness");']
        for name, spelling in ctx.typedefs:
            rows.append(f'_Static_assert(__builtin_types_compatible_p({name} *, {spelling} *), "native typedef");')
        for b in ctx.boundaries:
            params = ', '.join(a.spelling for a in b.arguments) or 'void'
            rows.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__(&{b.symbol}), {b.result.spelling} (*)({params})), "native prototype");')
            rows += [f'#ifdef {b.adapter}', '#error "adapter macro collision"', '#endif']
        return '\n'.join(rows)+'\n'

    def _source(self):
        bound = {b.symbol:b for b in self.context.boundaries}
        class Emitter(CEmitter):
            def instance(self, fn, args=()):
                name = super().instance(fn,args)
                if fn.extern_c:
                    self.instances[(fn.name,tuple(args))] = bound[fn.name].adapter
                    return bound[fn.name].adapter
                return name
            def signature(self, fn, args=()):
                s = super().signature(fn,args)
                return 'static '+s if fn.extern_c else s
        emitter = Emitter(self.program,self.checked,'bin')
        source = emitter.emit()
        anchor = '\n_Static_assert(CHAR_BIT'
        require(source.count(anchor)==1, 'experimental insertion anchor changed')
        source = source.replace(anchor,'\n'+self.assertions()+anchor,1)
        for b in self.context.boundaries:
            fn = next(f for f in self.program.functions if f.name==b.symbol and f.extern_c)
            signature = emitter.signature(fn)
            arguments = ', '.join('('+t.spelling+')(h_'+p.name+')' for p,t in zip(fn.params,b.arguments))
            call = b.symbol+'('+arguments+')'
            body = call+';' if b.result.mapped.name=='Unit' else 'return ('+emitter.typ(b.result.mapped)+')('+call+');'
            source += '\n'+signature+' { '+body+' }\n'
        return source

    def compile(self, *, optimize=False, native_source=None, lto=False, strict_aliasing=False):
        """Only fixed qualified flags; no caller-supplied late link/compile flags."""
        self._assert_current()
        ctx = self.context
        source = self._source()
        cfile = self.directory/'program.c'
        cfile.write_text(source)
        artifact = self.directory/'program'
        flags = ['-std=c11','-O3' if optimize else '-O0',*MODES[ctx.char_mode],
                 '-fexcess-precision=standard','-ffp-contract=off','-Wall','-Wextra',
                 '-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration',
                 '-fsanitize=undefined','-fno-sanitize-recover=all',
                 '-fstrict-aliasing' if strict_aliasing else '-fno-strict-aliasing']
        if lto:
            flags += ['-flto','-Werror=lto-type-mismatch']
        inputs = [cfile]
        native_hash = None
        if native_source is not None:
            native_file = self.directory/'native.c'
            native_file.write_text('#include '+json.dumps(str(self.snapshot))+'\n'+native_source)
            native_hash = digest(native_file.read_bytes())
            inputs.append(native_file)
        objects, hashes = [], {}
        for index, input_file in enumerate(inputs):
            obj = self.directory/f'unit-{index}.o'
            dep = self.directory/f'unit-{index}.d'
            self.run([ctx.compiler[0],*flags,'-c',input_file,'-MD','-MF',dep,'-o',obj])
            objects.append(obj)
            dependency_paths = shlex.split(dep.read_text().replace('\\\n','').split(':',1)[1])
            hashes.update({p:digest(Path(p).read_bytes()) for p in dependency_paths})
        self.run([ctx.compiler[0],*flags,*objects,'-lm','-o',artifact])
        self._assert_current()
        receipt = {'profile':PROFILE,'status':'compiled_experimental', 'source_sha256':digest(source.encode()),
                   'artifact_sha256':digest(artifact.read_bytes()),'compiler':ctx.compiler,'flags':flags,
                   'context_source_sha256':ctx.source_hash,'header_sha256':ctx.header_hash,
                   'native_source_sha256':native_hash,'dependencies_observed_after_compile':hashes,
                   'foreign_binary_authenticated':False,'atomic_system_snapshot':False}
        return artifact, receipt
