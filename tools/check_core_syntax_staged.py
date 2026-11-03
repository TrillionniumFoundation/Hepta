"""Same-run, hash-bound staged kernel research. No runtime or production authority.

Generated oleans are trusted only as successful prior pinned-kernel outputs in
this fresh run. Importing them does not recheck every imported proof.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from tools.check_guarded_slice_lean import require, theorem_inventory
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

ROOT = Path(__file__).resolve().parents[1]
MODULE_PREFIX = 'HiaSyntaxResearch'
PARTITION_PROTOCOL = 'contiguous-transport-certificate-partitions-v1'
MAX_INVOCATIONS = 11
PROCESS_SECONDS = 60
LAUNCH_SECONDS = 540
MAX_SOURCE = 2 * 1024 * 1024
MAX_TOTAL_SOURCE = 8 * 1024 * 1024
MAX_MODULE = 32 * 1024 * 1024
MAX_TOTAL_MODULE = 128 * 1024 * 1024
MAX_DIAGNOSTIC = 1024 * 1024
NEGATIVES = {'changed_exact_byte','stale_descriptor','duplicate_keys','unordered_keys',
             'byte_modulo_alias','leading_zero','wrong_phi','literal_two',
             'wrong_condition','wrong_arm_implementation'}


def digest(data):
    return sha256(data).hexdigest()


def _relative(name):
    require(type(name) is str and name and '\\' not in name, 'unsafe relative path')
    parts = name.split('/')
    require(all(p and p not in ('.','..') for p in parts) and not name.startswith('/'),
            'unsafe relative path')
    return parts


class SafeRoot:
    """Descriptor-relative no-follow reads; no hostile-host atomicity claim."""
    def __init__(self, path):
        self.path = Path(path).absolute()
        require(self.path.parent.is_dir(), 'output parent missing')
        for parent in (self.path.parent, *self.path.parent.parents):
            require(not parent.is_symlink(), 'symlink output ancestor')
        self.path.mkdir(exist_ok=False)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = os.fstat(self.fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def unchanged(self):
        now = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISDIR(now.st_mode) and (now.st_dev,now.st_ino) ==
                (self.identity.st_dev,self.identity.st_ino), 'output root replaced')

    def _parent(self, relative, create=False):
        parts = _relative(relative)
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def write(self, relative, data):
        require(type(data) is bytes, 'output bytes required')
        fd, name = self._parent(relative, create=True)
        try:
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
            try:
                with os.fdopen(out, 'wb') as stream:
                    stream.write(data)
            except BaseException:
                raise
        finally:
            os.close(fd)

    def read(self, relative, max_bytes):
        fd, name = self._parent(relative)
        try:
            inp = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(inp)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                        'nonregular or hardlinked output')
                require(0 <= before.st_size <= max_bytes, 'file byte budget')
                chunks = []
                remaining = max_bytes + 1
                while remaining:
                    chunk = os.read(inp, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b''.join(chunks)
                require(len(data) <= max_bytes, 'file byte budget')
                after = os.fstat(inp)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                fields = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
                require(fields(before)==fields(after)==fields(current) and
                        stat.S_ISREG(current.st_mode), 'file changed while reading')
                return data
            finally:
                os.close(inp)
        finally:
            os.close(fd)

    def scan(self, allowed):
        self.unchanged()
        result = {}
        directories = { '/'.join(_relative(p)[:i]) for p in allowed
                       for i in range(1,len(_relative(p))) }
        def walk(fd, prefix=''):
            with os.scandir(fd) as entries:
                for entry in entries:
                    rel = prefix + entry.name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        require(rel in directories, 'unexpected output directory: '+rel)
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            actual = os.fstat(child)
                            require((info.st_dev,info.st_ino)==(actual.st_dev,actual.st_ino),
                                    'output directory changed')
                            walk(child, rel+'/')
                        finally:
                            os.close(child)
                    else:
                        require(rel in allowed, 'unexpected output file: '+rel)
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,
                                'nonregular or hardlinked output: '+rel)
                        result[rel] = info.st_size
        walk(self.fd)
        return result


def _diagnostics(stdout, stderr):
    def raw(value):
        if value is None:
            return b''
        if type(value) is bytes:
            return value
        if type(value) is str:
            return value.encode('utf-8',errors='replace')
        raise ValueError('unexpected diagnostic type')
    out, err = raw(stdout), raw(stderr)
    normalized_out = out.decode('utf-8',errors='replace').encode('utf-8')
    normalized_err = err.decode('utf-8',errors='replace').encode('utf-8')
    kept_out = normalized_out[:MAX_DIAGNOSTIC].decode('utf-8',errors='ignore').encode('utf-8')
    kept_err = normalized_err[:max(0,MAX_DIAGNOSTIC-len(kept_out))].decode('utf-8',errors='ignore').encode('utf-8')
    return {'stdout':kept_out.decode('utf-8',errors='replace'),
            'stderr':kept_err.decode('utf-8',errors='replace'),
            'stdout_available_bytes':len(out),'stderr_available_bytes':len(err),
            'stdout_available_sha256':digest(out),'stderr_available_sha256':digest(err),
            'retained_output_sha256':digest(kept_out+kept_err),
            'output_truncated':len(normalized_out)+len(normalized_err)>len(kept_out)+len(kept_err)}


def capture_result(executable, source, output, root):
    environment = dict(os.environ)
    environment['LEAN_PATH'] = str(root)
    environment.pop('LEAN_SRC_PATH',None)
    environment['LEAN_SYSROOT'] = str(Path(executable).parent.parent)
    argv = [str(executable),'--root='+str(root),'-o',str(output),str(source)]
    started = time.monotonic()
    base = {'argv':argv,'cwd':str(root),'search_path':str(root),
            'sysroot':environment['LEAN_SYSROOT'],'timeout_seconds':PROCESS_SECONDS}
    try:
        result = subprocess.run(argv,cwd=root,env=environment,capture_output=True,
                                timeout=PROCESS_SECONDS)
        return {**base,'returncode':result.returncode,'timed_out':False,
                'incomplete':False,'elapsed_seconds':time.monotonic()-started,
                **_diagnostics(result.stdout,result.stderr)}
    except subprocess.TimeoutExpired as error:
        return {**base,'returncode':None,'timed_out':True,'incomplete':True,
                'elapsed_seconds':time.monotonic()-started,
                'error_type':'TimeoutExpired',**_diagnostics(error.stdout,error.stderr)}
    except OSError as error:
        return {**base,'returncode':None,'timed_out':False,'incomplete':True,
                'elapsed_seconds':time.monotonic()-started,'error_type':type(error).__name__,
                **_diagnostics(None,None)}


def validate_plan(prepared):
    stages = prepared['stages']
    partitioned = prepared['manifest'].get('protocol') == PARTITION_PROTOCOL
    required_count = 11 if partitioned else 10
    require(type(stages) is tuple and len(stages)==required_count and len(stages)<=MAX_INVOCATIONS,
            'exact staged invocation inventory')
    require(len(prepared['expected_theorems'])==66 and set(prepared['negatives'])==NEGATIVES,
            'complete positive/negative inventory required')
    manifest = prepared['manifest']
    encoded = json.dumps(manifest,sort_keys=True,separators=(',', ':'))
    require(encoded==prepared['manifest_json'] and digest(encoded.encode())==prepared['manifest_sha256'],
            'manifest identity differs')
    require(manifest['stages']==[s.manifest() for s in stages] and
            manifest['negatives']==prepared['negatives'] and
            manifest['expected_theorems']==sorted(prepared['expected_theorems']) and
            manifest['module_prefix']==MODULE_PREFIX, 'manifest content differs')
    require(dict(prepared['sources'])=={s.module_name:s.source for s in stages}, 'source map differs')
    canonical_binding = (manifest['inputs']['linear']['original_input_binding'] if partitioned
                         else manifest['inputs']['linear'])
    require(digest(prepared['canonical_bytes'])==canonical_binding['canonical_sha256'],
            'fixed canonical byte identity differs')
    expected_names = ('Baseline','SyntaxData','LinearTransport','ParallelTransport',
                      'WrongPhiTransport','LiteralTwoTransport','WrongConditionTransport',
                      'Connections','TransportRejections','WrongArm')
    if partitioned:
        expected_names = ('Baseline','SyntaxData') + tuple(f'CertPart{i:02d}' for i in range(1,7)) + (
            'Connections','TransportRejections','WrongArm')
    require(tuple(s.name for s in stages)==expected_names, 'fixed stage order differs')
    known = {}
    modules = {}
    total = 0
    rejections = []
    all_names = set()
    for stage in stages:
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*',stage.name) is not None,
                'unsafe stage name')
        require(stage.name not in known and stage.module_name not in modules and
                stage.module_name==MODULE_PREFIX+'.'+stage.name, 'duplicate or foreign stage module')
        raw = stage.source.encode('utf-8')
        total += len(raw)
        require(len(raw)<=MAX_SOURCE and total<=MAX_TOTAL_SOURCE, 'staged proof byte budget')
        require(digest(raw)==stage.source_sha256, 'stage source identity differs')
        lines = [line.strip() for line in stage.source.splitlines()
                 if re.match(r'^\s*import\b',line)]
        imports = []
        for line in lines:
            match = re.fullmatch(r'import ([A-Za-z][A-Za-z0-9_.]*)',line)
            require(match is not None, 'unsupported import header')
            imports.append(match.group(1))
        require(tuple(imports)==tuple(stage.explicit_imports) and
                len(set(imports))==len(imports), 'explicit import inventory')
        require(not re.search(r'(?m)^\s*(prelude|set_option|unsafe|axiom|opaque|initialize|run_cmd|run_elab)\b|\b(sorry|native_decide)\b',stage.source), 'forbidden source command')
        require(tuple(stage.direct_imports)==('Init',)+tuple(imports), 'implicit Init import missing')
        parents = tuple(stage.parents)
        require(len(set(parents))==len(parents) and all(p in modules for p in parents),
                'unknown/cyclic/duplicate parent')
        expected_modules = parents
        generated_imports = tuple(n for n in imports if n.startswith(MODULE_PREFIX+'.'))
        require(generated_imports==expected_modules, 'parent import mismatch')
        require(all(n in ('Lean.Elab.Tactic.Omega',) or n in expected_modules for n in imports),
                'unknown or shadowing import')
        require(stage.expected_theorems is not None, 'stage theorem inventory missing')
        require(set(stage.rejection_names)<=NEGATIVES and
                {prepared['negatives'][n]['certificate'] for n in stage.rejection_names}<=set(stage.expected_theorems),
                'unbound rejection theorem')
        rejections.extend(stage.rejection_names)
        all_names.update(stage.expected_theorems)
        known[stage.name] = stage
        modules[stage.module_name] = stage
    require(len(rejections)==10 and len(set(rejections))==10, 'all ten unique rejection certificates required')
    require(set(prepared['expected_theorems'])<=all_names and
            any(set(prepared['expected_theorems'])<=set(s.expected_theorems) for s in stages),
            'final full positive inventory missing')
    if partitioned:
        from tools.core_syntax_partition_sources import validate_bindings
        validate_bindings(prepared)
    elif manifest.get('protocol')=='structured-prefix-certificates-v1':
        from tools.core_syntax_structured_stages import validate_bindings
        validate_bindings(prepared)
    else:
        require('protocol' not in manifest, 'unknown staged protocol')
        # Ownership is fixed independently of the mutable manifest metadata.
        input_layout = (
            ('linear','LinearTransport','HiaCoreSyntaxSlice','linear'),
            ('parallel','ParallelTransport','HiaCoreSyntaxSlice','parallel'),
            ('wrong_phi','WrongPhiTransport','HiaCoreSyntaxSlice.WrongPhi','linear'),
            ('literal_two','LiteralTwoTransport','HiaCoreSyntaxSlice.LiteralTwo','linear'),
            ('wrong_condition','WrongConditionTransport','HiaCoreSyntaxSlice.WrongCondition','linear'))
        for key,owner,namespace,stem in input_layout:
            item = manifest['inputs'][key]
            require(item['definition_module']==MODULE_PREFIX+'.'+owner, 'input owner differs')
            source = known[owner].source
            require(len(re.findall(r'(?m)^def \w+ : (Raw|List Nat) :=',source))==2,
                    'transport must own only its two input definitions')
            pattern = (r'namespace '+re.escape(namespace)+r'\n'
                       r'(def '+stem+r'Raw : Raw := ([^\n]+)\n'
                       r'def '+stem+r'Bytes : List Nat := ([^\n]+)\n)'
                       r'end '+re.escape(namespace)+r'\n')
            found = list(re.finditer(pattern,source))
            require(len(found)==1, 'exact owned input block missing or duplicated')
            match = found[0]
            block = match.group(0)
            require(sum(stage.source.count(block) for stage in stages)==1,
                    'input block appears in a sibling')
            require(digest(match.group(1).encode())==item['definitions_sha256'] and
                    digest(match.group(2).encode())==item['raw_literal_sha256'] and
                    digest(match.group(3).encode())==item['byte_literal_sha256'], 'owned input bytes differ')
            certificate_stem = stem if key in ('linear','parallel') else 'mutated'
            certificate = re.search(r'(?m)^theorem '+certificate_stem+r'_bounds\b',source)
            require(certificate is not None and match.end()<certificate.start(),
                    'input must precede transport certificate')
        require(not re.search(r'(?m)^def \w+ : (Raw|List Nat|Hint) :=',known['SyntaxData'].source),
                'common module must not own concrete input data')
    require(manifest['proof_input_bytes']==total, 'aggregate source manifest differs')
    expected_parents = {
        'Baseline':(), 'SyntaxData':('Baseline',),
        **{n:('SyntaxData',) for n in expected_names[2:7]},
        'Connections':expected_names[2:7], 'TransportRejections':('LinearTransport',),
        'WrongArm':('ParallelTransport',)}
    if partitioned:
        expected_parents = {'Baseline':(), 'SyntaxData':('Baseline',),
            **{f'CertPart{i:02d}':(('SyntaxData',) if i==1 else (f'CertPart{i-1:02d}',))
               for i in range(1,7)},
            'Connections':('CertPart06',), 'TransportRejections':('CertPart02',),
            'WrongArm':('CertPart03',)}
    for stage in stages:
        require(stage.parents==tuple(MODULE_PREFIX+'.'+n for n in expected_parents[stage.name]),
                'fixed import graph differs')
    return None


def _support_imports(prepared, support):
    for stage in prepared['stages']:
        for name in stage.direct_imports:
            if not name.startswith(MODULE_PREFIX+'.'):
                require('lib/lean/'+name.replace('.','/')+'.olean' in support,
                        'unbound standard import: '+name)


def execute_plan(executable, output_directory, prepared, identity, support,
                 source_reader, support_reader, expected_binary_sha, run_process=capture_result, stage_limit=MAX_INVOCATIONS):
    """Execute only a complete frozen DAG; injected readers/process are for tests."""
    require(type(stage_limit) is int and stage_limit in (2,MAX_INVOCATIONS), 'unsupported diagnostic stage limit')
    if prepared['manifest'].get('protocol') == PARTITION_PROTOCOL:
        require(stage_limit == MAX_INVOCATIONS, 'partition protocol requires complete eleven-stage execution')
    validate_plan(prepared)
    _support_imports(prepared,support)
    require(source_reader()==identity and support_reader(executable)==support,
            'initial source/support changed')
    binary_sha = expected_binary_sha
    require(digest(Path(executable).read_bytes())==binary_sha, 'pinned Lean binary changed before execution')
    module_root = Path(executable).parent.parent/'lib/lean'
    require(not os.path.lexists(module_root/MODULE_PREFIX) and
            not os.path.lexists(module_root/(MODULE_PREFIX+'.olean')), 'module prefix shadows support')
    root = SafeRoot(output_directory)
    report = {'schema':'hepta.hia.core-syntax-staged-kernel.v1','status':'running',
              'kernel_core_syntax_connection_checked':False,'actual_core_bridge_proved':False,
              'python_exporter_refinement_proved':False,'body_prefix_refinement_proved':False,
              'all_edge_transfer_proved':False,'source_sha256':identity,'support_sha256':support,
              'lean_binary_sha256':binary_sha,
              'stage_manifest_sha256':prepared['manifest_sha256'],
              'import_trust':'same-run successful pinned-kernel outputs; imports are not rechecked',
              'negative_protocol':'kernel_proof_of_exact_negation','stages':[],
              'diagnostic_stage_limit':stage_limit if stage_limit==2 else None,
              'invocations':0,'obligations':[{'id':n,'status':'unproved'} for n,_ in OBLIGATIONS], **DENY}
    if prepared['manifest'].get('protocol') == PARTITION_PROTOCOL:
        report.update(protocol=PARTITION_PROTOCOL, expected_stage_count=11)
    allowed = set()
    accepted = {}
    source_hashes = {}
    frozen_receipt_hashes = {}
    partitioned = prepared['manifest'].get('protocol') == PARTITION_PROTOCOL
    completed_rejections = set()
    full_inventory = None
    started = time.monotonic()
    def write(name,data):
        root.write(name,data)
        allowed.add(name)
        if partitioned and name != 'RESULT.json' and (name == 'RUN.json' or
                name.endswith(('.started.json', '.stdout', '.stderr', '.finished.json'))):
            frozen_receipt_hashes[name] = digest(data)
    def write_json(name,obj):
        data = (json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()
        write(name,data)
        return digest(data)
    def check_state(extra=()):
        require(not os.path.lexists(module_root/MODULE_PREFIX) and
                not os.path.lexists(module_root/(MODULE_PREFIX+'.olean')), 'module prefix shadows support')
        require(digest(Path(executable).read_bytes())==binary_sha, 'Lean binary changed')
        files = root.scan(allowed | set(extra))
        for rel,expected in source_hashes.items():
            require(digest(root.read(rel,MAX_SOURCE))==expected, 'staged source changed')
        for rel,expected in frozen_receipt_hashes.items():
            require(digest(root.read(rel,MAX_DIAGNOSTIC))==expected, 'partition frozen receipt changed')
        total = 0
        for item in accepted.values():
            raw = root.read(item['path'],MAX_MODULE)
            require(digest(raw)==item['sha256'] and len(raw)==item['bytes'], 'accepted module changed')
            total += len(raw)
        for rel in extra:
            if rel in files:
                require(files[rel]<=MAX_MODULE, 'module byte budget')
                total += files[rel]
        require(total<=MAX_TOTAL_MODULE, 'aggregate module byte budget')
        require(source_reader()==identity and support_reader(executable)==support,
                'source/support changed')
    current = None
    try:
        write('manifest.json',prepared['manifest_json'].encode())
        if partitioned:
            frozen_receipt_hashes['manifest.json'] = prepared['manifest_sha256']
        write_json('RUN.json',{'status':'running','manifest_sha256':prepared['manifest_sha256'],
                             'source_sha256':identity,'support_sha256':support})
        for stage in prepared['stages']:
            rel = stage.module_name.replace('.','/')+'.lean'
            write(rel,stage.source.encode())
            source_hashes[rel] = stage.source_sha256
        check_state()
        for stage in prepared['stages']:
            require(report['invocations']<stage_limit, 'diagnostic stage boundary' if stage_limit==2 else 'Lean invocation budget')
            require(time.monotonic()-started<LAUNCH_SECONDS, 'new-stage launch deadline')
            require(all(p in accepted for p in stage.parents), 'parent not successfully admitted')
            check_state()
            source_rel = stage.module_name.replace('.','/')+'.lean'
            output_rel = stage.module_name.replace('.','/')+'.olean'
            require(output_rel not in root.scan(allowed), 'output must be newly produced')
            parents = {p:accepted[p] for p in stage.parents}
            current = {'name':stage.name,'module_name':stage.module_name,'status':'running',
                       'source_sha256':stage.source_sha256,'direct_imports':list(stage.direct_imports),
                       'parents':parents,'remaining_launch_seconds':LAUNCH_SECONDS-(time.monotonic()-started)}
            if partitioned:
                current['parent_receipts'] = {p: {
                    'path': accepted[p]['successful_stage']+'.finished.json',
                    'sha256': frozen_receipt_hashes[accepted[p]['successful_stage']+'.finished.json']}
                    for p in stage.parents}
            report['stages'].append(current)
            write_json(stage.name+'.started.json',current)
            report['invocations'] += 1
            result = run_process(executable,root.path/source_rel,root.path/output_rel,root.path)
            require(type(result) is dict, 'process receipt missing')
            # Store only bounded diagnostic files; RESULT retains their identities.
            out = result.get('stdout','').encode('utf-8',errors='replace')
            err = result.get('stderr','').encode('utf-8',errors='replace')
            require(len(out)+len(err)<=MAX_DIAGNOSTIC, 'decoded diagnostic budget')
            # Replacement of invalid UTF-8 may expand retained text at most 3x.
            write(stage.name+'.stdout',out)
            write(stage.name+'.stderr',err)
            current['process'] = {k:v for k,v in result.items() if k not in ('stdout','stderr')}
            current['diagnostics'] = {'stdout':stage.name+'.stdout','stderr':stage.name+'.stderr',
                                      'stdout_sha256':digest(out),'stderr_sha256':digest(err)}
            check_state((output_rel,))
            require(type(result.get('returncode')) is int and result['returncode']==0 and
                    result.get('timed_out') is False and result.get('incomplete') is False and
                    result.get('output_truncated') is False, 'stage process incomplete or failed')
            inventory = theorem_inventory(result.get('stdout','')+result.get('stderr',''),
                                          set(stage.expected_theorems))
            raw = root.read(output_rel,MAX_MODULE)
            require(raw, 'missing or empty module')
            require(sum(a['bytes'] for a in accepted.values())+len(raw)<=MAX_TOTAL_MODULE,
                    'aggregate module byte budget')
            accepted[stage.module_name] = {'path':output_rel,'sha256':digest(raw),'bytes':len(raw),
                                           'source_sha256':stage.source_sha256,
                                           'successful_stage':stage.name}
            allowed.add(output_rel)
            current.update(status='passed',theorems=inventory,olean=accepted[stage.module_name])
            completed_rejections.update(stage.rejection_names)
            if set(prepared['expected_theorems'])<=set(inventory):
                full_inventory = {n:inventory[n] for n in sorted(prepared['expected_theorems'])}
            receipt_hash = write_json(stage.name+'.finished.json',current)
            if partitioned:
                frozen_receipt_hashes[stage.name+'.finished.json'] = receipt_hash
            current = None
        check_state()
        require(len(accepted)==len(prepared['stages']) and completed_rejections==NEGATIVES and
                full_inventory is not None, 'incomplete complete-connection evidence')
        report.update(status='passed',kernel_core_syntax_connection_checked=True,
                      theorems=full_inventory,rejection_certificates=sorted(completed_rejections),
                      modules=accepted)
    except Exception as error:
        if current is not None:
            current.update(status='failed',error_type=type(error).__name__,error=str(error))
            try:
                write_json(current['name']+'.finished.json',current)
            except Exception:
                current['receipt_write_failed'] = True
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
    finally:
        report['wall_seconds'] = time.monotonic()-started
        if partitioned:
            report['frozen_receipt_sha256'] = dict(frozen_receipt_hashes)
        try:
            write_json('RESULT.json',report)
        finally:
            root.close()
    return report


def source_identity():
    from tools.check_core_syntax_lean import source_identity as prior
    result = prior()
    for relative in ('tools/check_core_syntax_staged.py','tools/core_syntax_stage_sources.py',
                     'tools/core_syntax_structured_sources.py','tools/core_syntax_structured_stages.py',
                     'experiments/hia_initialization_frontiers_20261103/StructuredTransport.lean'):
        result[relative] = digest((ROOT/relative).read_bytes())
    return result


def qualify(lean, output_directory, stage_limit=MAX_INVOCATIONS):
    from tools.core_syntax_structured_stages import build_inputs
    from tools.check_core_syntax_lean import fixed_input
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT/'formal/toolchain-lock.json').read_text())
    require(digest(executable.read_bytes())==lock['lean_binary_sha256'], 'pinned Lean binary required')
    identity = source_identity()
    support = _support_identity(executable)
    prepared = build_inputs()
    require(source_identity()==identity, 'sources changed during preparation')
    require(fixed_input()['bytes']==prepared['canonical_bytes'], 'Core bytes changed')
    return execute_plan(executable,output_directory,prepared,identity,support,
                        source_identity,_support_identity,lock['lean_binary_sha256'],stage_limit=stage_limit)


def print_diagnostics(directory):
    """Read only fixed diagnostic names through no-follow descriptors; never modules."""
    path = Path(directory).absolute()
    for parent in (path,*path.parents):
        require(not parent.is_symlink(), 'diagnostic ancestor is a symlink')
    if not path.exists():
        print('No proof output directory was created.')
        return
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        stages = ('Baseline','SyntaxData','LinearTransport','ParallelTransport',
                  'WrongPhiTransport','LiteralTwoTransport','WrongConditionTransport',
                  'Connections','TransportRejections','WrongArm')
        names = ['RUN.json','RESULT.json'] + [n+suffix for n in stages
                 for suffix in ('.started.json','.stdout','.stderr','.finished.json')]
        for name in names:
            try:
                handle = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(handle)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                        info.st_size<=MAX_DIAGNOSTIC, 'unsafe diagnostic file')
                data = os.read(handle,MAX_DIAGNOSTIC+1)
                require(len(data)<=MAX_DIAGNOSTIC, 'diagnostic exceeded limit')
                after = os.fstat(handle)
                require((info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
                        (after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'diagnostic changed')
                print(name)
                print(data.decode('utf-8',errors='replace'))
            finally:
                os.close(handle)
    finally:
        os.close(fd)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean',type=Path)
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--print-diagnostics',action='store_true')
    parser.add_argument('--diagnostic-stage-limit',type=int,choices=(2,))
    args = parser.parse_args()
    if args.print_diagnostics:
        print_diagnostics(args.output_directory)
        return 0
    require(args.lean is not None, '--lean required for checking')
    result = qualify(args.lean,args.output_directory,
                     args.diagnostic_stage_limit if args.diagnostic_stage_limit is not None else MAX_INVOCATIONS)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
