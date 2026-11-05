"""Finite composition oracle. No production resolver/diff/native expectation helpers.
Real source bytes are copied unchanged. Candidate versions are synthetic fixtures.
This qualifies local composition only, not Rust, registry, compatibility or closure.
"""
import argparse, base64, bisect, ctypes as C, hashlib, itertools, json, sys, tempfile
from pathlib import Path

class Bytes(C.Structure):
    _fields_=[('data',C.POINTER(C.c_uint8)),('len',C.c_size_t)]
class Scalars(C.Structure):
    _fields_=[('data',C.POINTER(C.c_uint64)),('len',C.c_size_t)]
class Result(C.Structure):
    _fields_=[('stage',C.c_uint32),('scalars',C.c_size_t),('lower',C.c_size_t),('upper',C.c_size_t)]
PARTS={'base64':'base64','codec':'bytes','order':'ordering','utf8':'utf8'}
def sha(data): return hashlib.sha256(data).hexdigest()
def put(path,data):
    path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
def manifest(bits, impossible=False):
    s='[package]\nname = "indexed_text"\nversion = "0.1.0"\nkind = "bin"\n[dependencies]\n'
    for i,(alias,part) in enumerate(PARTS.items()):
        req='=9.0.0' if impossible and i==0 else ('>=0.1.0' if bits[i] else '=0.1.0')
        # Alternate candidate declaration order: version priority must not depend on it.
        candidates=[f'candidates/{part}_v1',f'candidates/{part}_v2']
        if i%2: candidates.reverse()
        s+=f'{alias} = {{ package = "hepta_{part}", version = "{req}", candidates = {json.dumps(candidates)} }}\n'
    return s.encode()
def expected(app,bits):
    edges={alias:f'candidates/{part}_v{1+bits[i]}' for i,(alias,part) in enumerate(PARTS.items())}
    nodes={'.':dict(name='indexed_text',version='0.1.0',kind='bin',entry='src/main.hepta',dependencies=edges)}
    paths=['hepta.toml','src/main.hepta','src/packet.hepta']
    for i,(alias,part) in enumerate(PARTS.items()):
        p=edges[alias]; nodes[p]=dict(name='hepta_'+part,version=f'0.{1+bits[i]}.0',kind='lib',entry='src/lib.hepta',dependencies={})
        paths += [p+'/hepta.toml',p+'/src/lib.hepta']
    content={'packages':nodes,'files':{p:sha((app/p).read_bytes()) for p in paths}}
    return dict(schema='hepta.lock.v1',**content,sha256=sha(json.dumps(content,sort_keys=True,separators=(',',':')).encode()))
def delta(a,b):
    out=dict(schema='hepta.lock-diff.v1',ok=True,changed=a!=b,compatibility='not_assessed',before_sha256=a['sha256'],after_sha256=b['sha256'],packages=dict(added=[],removed=[],changed=[]),dependencies=dict(added=[],removed=[],retargeted=[]),files=dict(added=[],removed=[],changed=[]))
    for p in sorted(set(a['packages'])|set(b['packages'])):
        x=a['packages'].get(p); y=b['packages'].get(p)
        if x is None: out['packages']['added'].append(dict(path=p,package=y))
        elif y is None: out['packages']['removed'].append(dict(path=p,package=x))
        else:
            changes={k:dict(before=x[k],after=y[k]) for k in ('name','version','kind','entry') if x[k]!=y[k]}
            if changes: out['packages']['changed'].append(dict(path=p,changes=changes))
        xe=x['dependencies'] if x else {}; ye=y['dependencies'] if y else {}
        for alias in sorted(set(xe)|set(ye)):
            if alias not in xe: out['dependencies']['added'].append(dict(package=p,alias=alias,target=ye[alias]))
            elif alias not in ye: out['dependencies']['removed'].append(dict(package=p,alias=alias,target=xe[alias]))
            elif xe[alias]!=ye[alias]: out['dependencies']['retargeted'].append(dict(package=p,alias=alias,before=xe[alias],after=ye[alias]))
    for p in sorted(set(a['files'])|set(b['files'])):
        x=a['files'].get(p);y=b['files'].get(p)
        if x is None: out['files']['added'].append(dict(path=p,sha256=y))
        elif y is None: out['files']['removed'].append(dict(path=p,sha256=x))
        elif x!=y: out['files']['changed'].append(dict(path=p,before=x,after=y))
    return out

def packet_case(function, wire, cap, slots, query, bad_range=False):
    # Python computes both the return value and every backing-array byte/cell.
    raw = None
    values = []
    stage = 1
    if not bad_range:
        try:
            decoded = base64.b64decode(wire, validate=True)
            if base64.b64encode(decoded) == wire and cap >= len(decoded) + 1:
                raw = decoded
        except ValueError:
            pass
    if raw is not None:
        if len(raw) < 2:
            stage = 2
        elif int.from_bytes(raw[:2], 'big') != len(raw) - 2:
            stage = 3
        else:
            try:
                values = sorted(ord(c) for c in raw[2:].decode('utf8'))
                stage = 0 if slots >= len(values) + 1 else 5
            except UnicodeDecodeError:
                stage = 4
    target = ((stage, 0, 0, 0) if stage else
              (0, len(values), bisect.bisect_left(values, query) + 1,
               bisect.bisect_right(values, query) + 1))
    data = (C.c_uint8 * (len(wire) + 2))(91, *wire, 92)
    scratch = (C.c_uint8 * (cap + 2))(93, *([165] * cap), 94)
    scalar = (C.c_uint64 * (slots + 2))(0xDEADBEEF, *([999] * slots), 0xFACECAFE)
    expected_input = bytes(data)
    expected_scratch = list(scratch)
    expected_scalars = list(scalar)
    if raw is not None:
        expected_scratch[2:2 + len(raw)] = raw
    if stage == 0:
        expected_scalars[2:2 + len(values)] = values
    data_pointer = C.cast(C.byref(data, 1), C.POINTER(C.c_uint8))
    scratch_pointer = C.cast(C.byref(scratch, 1), C.POINTER(C.c_uint8))
    scalar_pointer = C.cast(C.byref(scalar, C.sizeof(C.c_uint64)), C.POINTER(C.c_uint64))
    result = function(Bytes(data_pointer, len(wire)),
                      len(wire) + 1 if bad_range else 0, len(wire),
                      Bytes(scratch_pointer, cap), Scalars(scalar_pointer, slots), query)
    actual = (result.stage, result.scalars, result.lower, result.upper)
    failures = []
    if actual != target:
        failures.append('return')
    if bytes(data) != expected_input:
        failures.append('input_backing')
    if list(scratch) != expected_scratch:
        failures.append('scratch_backing')
    if list(scalar) != expected_scalars:
        failures.append('scalar_backing')
    return dict(failures=failures, actual=actual, expected=target)


def native(app, temporary, tag):
    from hepta.modules import load_project
    from hepta.checker import check
    from hepta.c_backend import emit_c, compile_c
    from hepta.packages import write_lock
    from hepta.pipeline import compiler_hash

    def emit():
        program = load_project(app, locked=True).program
        checked = check(program)
        assert checked.ok, checked.diagnostics
        names = [f.name for f in program.functions if f.name.endswith('index_packet')]
        assert len(names) == 1
        return emit_c(program, checked, crate_type='cdylib'), names[0]

    def build(source, name, lane, suffix):
        report = compile_c(source, crate_type='cdylib', optimize=lane == 'O3',
                           sanitize=True, output=temporary / f'{tag}-{lane}-{suffix}.so')
        assert report['ok'], report
        assert ('-fsanitize=undefined' in report['flags']
                and '-fno-sanitize-recover=all' in report['flags']
                and '-' + lane in report['flags'] and not report['rustc_used'])
        library = C.CDLL(report['artifact'])
        function = getattr(library, '__hepta_cb_fn_' + name)
        function.argtypes = [Bytes, C.c_size_t, C.c_size_t, Bytes, Scalars, C.c_uint64]
        function.restype = Result
        metadata = {k: report[k] for k in ('flags', 'toolchain', 'target', 'source_sha256',
                                           'artifact_sha256', 'rustc_used')}
        metadata['compiler_sha256'] = compiler_hash()
        return library, function, metadata

    source, name = emit()
    samples = ['', 'a', '\0', '\u007f\u0080\u07ff\u0800',
               '\ud7ff\ue000\uffff\U00010000\U0010ffff', 'ézé😀\0', 'bbbb', '東京']
    wires = [base64.b64encode(len(t.encode()).to_bytes(2, 'big') + t.encode()) for t in samples]
    wires += [b'!!!!', b'AB==', b'AAB=', base64.b64encode(b''),
              base64.b64encode(b'\x00'), base64.b64encode(b'\x00\x02a'),
              base64.b64encode(b'\x00\x01\xff'), base64.b64encode(b'\x00\x02\xc0\x80')]
    lanes = {}
    for lane in ('O0', 'O3'):
        library, function, metadata = build(source, name, lane, 'original')
        stages = {str(i): 0 for i in range(6)}
        cases = 0
        for wire, cap, slots, query, bad_range in itertools.product(
                wires, (0, 1, 3, 64), (0, 1, 3, 32), (0, 98, 233, 0x110000), (False, True)):
            outcome = packet_case(function, wire, cap, slots, query, bad_range)
            assert not outcome['failures'], (wire, cap, slots, query, bad_range, outcome)
            stages[str(outcome['expected'][0])] += 1
            cases += 1
        assert cases == 2048 and all(stages.values()), stages
        lanes[lane] = dict(result='PASS', cases=cases, stages=stages,
                           full_backing_checks=cases * 3, **metadata)

    # Compile a genuinely altered packet implementation, with a fresh valid lock.
    # The model and inputs remain unchanged. The original fixture and lock are restored.
    packet = app / 'src/packet.hepta'
    original_packet = packet.read_bytes()
    original_lock = (app / 'Hepta.lock').read_bytes()
    needle = b'lower: low.index'
    assert original_packet.count(needle) == 1
    try:
        packet.write_bytes(original_packet.replace(needle, b'lower: high.index'))
        write_lock(app)
        wrong_source, wrong_name = emit()
        assert wrong_source != source
        wrong_wire = base64.b64encode(b'\x00\x04bbbb')
        for lane in ('O0', 'O3'):
            library, function, metadata = build(wrong_source, wrong_name, lane, 'wrong-output')
            outcome = packet_case(function, wrong_wire, 64, 32, 98)
            assert outcome['failures'] == ['return'], outcome
            assert outcome['expected'] == (0, 4, 1, 5) and outcome['actual'] == (0, 4, 5, 5)
            lanes[lane]['compiled_wrong_output_control'] = dict(
                result='REJECTED', mutation='lower: low.index -> lower: high.index',
                **outcome, **metadata)
    finally:
        packet.write_bytes(original_packet)
        (app / 'Hepta.lock').write_bytes(original_lock)
    return lanes

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);args=ap.parse_args();root=args.root.resolve();sys.path.insert(0,str(root))
    from hepta.packages import write_lock
    from hepta.modules import load_project
    from hepta.lock_diff import compare_locks
    from hepta.ast import HeptaError
    if not __debug__: raise RuntimeError('Assertions required')
    if C.sizeof(C.c_size_t) != 8 or C.sizeof(C.c_void_p) != 8:
        raise RuntimeError('Oracle requires the qualified 64-bit size_t/pointer host')
    identities={};counts={'states':0,'diff_checks':0,'stale_refusals':0,'unsatisfiable_refusals':0};lanes={}
    with tempfile.TemporaryDirectory(prefix='hepta-independent-versioned-') as tmp:
        base=Path(tmp);app=base/'app'
        for name in ('main.hepta','packet.hepta'):
            source=root/'examples/packages/indexed_text/src'/name;put(app/'src'/name,source.read_bytes());identities[str(source.relative_to(root))]=sha(source.read_bytes())
        for part in PARTS.values():
            src=root/'stdlib'/part/'src/lib.hepta';identities[str(src.relative_to(root))]=sha(src.read_bytes())
            for v in (1,2):
                folder=app/f'candidates/{part}_v{v}';put(folder/'src/lib.hepta',src.read_bytes());put(folder/'hepta.toml',f'[package]\nname = "hepta_{part}"\nversion = "0.{v}.0"\nkind = "lib"\n'.encode())
        previous=None
        for bits in itertools.product((0,1),repeat=4):
            put(app/'hepta.toml',manifest(bits));before=base/'before.lock';after=base/'after.lock'
            if previous:
                prior=(app/'Hepta.lock').read_bytes();before.write_bytes(prior)
                try: load_project(app,locked=True)
                except HeptaError as e: assert e.diagnostic.code=='E_LOCK_STALE';counts['stale_refusals']+=1
                else: raise AssertionError('Stale lock accepted')
                assert (app/'Hepta.lock').read_bytes()==prior
            want=expected(app,bits);got=write_lock(app)['snapshot'];assert got==want,(bits,got,want)
            after.write_bytes((app/'Hepta.lock').read_bytes());assert compare_locks(after,after)==delta(want,want);counts['diff_checks']+=1
            if previous:
                assert compare_locks(before,after)==delta(previous,want);assert compare_locks(after,before)==delta(want,previous);counts['diff_checks']+=2
            if bits in ((0,0,0,0),(1,1,1,1)):lanes[str(bits)]=native(app,base,str(sum(bits)))
            previous=want;counts['states']+=1
        prior=(app/'Hepta.lock').read_bytes();put(app/'hepta.toml',manifest((1,1,1,1),impossible=True))
        for op in (lambda:write_lock(app),lambda:load_project(app,locked=True)):
            try: op()
            except HeptaError as e: assert e.diagnostic.code=='E_PACKAGE_RESOLUTION';counts['unsatisfiable_refusals']+=1
            else: raise AssertionError('Impossible candidate set accepted')
            assert (app/'Hepta.lock').read_bytes()==prior
    print(json.dumps(dict(result='PASS',python=sys.version,counts=counts,native_calls=lanes,source_sha256=identities,oracle_sha256=sha(Path(__file__).read_bytes()),scope='Finite local four-library candidate composition; synthetic version metadata; private C ABI; not native Rust or full blocker closure'),sort_keys=True))
if __name__=='__main__':main()
