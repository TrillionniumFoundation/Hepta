from pathlib import Path
from hashlib import sha256
import io, json, os, platform, statistics, subprocess, sys, time, traceback
BASE = Path('/home/qq/hia-native-self-rewrite-20261111-dda7')
SOURCE = BASE / 'published-v68-e03c82d1-r1/source'
OUT = BASE / 'source-read-cost-v70-r1'
OUT.mkdir(mode=0o700, exist_ok=False)
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_') and (key.endswith(('_MANIFEST', '_COLD_REPORT')) or '_DEVELOPMENT' in key):
        del os.environ[key]
from tools import hia_selfhost_contract as contract
assert Path(contract.__file__).resolve() == SOURCE / 'tools/hia_selfhost_contract.py'
def dump(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
def git_id():
    commands = (['git','rev-parse','HEAD'], ['git','rev-parse','HEAD^{tree}'],
                ['git','status','--porcelain=v1','--untracked-files=all'])
    return [subprocess.run(a, cwd=SOURCE, check=True, capture_output=True, text=True).stdout for a in commands]
def direct_stream_digests(root=SOURCE):
    root = Path(root)
    paths = sorted(set(contract.SOURCE_FILES) | {
        p.relative_to(root).as_posix() for p in (root / 'hepta').rglob('*.py')
    })
    root_name = os.fspath(root)
    result = {}
    for name in paths:
        with io.open(os.path.join(root_name, name), 'rb') as stream:
            raw = stream.read()
        result[name] = sha256(raw).hexdigest()
    return result
report = {'schema':'hia.source-read-cost.diagnostic.v1',
          'scope':'PURE_SOURCE_READ_DIAGNOSTIC_ON_EXACT_E03_NO_PRODUCT_EDIT_NO_DEADLINE_TEST',
          'whole_native':False, 'qualification':False, 'default_native':False, 'legacy_deletion':False,
          'source':str(SOURCE), 'output':str(OUT), 'python':sys.version,
          'executable':sys.executable, 'platform':platform.platform(),
          'original_method':'tools.hia_selfhost_contract.file_digests',
          'candidate_method':'io.open(os.path.join(root_name, relative_name), rb) with identical sorted inventory and per-file SHA256',
          'source_maps':[], 'timings':[]}
start = time.monotonic()
try:
    before = git_id()
    report['git_before'] = before
    assert before[0].strip() == 'e03c82d1b5b7026ead9a5942336d54273b1a6931'
    assert before[1].strip() == 'bac117a8b24c506b60a65562cf81587ee0ec0c31'
    assert before[2] == ''
    expected = json.loads((SOURCE / contract.CONTRACT_PATH).read_bytes())['source_identity']['files']
    assert len(expected) == 751
    expected_keys = sorted(expected)
    assert contract.file_digests(SOURCE) == expected
    assert direct_stream_digests(SOURCE) == expected
    for index, method in enumerate('ABBAABBAABBA'):
        function = contract.file_digests if method == 'A' else direct_stream_digests
        began = time.perf_counter_ns()
        actual = function(SOURCE)
        elapsed = time.perf_counter_ns() - began
        assert list(actual) == expected_keys
        assert actual == expected
        report['timings'].append({'index':index, 'method':method, 'elapsed_ns':elapsed, 'files':len(actual)})
        dump('progress.json', report)
    final = contract.file_digests(SOURCE)
    assert final == expected
    after = git_id()
    report['git_after'] = after
    report['source_unchanged'] = before == after and final == expected
    report['source_unchanged_scope'] = 'All 751 contract files by exact digest plus Git HEAD/tree/status; no new full-repository custody claim'
    medians = {method:statistics.median([r['elapsed_ns'] for r in report['timings'] if r['method']==method]) for method in 'AB'}
    report['median_ns'] = medians
    report['candidate_ratio'] = medians['B'] / medians['A']
    report['static_savings_for_158_calls_ns'] = (medians['A'] - medians['B']) * 158
    report['static_savings_note'] = 'Arithmetic extrapolation, not an observed build_pair/evaluate time or qualification result'
    report['passed'] = report['source_unchanged']
    report['status'] = 'DIAGNOSTIC_COMPLETE'
except BaseException:
    report['status'] = 'DIAGNOSTIC_FAILED'
    report['passed'] = False
    report['exception'] = traceback.format_exc()
    raise
finally:
    report['seconds'] = time.monotonic() - start
    dump('report.json', report)
    print(json.dumps({'status':report['status'], 'passed':report['passed'],
                      'seconds':report['seconds'], 'report':str(OUT/'report.json'),
                      'bytes':(OUT/'report.json').stat().st_size,
                      'sha256':sha256((OUT/'report.json').read_bytes()).hexdigest(),
                      'median_ns':report.get('median_ns'), 'candidate_ratio':report.get('candidate_ratio')}, sort_keys=True), flush=True)
