"""Derive new, unexecuted bounded-read installation controls from actual Pretty IO controls."""
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parent
REF = ROOT / 'references'
OUT = ROOT / 'control'


def replace_once(text, before, after):
    assert text.count(before) == 1, (before[:120], text.count(before))
    return text.replace(before, after, 1)


def replace_definition(text, name, replacement, class_name=None):
    tree = ast.parse(text)
    body = tree.body
    if class_name:
        body = next(node for node in body if isinstance(node, ast.ClassDef) and node.name == class_name).body
    node, = [node for node in body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    first = min([node.lineno, *(item.lineno for item in node.decorator_list)])
    lines = text.splitlines(keepends=True)
    return ''.join(lines[:first - 1]) + replacement.rstrip() + '\n' + ''.join(lines[node.end_lineno:])


def write(name, source):
    ast.parse(source, filename=name)
    with (OUT / name).open('x') as stream:
        stream.write(source)


helper = (REF / 'pretty_package_helper.py').read_text()
assert hashlib.sha256(helper.encode()).hexdigest() == 'fd5b1b014dd48b333be2cf3ed878e585661e29d282462c18911d2c4922e7fa25' and len(helper.encode()) == 39882
helper = helper.replace('json-pretty', 'bounded-read').replace('json_pretty', 'bounded_read').replace('Pretty', 'Bounded-read').replace('pretty', 'bounded-read')
helper = helper.replace('325d28bf8857696132b22a86dab0d551a3ce87bf', 'ba714f34b8dcb248c779bb5fc0b9538d9151c685')
helper = helper.replace('5739697d49188ce0e4cc809980d42a314a0a2787', '3489d2047956c1481b2e0593e2fbd32cf273cc70')
helper = helper.replace('installed_package_sources_and_native_output', 'installed_package_sources_and_native_read')
helper = helper.replace('== 81', '== 90').replace('== 96', '== 105').replace('== 169', '== 170')
helper = helper.replace("'source_resource_count': 96", "'source_resource_count': 105")
helper = helper.replace("'native_source_resource_count': 81", "'native_source_resource_count': 90")
helper = helper.replace("'source_python_count': 169", "'source_python_count': 170")
helper = helper.replace('complete 96 resources', 'complete 105 resources')
helper = helper.replace('len(hepta_names) == 170', 'len(hepta_names) == 172')
helper = replace_once(helper, "== {'hia_core_lowering_abi.json'},", "== {'hia_core_lowering_abi.json', 'hia_bounded_read_abi.json'},")
helper = helper.replace("'hepta.hia.bounded-read-native.v1'", "'hepta.hia.bounded-read-native.v3'")
helper = replace_once(helper, "'source_sha256': source_sha256, 'bridge_sha256': bridge_sha256,\n            'child_script':", "'source_sha256': source_sha256, 'bridge_sha256': bridge_sha256,\n            'abi_sha256': sha256(inputs['hepta/hia_bounded_read_abi.json']).hexdigest(),\n            'child_script':")
helper = helper.replace("'expected_native_completions': 14", "'expected_native_read_returns': 7")
helper = replace_once(helper, "and child_result['native_completions'] == 14", "and child_result['native_read_returns'] == 7\n                and child_result['native_completions'] > 0\n                and len(child_result['native_entry_attempts']) == child_result['native_completions']\n                and sum(row['status'] == 0 for row in child_result['native_entry_completed']) == 7")
helper = helper.replace('forbidden_host_layout_attempts', 'forbidden_retained_owner_attempts')
helper = replace_once(helper, "'consumer-cwd', 'invalid-manifests')", "'consumer-cwd', 'invalid-manifests', 'fixtures')")
write('package_helper.py', helper)

child = (REF / 'pretty_installed_cases.py').read_text()
assert hashlib.sha256(child.encode()).hexdigest() == '200a92b8f6a59149fd251a69063a6de2b1bf1b8ed710874f09e36688e8abae9c'
child = child.replace('json-pretty', 'bounded-read').replace('json_pretty', 'bounded_read').replace('Pretty', 'Bounded-read')
child = child.replace('installed_package_sources_and_native_output', 'installed_package_sources_and_native_read')
child = child.replace("'hepta.hia.bounded-read-native.v1'", "'hepta.hia.bounded-read-native.v3'")
child = child.replace('installed_bounded_read', 'installed_bounded_read')
child = child.replace('len(module_names) == 169', 'len(module_names) == 170').replace('len(resource_names) == 96', 'len(resource_names) == 105')
child = child.replace('forbidden_host_layout_attempts', 'forbidden_retained_owner_attempts')
child = child.replace("request['expected_native_completions'] == 14", "request['expected_native_read_returns'] == 7")
child = replace_once(child, "self.completed = []\n        self.attempts = []", "self.completed = []\n        self.reads = []\n        self.attempts = []")
child = replace_once(child, "self.bridge, self.admission = bridge, admission", "from hepta import hia_program_tools as public\n        self.public = public\n        self.bridge, self.admission = bridge, admission\n        os.environ[bridge.SELECTOR] = str(self.manifest)")
child = replace_definition(child, 'no_host_layout', '''@contextmanager
def no_retained_policy(attempts, public):
    previous_profile = sys.getprofile()
    require(previous_profile is None, 'unexpected installed caller profiler')
    original = public._RETAINED_READ_BOUNDED
    retained_code = public._READ_BOUNDED_REFERENCE.__code__
    def forbidden(*args, **kwargs):
        attempts.append({'kind': 'retained_alias'})
        raise AssertionError('installed native call entered the retained Python policy')
    def profile(frame, event, arg):
        if event == 'call' and frame.f_code is retained_code:
            attempts.append({'kind': 'retained_code_object', 'filename': frame.f_code.co_filename})
            raise AssertionError('installed native call entered the retained Python code object')
    public._RETAINED_READ_BOUNDED = forbidden
    sys.setprofile(profile)
    try:
        yield
    finally:
        sys.setprofile(previous_profile)
        public._RETAINED_READ_BOUNDED = original
''')
child = replace_definition(child, 'format', '''    def read_fixture(self, data=b'bounded\\x00read\\xff', expected=None):
        if expected is None:
            expected = data
        owner = self.selected()
        fixture = self.root / 'fixtures' / ('read-%03d.bin' % len(self.reads))
        fixture_record = create(fixture, data)
        count, before_calls, before_transitions = len(self.completed), owner.calls, owner.transitions
        with no_retained_policy(self.report['forbidden_retained_owner_attempts'], self.public):
            actual = self.public.read_bounded(fixture)
        returns = self.completed[count:]
        require(type(actual) is bytes and actual == expected, 'actual installed native file read differs')
        require(owner.calls == before_calls + 1 and owner.transitions > before_transitions
                and len(returns) == owner.transitions - before_transitions
                and len(returns) >= 2 and [row['status'] for row in returns] == [1] * (len(returns) - 1) + [0],
                'actual native continuation/terminal return sequence differs')
        result = {'id': self.case_id, 'fixture': fixture_record, 'input': pin(data), 'output': pin(actual),
                  'native_read_returns': 1, 'native_calls_before': before_calls, 'native_calls_after': owner.calls,
                  'native_completed_calls': len(returns), 'native_statuses': [row['status'] for row in returns]}
        self.reads.append(result)
        return result
''', 'Cases')
child = child.replace('self.format()', 'self.read_fixture()')
child = replace_once(child, "self.format(b'{}', b'{}'),\n            self.format(b'[1,2]', b'[\\n  1,\\n  2\\n]'),", "self.read_fixture(b'', b''),\n            self.read_fixture(b'x' * (8 << 20)),")
child = replace_once(child, "'source_path': str(self.source), 'format': self.read_fixture(),", "'source_path': str(self.source), 'read': self.read_fixture(),\n                'abi_descriptor': self.abi_descriptor(),")
position = child.index('    def invalid_manifest_schema(self):')
child = child[:position] + '''    def abi_descriptor(self):
        name = 'hepta/hia_bounded_read_abi.json'
        path = self.admission._source_resource_path(name)
        require(path == self.installed / 'hepta' / '_data' / name,
                'ABI descriptor must remain an installed package resource')
        raw, record = read(path, 16384)
        value = json.loads(raw)
        require(record['sha256'] == self.request['abi_sha256']
                and value['schema'] == 'hepta.hia.bounded-read-entry-abi.v1'
                and value['source_sha256'] == self.request['source_sha256'],
                'actual installed descriptor differs from the source-owned resource')
        return {'record': record, 'runtime_adapter_consumes_descriptor': False,
                'classification': 'source-owned ABI descriptor, not an independent Python native module'}

''' + child[position:]
child = child.replace("'native_completions': 0, 'native_entry_attempts': []", "'native_completions': 0, 'native_read_returns': 0, 'native_reads': [], 'native_entry_attempts': []")
child = child.replace("report['native_completions'] = len(cases.completed)", "report['native_completions'] = len(cases.completed)\n        report['native_read_returns'] = len(cases.reads)\n        report['native_reads'] = cases.reads", 1)
child = replace_once(child, "and report['native_completions'] == 14", "and report['native_read_returns'] == 7\n                and sum(row['status'] == 0 for row in cases.completed) == 7\n                and [row['id'] for row in cases.reads] == [IDS[0], IDS[5], IDS[6], IDS[7], IDS[8], IDS[8], IDS[8]]")
child = replace_once(child, "            report['native_completions'] = len(cases.completed)\n            report['negative_manifest_originals']", "            report['native_completions'] = len(cases.completed)\n            report['native_read_returns'] = len(cases.reads)\n            report['native_reads'] = cases.reads\n            report['negative_manifest_originals']")
assert 'self.format' not in child and 'format_admitted' not in child and 'no_host_layout' not in child
write('installed_cases.py', child)

result = {'schema': 'hepta.hia.bounded-read-installed-control-static-derivation.v1',
          'status': 'AST_PARSED_UNEXECUTED', 'product_runs': 0, 'files': []}
for name in ('package_helper.py', 'installed_cases.py'):
    data = (OUT / name).read_bytes()
    result['files'].append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
with (ROOT / 'INSTALLATION-STATIC.json').open('x') as stream:
    json.dump(result, stream, sort_keys=True, indent=2)
    stream.write('\n')
print(json.dumps(result))
