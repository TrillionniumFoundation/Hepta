"""Write a deterministic reference-edit client. This is never an AI provider."""
from pathlib import Path
import json
import sys

from ..semantic import nodes

FIXTURE_MODEL = {'provider': 'fixture-not-ai', 'name': 'crossfile-reference-script', 'revision': 'trusted-v1'}


def write_fixture(directory, request, reference):
    directory = Path(directory)
    replacements = {name: reference[name] for name in request['editable']}
    declarations = {name: [node['text'] for node in nodes(request['language'], reference[name], name)
                           if node['kind'] == 'declaration'] for name in request['editable']}
    data = {'files': replacements, 'declarations': declarations}
    (directory / 'edits.json').write_text(json.dumps(data))
    (directory / 'adapter.py').write_text('''import json, pathlib, sys
request = json.loads(sys.stdin.readline())
edits = json.loads((pathlib.Path(__file__).parent / 'edits.json').read_text())
identity = {k: request[k] for k in ('request_id','task_sha256','base_sha256','model','adapter_kind')}
calls = 0
version = request['version']
def usage():
    return {'input_tokens':0,'output_tokens':0,'total_tokens':0,'tool_calls':calls,'provider_calls':[]}
def tool(name, arguments):
    global calls, version
    calls += 1
    print(json.dumps({**identity,'kind':'tool_call','call_id':str(calls),'tool':name,'arguments':arguments,'usage':usage()}), flush=True)
    answer = json.loads(sys.stdin.readline())
    version = answer['version']
    return answer['result']
if 'query_nodes' in request['tools']:
    indexed = tool('query_nodes', {})
    replacements = []
    for name, contents in edits['declarations'].items():
        before = [n for n in indexed['nodes'][name] if n['kind']=='declaration']
        assert len(before)==len(contents)
        replacements += [{'op':'replace_declaration','target':name,'node':n['id'],'replacement':text}
                         for n,text in zip(before, contents)]
    tool('replace_nodes', {'expected_version':version,'edits':replacements})
else:
    tool('replace_files', {'expected_version':version,'files':edits['files']})
tool('public_test', {})
print(json.dumps({**identity,'kind':'final','version':version,'usage':usage()}),flush=True)
''')
    return [sys.executable, '{adapter}/adapter.py']
