"""Create standalone, zero-token adapters for evaluator qualification only."""
from pathlib import Path


FIXTURE_MODEL = {'provider': 'fixture', 'name': 'deterministic-protocol-script',
                 'revision': '1-not-an-ai-model'}

SCRIPT = r'''
import json
import sys
import time

request = json.loads(sys.stdin.readline())
identities = {key: request[key] for key in ('request_id', 'task_sha256', 'base_sha256', 'model', 'adapter_kind')}
usage = {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0, 'tool_calls': 0, 'provider_calls': []}

def emit(kind, **fields):
    frame = dict(identities, kind=kind, usage=dict(usage), **fields)
    if MODE == 'stale': frame['base_sha256'] = '0' * 64
    if MODE == 'wrong_model': frame['model'] = dict(request['model'], revision='wrong')
    if MODE == 'missing_usage': frame.pop('usage')
    print(json.dumps(frame), flush=True)

if MODE == 'sleep':
    time.sleep(30)
elif MODE == 'flood':
    print('x' * 100000, flush=True)
elif MODE in ('public_test', 'check', 'extra_tool', 'unknown_tool'):
    usage['tool_calls'] = 1
    emit('tool_call', call_id='t1', tool='unknown' if MODE == 'unknown_tool' else ('check' if MODE == 'extra_tool' else MODE), body=BODY)
    answer = json.loads(sys.stdin.readline())
    if MODE == 'extra_tool':
        usage['tool_calls'] = 2
        emit('tool_call', call_id='t2', tool='check', body=BODY)
        answer = json.loads(sys.stdin.readline())
    emit('final', body=BODY)
elif MODE == 'fixture_tokens':
    usage.update(input_tokens=1, total_tokens=1, provider_calls=[{
        'request_id': 'fixture-cannot-claim-provider-usage', 'model': request['model'],
        'input_tokens': 1, 'output_tokens': 0, 'raw_usage': {'input_tokens': 1, 'output_tokens': 0}}])
    emit('final', body=BODY)
else:
    emit('final', body=BODY)
'''


def write_fixture(directory: Path, body: str, mode='oracle') -> list[str]:
    """The caller owns a temporary directory outside the evaluator source tree."""
    import sys
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'adapter.py').write_text('BODY = ' + repr(body) + '\nMODE = ' + repr(mode) + '\n' + SCRIPT)
    return [sys.executable, '{adapter}/adapter.py']
