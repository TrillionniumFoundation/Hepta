#!/usr/bin/env python3
"""Record the actual frozen main refusal after complete failed qualification."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

WT = Path('/tmp/hepta-next-agent-toolstudy-v10-20261029')
RESULT = Path('/tmp/hepta-next-agent-v10-qwen4b-01/RESULT.json')
CAP = Path('/tmp/hepta-next-agent-v10-capacity-01/CAPACITY.json')
OUT = Path('/tmp/hepta-next-agent-v10-main-refused-01')
RECEIPT = Path('/tmp/hepta-next-agent-v10-main-refusal.json')
r = json.loads(RESULT.read_text())
assert r['source_commit'] == '11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0'
assert r['valid_observation'] and not r['calibration_eligible']
assert all(e['exited'] for e in r['engines'])
assert not OUT.exists() and not RECEIPT.exists()
assert os.environ.get('LLAMA_ARG_REPACK') == '0'
argv = ['/usr/bin/python3', '-B', 'tools/qualify_hia_agent_toolstudy_v10.py', 'main', '--output', str(OUT),
        '--binary', '/tmp/hepta-agent-v4-runtime/llama-b11669/llama-server',
        '--tokenizer', '/tmp/hepta-agent-v4-runtime/llama-b11669/llama-tokenize',
        '--model', '/tmp/hepta-next-model-qwen3-4b-20261029/qwen3_4b.gguf',
        '--clang', os.environ['CLANG'], '--rustc', os.environ['RUSTC'],
        '--capacity', str(CAP), '--calibration-result', str(RESULT)]
started = time.monotonic_ns()
proc = subprocess.run(argv, cwd=WT, text=True, capture_output=True)
wall = time.monotonic_ns() - started
sys.path.insert(0, str(WT))
from experiments.hia_agent_toolstudy_v10_20261029 import support
head, bindings = support.clean_committed_source()

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

refused = (proc.returncode != 0 and not OUT.exists()
           and 'E_TOOLSTUDY_NO_QUALIFIED_MODEL: fresh Rust node qualification did not pass 3/3' in proc.stderr)
record = {'schema': 'hepta.agent.toolstudy-main-refusal.v10', 'argv': argv,
          'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr,
          'wall_ns': wall, 'qualification': identity(RESULT), 'capacity': identity(CAP),
          'source_commit': head, 'source_bindings': bindings,
          'source_unchanged': bindings == r['source_bindings'],
          'main_output_directory_created': OUT.exists(),
          'gate_rejected_before_engine_construction': refused,
          'model_requests': 0 if refused else None, 'main_cells_started': 0 if refused else None}
RECEIPT.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps({k: v for k, v in record.items() if k not in {'source_bindings', 'stderr', 'stdout', 'argv'}}))
assert refused and record['source_unchanged']
