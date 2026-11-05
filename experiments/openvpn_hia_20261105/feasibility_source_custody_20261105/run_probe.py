import json
import platform
import subprocess
from pathlib import Path
from hepta.ast import HeptaError
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c, compile_c
from hepta.c_import import import_header
from hepta.backend import compile_rust, emit_rust

root = Path(__file__).resolve().parent
report = {
    'source_commit': '125d11c5454835a7df1dc51915fc49901fbede5b',
    'host': platform.platform(),
    'scope': 'finite Hepta 0.2 C-backend probe; not HIA execution or OpenVPN performance',
}
source = (root / 'probe.hepta').read_text()
program = parse(source)
checked = check(program)
assert checked.ok, [d.to_dict() for d in checked.diagnostics]
c_source = emit_c(program, checked, crate_type='obj')
(root / 'probe_generated.c').write_text(c_source)
report['c_build'] = compile_c(c_source, crate_type='obj', output=root/'probe.o', sanitize=True)
if not report['c_build']['ok']:
    raise RuntimeError(report['c_build'])
command = ['gcc', '-std=c11', '-O3', '-fsanitize=undefined', '-fno-sanitize-recover=all', str(root/'harness.c'), str(root/'probe.o'), '-o', str(root/'probe-executable')]
link = subprocess.run(command, capture_output=True, text=True)
report['link'] = dict(command=command, returncode=link.returncode, stdout=link.stdout, stderr=link.stderr)
assert link.returncode == 0
run = subprocess.run([str(root/'probe-executable')], capture_output=True, text=True)
report['run'] = dict(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)
assert run.returncode == 0
report['negative_imports'] = []
for name in ['/usr/include/x86_64-linux-gnu/sys/socket.h', '/usr/include/openssl/ssl.h']:
    try:
        result = import_header(name)
        report['negative_imports'].append({'header': name, 'rejected': False})
    except HeptaError as error:
        report['negative_imports'].append({'header': name, 'rejected': True, 'diagnostic': error.diagnostic.to_dict()})
try:
    rustc_path = subprocess.check_output(['/root/.cargo/bin/rustup', 'which', 'rustc'], text=True).strip()
    report['rust_build'] = compile_rust(emit_rust(program, checked), rustc=rustc_path, crate_type='obj', output=root/'probe-rust.o')
except HeptaError as error:
    report['rust_build'] = {'rejected': True, 'diagnostic': error.diagnostic.to_dict()}
(root/'probe-result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False, indent=2))
