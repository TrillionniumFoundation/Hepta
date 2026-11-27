"""Development observers: invoke four pinned independent native seed roots.

Every projection, machine emission and pack is performed by those native
programs. This helper records construction bytes; it does not qualify cold.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import struct

PINS = {
    'hia-seed-assembly': '671a968198e651e79e87a17a1ca3cf2fddcfaaf37572666479b9057ff670968c',
    'hia-seed-projector': 'bded06c364aa15811da6f3d005b31e06342df6261705db636692d73f41e37369',
    'hia-seed-backend': 'd7d02d3dcd889c18e95645857df2b36871319ed11734df2ab4d9a8f42a1b66fb',
    'hia-seed-filter-pack': 'bd9f7c5d09a044737c549f860a581bb44e9d5e007fd9dd1ce15524cafff918f0',
}

class NativeSeeds:
    def __init__(self, source, bootstrap, output):
        self.root = Path(source).resolve()
        self.bootstrap = Path(bootstrap).resolve()
        self.output = Path(output)
        self.output.mkdir(mode=0o700, exist_ok=False)
        self.calls = []
        self.profiles = {}
        for name, digest in PINS.items():
            source = self.bootstrap / name
            raw = source.read_bytes()
            assert source.is_file() and not source.is_symlink() and hashlib.sha256(raw).hexdigest() == digest
            target = self.output / name
            target.write_bytes(raw)
            target.chmod(0o500)
        self.profiles['v1'] = self.output / 'hia-seed-backend'

    def invoke(self, tool, raw, *args):
        result = subprocess.run([str(tool), *args], input=raw, capture_output=True, timeout=30,
                                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'})
        row = {'tool': str(tool), 'tool_sha256': hashlib.sha256(Path(tool).read_bytes()).hexdigest(),
               'input_bytes': len(raw), 'input_sha256': hashlib.sha256(raw).hexdigest(),
               'returncode': result.returncode, 'stdout_bytes': len(result.stdout),
               'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
               'stderr_hex': result.stderr.hex()}
        self.calls.append(row)
        assert result.returncode == 0 and result.stdout and not result.stderr, row
        return result.stdout

    def compile(self, source, profile='v1'):
        core = self.invoke(self.output / 'hia-seed-assembly', source, '--agent-compact')
        projected = self.invoke(self.output / 'hia-seed-projector', b'[' + core + b',"f0",1]')
        return self.invoke(self.backend(profile), projected)

    def backend(self, profile):
        if profile in self.profiles:
            return self.profiles[profile]
        assert profile in ('word', 'endian', 'bulk', 'cold-bulk', 'cold-endian', 'cold-bulk-word')
        source = self.root / 'examples/hia_bootstrap' / ('seed_' + profile.replace('-', '_') + '_backend.hepta')
        flat = self.compile(source.read_bytes(), 'v1')
        if 'seed-packer' not in self.profiles:
            body = self.compile((self.root / 'examples/hia_bootstrap/seed_backend_filter_packer.hepta').read_bytes(), 'v1')
            packed = self.invoke(self.output / 'hia-seed-filter-pack', b'HIAFLT01' + struct.pack('<Q', len(body)) + body)
            tool = self.output / 'seed-packer'
            tool.write_bytes(packed)
            tool.chmod(0o500)
            self.profiles['seed-packer'] = tool
        packed = self.invoke(self.profiles['seed-packer'], b'HIAFLT01' + struct.pack('<Q', len(flat)) + flat)
        tool = self.output / ('seed-' + profile)
        tool.write_bytes(packed)
        tool.chmod(0o500)
        self.profiles[profile] = tool
        return tool

    def save(self):
        (self.output / 'construction.json').write_text(json.dumps({'scope': 'native component diagnostic; not complete cold qualification',
                                                                'root_pins': PINS, 'calls': self.calls}, indent=2) + '\n')
