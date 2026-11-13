#!/usr/bin/env bash
# Preparation only for the immutable product named in target.json.
# Run on the provisioned Linux x86_64 / Python 3.14 / Clang 20 CI runner.
# This does not run the test suite or claim a passing gate.
set -euo pipefail

if [[ $# != 3 ]]; then
  printf 'usage: %s /absolute/Hepta /absolute/new-dependency-directory /absolute/target.json\n' "$0" >&2
  exit 2
fi
gate_python=${HIA_GATE_PYTHON:-python}
source_root=$(realpath "$1")
dependency_root=$(realpath -m "$2")
target_file=$(realpath "$3")
harness_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
upstream_url=https://github.com/TrillionniumFoundation/hepta-private-ci.git

"$gate_python" -B - "$source_root" "$dependency_root" "$target_file" "$harness_root" <<'PY'
import importlib.util, sys
from pathlib import Path
root, out, target_path, harness = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('external_gate_harness', harness / 'run-gate.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner.require_native_runner()
if out.exists() or out.is_relative_to(root):
    raise ValueError('dependency output must be a new directory outside the source checkout')
target = runner.load_target(target_path)
before = runner.source_admission(root, target)
out.mkdir(parents=True, exist_ok=False)
(out / 'logs').mkdir()
runner.write_json(out / 'preparation-target.json', {'target': target, 'target_file_sha256': runner.sha(target_path)})
runner.write_json(out / 'preparation-source-before.json', before)
PY
stage=initialization
trap 'code=$?; printf "exit_code=%s\nstage=%s\n" "$code" "$stage" > "$dependency_root/preparation-exit.txt"' EXIT
export GIT_TERMINAL_PROMPT=0
export PYTHONDONTWRITEBYTECODE=1
export CLANG=/usr/bin/clang-20
export HEPTA_CLANG=/usr/bin/clang-20
export HEPTA_TEST_CLANG=/usr/bin/clang-20
export PATH="/usr/lib/llvm-20/bin:$PATH"
test -x "$CLANG"
command -v clang
command -v cc
command -v rustup
cd "$source_root"

# Each command's original streams survive failure. Reusing this output root is
# deliberately refused; a later attempt must use a different directory.
run_logged() {
  local label=$1
  shift
  stage=$label
  printf '%q ' "$@" > "$dependency_root/logs/$label.command"
  printf '\n' >> "$dependency_root/logs/$label.command"
  "$@" > "$dependency_root/logs/$label.stdout" 2> "$dependency_root/logs/$label.stderr"
}

run_logged install-rust-190 rustup toolchain install 1.90.0 --profile minimal
run_logged install-rust-195 rustup toolchain install 1.95.0 --profile minimal
cargo190=$(rustup which --toolchain 1.90.0 cargo)
rustc190=$(rustup which --toolchain 1.90.0 rustc)
cargo195=$(rustup which --toolchain 1.95.0 cargo)
rustc195=$(rustup which --toolchain 1.95.0 rustc)

# The adapter has its own [workspace]. Its only production path dependencies
# are the three original crates below. Keep their full directories (including
# embedded fixtures) and their original parent manifest, without other assets.
fetch_profile() {
  local profile=$1 pin=$2 adapter=$3
  local checkout="$dependency_root/$profile-source"
  run_logged "$profile-git-init" git init --quiet "$checkout"
  git -C "$checkout" remote add origin "$upstream_url"
  git -C "$checkout" config credential.helper ''
  git -C "$checkout" config remote.origin.promisor true
  git -C "$checkout" config remote.origin.partialclonefilter blob:none
  run_logged "$profile-git-fetch" git -C "$checkout" -c credential.helper= -c protocol.version=2 fetch --no-tags --filter=blob:none --depth=1 origin "$pin"
  test "$(git -C "$checkout" rev-parse FETCH_HEAD)" = "$pin"
  git -C "$checkout" sparse-checkout init --no-cone
  {
    printf '%s\n' '/codex-rs/Cargo.toml' '/codex-rs/hepta-ndu/' '/codex-rs/hepta-types/' '/codex-rs/hepta-contracts/'
    if [[ $adapter == yes ]]; then
      printf '%s\n' '/tools/hia-ndu-bridge/'
    fi
  } | git -C "$checkout" sparse-checkout set --no-cone --stdin
  run_logged "$profile-git-checkout" git -C "$checkout" -c credential.helper= checkout --detach "$pin"
  test "$(git -C "$checkout" rev-parse HEAD)" = "$pin"
  test -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)"
}

fetch_profile ranking d3c2d760eca5065fc966820379c35c6e8d56e855 no
fetch_profile recursive 2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b yes
fetch_profile finite 4b6391e116949af0c7e59776baead67271856bdb yes
fetch_profile stream 8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d yes

# Ranking intentionally uses the existing isolated-production-manifest builder.
# All original upstream non-manifest bytes and the committed local adapter are
# admitted by that builder. No original checkout or adapter is edited here.
run_logged ranking-build env RUSTC="$rustc190" CARGO_TARGET_DIR="$dependency_root/ranking-target" \
  "$gate_python" -B tools/build_hia_ndu_bridge.py \
  --upstream "$dependency_root/ranking-source" --output "$dependency_root/ranking-build" --cargo "$cargo190"
run_logged recursive-build "$gate_python" -B tools/build_hia_recursive_ndu_bridge.py \
  --ndu-source "$dependency_root/recursive-source" --expected-source 2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b \
  --output "$dependency_root/recursive-build" --target-dir "$dependency_root/recursive-target" \
  --cargo "$cargo190" --rustc "$rustc190"
run_logged finite-build "$gate_python" -B tools/build_hia_recursive_ndu_bridge.py \
  --ndu-source "$dependency_root/finite-source" --expected-source 4b6391e116949af0c7e59776baead67271856bdb \
  --output "$dependency_root/finite-build" --target-dir "$dependency_root/finite-target" \
  --cargo "$cargo195" --rustc "$rustc195"
run_logged stream-build "$gate_python" -B tools/build_hia_recursive_ndu_bridge.py \
  --ndu-source "$dependency_root/stream-source" --expected-source 8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d \
  --output "$dependency_root/stream-build" --target-dir "$dependency_root/stream-target" \
  --cargo "$cargo195" --rustc "$rustc195"

stage=identity-admission-and-environment
"$gate_python" -B - "$source_root" "$dependency_root" "$target_file" "$harness_root" \
  > "$dependency_root/logs/identity-admission.stdout" \
  2> "$dependency_root/logs/identity-admission.stderr" <<'PY'
import hashlib, importlib.util, json, shlex, subprocess, sys
from pathlib import Path
root, out, target_path, harness = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('external_gate_harness', harness / 'run-gate.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
target = runner.load_target(target_path)
target_sha = runner.sha(target_path)
if json.loads((out / 'preparation-target.json').read_bytes()) != {'target': target, 'target_file_sha256': target_sha}:
    raise ValueError('target.json changed during dependency preparation')
runner.source_admission(root, target)
sys.path.insert(0, str(root))
from hepta.hia_ndu import NduBridge
from hepta.hia_ndu_optimizer import _bridge_identity
from hepta.hia_ndu_session import NduSession

def write(name, value):
    with (out / name).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')

def fingerprint(path):
    path = Path(path)
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

ranking_path = out / 'ranking-build/build-receipt.json'
ranking = json.loads(ranking_path.read_bytes())
assert ranking['upstream']['commit'] == 'd3c2d760eca5065fc966820379c35c6e8d56e855'
_, ranking_identity = _bridge_identity({'binary': ranking['binary'], 'build_receipt': str(ranking_path)})
native = {}
pins = {
    'recursive': '2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b',
    'finite': '4b6391e116949af0c7e59776baead67271856bdb',
    'stream': '8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d',
}
for profile, pin in pins.items():
    path = out / (profile + '-build/identity.json')
    manifest = json.loads(path.read_bytes())
    assert manifest['identity']['source_commit'] == pin
    expected_rust = '1.90.0' if profile == 'recursive' else '1.95.0'
    assert manifest['identity']['rustc'].startswith('rustc ' + expected_rust + ' ')
    assert fingerprint(manifest['binary'])['sha256'] == manifest['binary_sha256']
    native[profile] = {'path': path, 'manifest': manifest}

recursive = native['recursive']
NduBridge(recursive['manifest']['binary'], recursive['path'])
finite = native['finite']
NduBridge.for_finite_profile(finite['manifest']['binary'], finite['path'])
stream = native['stream']
with NduSession.for_stream_profile(stream['manifest']['binary'], stream['path'],
                                  profile='zero-abstain-v1'):
    pass

environment = {
    'HEPTA_NDU_BUILD': str(out / 'ranking-build'),
    'HEPTA_NDU_BRIDGE': ranking['binary'],
    'HEPTA_NDU_UPSTREAM': str(out / 'ranking-source'),
    'HEPTA_RECURSIVE_NDU_IDENTITY': str(recursive['path']),
    'HEPTA_RECURSIVE_NDU_BRIDGE': recursive['manifest']['binary'],
    'HEPTA_FINITE_NDU_IDENTITY': str(finite['path']),
    'HEPTA_FINITE_NDU_BRIDGE': finite['manifest']['binary'],
    'HEPTA_NDU_STREAM_IDENTITY': str(stream['path']),
    'CLANG': '/usr/bin/clang-20',
    'HEPTA_CLANG': '/usr/bin/clang-20',
    'HEPTA_TEST_CLANG': '/usr/bin/clang-20',
    'RUSTUP_TOOLCHAIN': '1.95.0',
}
after = runner.source_admission(root, target)
if after != json.loads((out / 'preparation-source-before.json').read_bytes()):
    raise ValueError('complete product source changed during preparation')
write('preparation-source-after.json', after)
for profile, pin in {'ranking': ranking['upstream']['commit'], **pins}.items():
    checkout = out / (profile + '-source')
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip() == pin
    assert not subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=all'], cwd=checkout)
write('environment.json', environment)
with (out / 'environment.sh').open('x', encoding='utf-8') as script:
    script.write('export PATH=/usr/lib/llvm-20/bin:"$PATH"\n')
    for key, value in environment.items():
        script.write('export ' + key + '=' + shlex.quote(value) + '\n')
with (out / 'github.env').open('x', encoding='utf-8') as script:
    for key, value in environment.items():
        assert '\n' not in value and '\r' not in value
        script.write(key + '=' + value + '\n')
write('preparation.json', {
    'schema': 'hepta.hia.verified-increment-native-prerequisites.v1',
    'scope': 'PREREQUISITE_BUILD_AND_IDENTITY_ADMISSION_ONLY_NO_GATE_PASS_CLAIM',
    'target': target, 'target_file_sha256': target_sha, 'python': sys.version,
    'harness_files_sha256': {name: runner.sha(harness / name) for name in ('prepare-dependencies.sh', 'run-gate.py')},
    'upstream_repository': 'https://github.com/TrillionniumFoundation/hepta-private-ci',
    'source_pins': {'ranking': ranking['upstream']['commit'], **pins},
    'current_stream_profile': 'zero-abstain-v1',
    'ranking_identity': ranking_identity,
    'ranking_receipt': fingerprint(ranking_path),
    'native_receipts': {name: fingerprint(row['path']) for name, row in native.items()},
    'environment': environment,
    'original_command_streams_retained': True,
    'original_upstream_checkouts_clean_after_build': True,
    'original_adapter_bytes_modified_by_this_harness': False,
    'ranking_uses_existing_isolated_production_manifests': True,
    'native_identity_admission_completed': True,
    'current_stream_handshake_and_close_completed': True,
    'test_suite_executed': False, 'fully_cold_machine_claim': False,
})
print(json.dumps({'prepared': True, 'head': target['commit'], 'environment_file': str(out / 'environment.sh')}, indent=2))
PY
stage=complete
printf 'Prepared native dependencies; source %s/environment.sh before fresh test discovery.\n' "$dependency_root"
