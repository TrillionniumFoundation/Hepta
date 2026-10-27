# Host procfs observation failure: repair and actual controls

Published repair: [44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314](https://github.com/TrillionniumFoundation/Hepta/commit/44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314), parent **d8e1b676**. The actual targeted probes executed local commit **e9ef62969201659b9c9415362b2200df17c5572d**. Both commits have exactly tree **b8cf0ef7d1a7b8a367308bbb28c4b0fcf0786157**. Original reports keep their actual local commit; they were not relabelled as a hosted run.

The full 7ef CI report contains a `PermissionError` for host `/proc/1/root/.../parent_oracle_canary`. In the exact qualifier source, that access happens while assembling optional host existence metadata after the real boundary child has responded. Its exception prevented the boundary result from being returned; the report retained startup success and nine `not_run` checks. It did not record an accepted boundary escape.

The repair keeps present, absent and unobservable host observations separate. An access denial or another host stat error records `host_exists: null`, `host_stat_status: unobservable`, and the actual errno. It does not become false/absent. The three required host canary/private-module preconditions, actual sandbox `os.open` checks, namespace requirements, empty procfs, capability dropping, environment/network/mount restrictions, two native checks, and ten-check release acceptance remain unchanged.

## Actual controls

| Control | Actual observation | Acceptance |
| --- | --- | --- |
| Ordinary host metadata | All 10 real namespace/boundary/native checks passed | Strict release collector accepted |
| Injected host-only procfs `EACCES` | Host metadata is unknown with errno 13; all 10 real checks still passed | Strict release collector accepted |
| Deliberately exposed synthetic canary, with the same host-stat denial | Actual canary became readable inside the namespace; `parent_paths_unreadable` failed; both later native checks stayed `not_run` | Strict release collector rejected |

The host-stat error is explicitly injected for the second and third local controls; the namespaces, boundary child, compilers and positive native programs actually execute. The third control adds a read-only mount of **only a newly created qualification marker**, using a patched test command. It does not alter production sandbox configuration or expose a real credential. This proves that unknown optional host metadata does not make a readable canary pass.

`probe.py` is the exact executed driver, with its hash bound in `originals/review.json`. It checkpoints each of the three planned controls and retains their complete original JSON. `native.log` is its exact terminal log. `unit.log` records nine passing namespace/configuration regressions, including real ordinary stat results, injected `EACCES`/`EPERM`/`EIO`, and required-host-input rejection before execution. The temporary native binaries were removed by the original qualifier; the reports preserve commands and hashes, not those binaries.

These are targeted controls. The published candidate's [full CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114) supplies a separate unchanged-source acceptance result. They do not count as model trials or a general sandbox-escape proof. `source-identities.json` and `change.patch` bind the reviewed source change and the unchanged production sandbox, release collector and Hepta compiler.

To check archived bytes without executing native code:

```sh
python3 - <<'PYVERIFY'
import hashlib, json
from pathlib import Path
root = Path('.')
manifest = json.loads((root / 'MANIFEST.json').read_text())
for item in manifest['files']:
    data = (root / item['path']).read_bytes()
    assert len(data) == item['bytes']
    assert hashlib.sha256(data).hexdigest() == item['sha256']
print('Verified', len(manifest['files']), 'retained files')
PYVERIFY
```

To perform a **new actual run**, use the intended candidate checkout with its pinned Rust compiler and working strict Bubblewrap namespaces, then invoke this driver with `--rustc /absolute/path/to/rustc --output /new/output/directory`. A new run cannot overwrite these original reports.
