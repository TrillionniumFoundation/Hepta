# Verification environment and portable test selection

The published repair is [d8e1b676665093c416a3484c3d7d7e0ceffe3207](https://github.com/TrillionniumFoundation/Hepta/commit/d8e1b676665093c416a3484c3d7d7e0ceffe3207), parent **7ef57d1b**. It exports the installed Lean/Clang environment and pinned QEMU/lld aliases before both full qualifications, and removes development-machine tool paths from two native test classes. No compiler source, benchmark implementation, frozen protocol, acceptance threshold or native negative-control body changes.

Installing verification tools alone did not make them available to later workflow steps. The actual source tests also use the ordinary `qemu-aarch64` name, while the locked installer produces `qemu-aarch64-static`. Explicit `CLANG`, `RUSTC`, `HEPTA_LLD` and `HEPTA_QEMU_AARCH64` selections now reach the native tests as actual executable paths; a missing explicit selection does not fall back. Every skipped test still fails complete qualification.

## Development checks and failures

All seven original logs are retained. They describe working-tree development checks, not a complete immutable-candidate qualification.

| Attempt | Tests | Actual terminal result |
| --- | ---: | --- |
| Initial workflow harness | 8 | One harness error: absent `__unittest_skip__` attribute |
| Skip-attribute correction | 8 | Passed |
| Initial actual native/formal checks | 5 | One failure: bulk qualifier received a bare `ld.lld` name; other four passed |
| Absolute-path workflow checks | 9 | Passed |
| Actual native/formal checks after resolution | 5 | Passed; no skips |
| Final environment/collector checks | 10 | Passed; no skips |
| Default-PATH actual edit-study check | 1 | Passed with `CLANG` and `RUSTC` unset |

The five native/formal tests cover actual composite-bulk execution, edit-study values and declared overflow boundaries, plus three selected Lean proof/receipt controls. The separate one-test run closes the default-PATH issue identified by independent read-only review. These are real tool executions, but the test-owned temporary binaries were cleaned up; this appendix preserves the logs, not those binaries. The small shell fixtures used by environment tests are never counted as real native or proof evidence.

The final six environment checks execute the actual workflow Bash with paths containing spaces, verify the exports inherited by subsequent steps, fail before export when a required installed tool is missing, and check explicit missing selection, default PATH binding and actual test-class/formal-tool selection. Four existing tests additionally cover strict zero-skip qualification and required CLI wiring.

`source-identities.json` binds all six changed files to the published Git tree. `change.patch` is the exact parent-to-candidate diff. `development-review.json` records the original log identities, outcomes and scope limits. Compiler and frozen benchmark code remain byte-identical to the parent. These targeted results do not replace [the candidate's complete CI run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827706).

## Check retained bytes

From this directory, the following checks every retained member without executing native code:

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
