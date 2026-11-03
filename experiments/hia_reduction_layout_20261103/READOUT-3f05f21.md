# Actual Clang20 reduction-layout ablation: no object-level change

This is evidence for source `3f05f2164f79888fa176c1a815edb532a8da7bf1`,
tree `5a0fe6cc3826f4c3f6d83dc71cf747b734ab0ab7`, not for this later evidence commit.

- [Diagnostic CI run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41608520828)
- [Draft implementation PR #585](https://github.com/TrillionniumFoundation/Hepta/pull/585)
- Original artifact ID: 13218325627; name:
  `reduction-layout-diagnostic-3f05f2164f79888fa176c1a815edb532a8da7bf1`.
- Preserved original ZIP SHA-256 (also matches GitHub's digest):
  `d7f6287db7a8b0313bbad7a84bb2006aa42e5999c8f68f5a7029ba37feefcd28`.
- Frozen registration SHA-256:
  `fa9a49c6ebd8a001a91258927f1f5f5766af1da573ca39a6aee824314071904a`.
- Actual compiler: Ubuntu Clang 20.1.8; executable SHA-256:
  `b1ca2b35b07cb5cb7db47247f329151ed22692a19de2763859b0867e6323e2fe`.

## Observations

Eight actual compiler invocations and 30 total recorded commands completed.
The experiment took 10.173506103 seconds (excluding CI setup and tests).
All seven tests passed in CI. Exact source and tool identities remained
unchanged. All 39 artifact inventory SHA-256 values were independently
recomputed from the downloaded ZIP and matched.

For **both** workloads, default, shrink-wrap disabled, and shrink-wrap enabled
produce identical entire object bytes and `.text` bytes. The additional
before/after-MIR printing compile also produces the identical default object.

- Linear object SHA-256:
  `26daeb37aaa980300f6e6a9bf198a3375db47b065204406c7beab0c1fc33e05e`.
- Affine object SHA-256:
  `e2a0c11accb5e0f780de54d8583573a954aafbfb9b242ce38740234e58f19b93`.

This rules out an object-level benefit from these switches on this exact
source/compiler. Identical bytes alone do not prove whether a pass was enabled:
an enabled pass may have no applicable transformation. No timing was needed
or run, and there is no new Rust-performance or P0–P7 qualification claim.

## Evidence toward the actual fixed-cost cause

The linear `shrink-wrap.mir.txt` shows the entry block already defining the
callee-saved `$ebp` and `$rbx` through parameter copies before the large-length
guard and n=0 branch. Its relocation-aware assembly still begins with three
register saves. This is consistent with early register definitions constraining
frame placement; it is not a complete compiler causal proof. The experiment
rejects simply forcing shrink-wrap as a useful fix. A distinct future proposal
would need to alter the early live-range/layout cause and independently test
correctness and the complete unchanged timing protocol, rather than repeating
the existing thin wrapper or excluding slow samples.

## Recheck without native execution

The ZIP contains REGISTRATION, RESULT, all Core/LLVM/proof/object/MIR files,
full bounded command receipts, and the actual focused-test log.

```python
import hashlib, json, zipfile
z = zipfile.ZipFile('ci-3f05f21.zip')
r = json.loads(z.read('reduction-layout/RESULT.json'))
assert r['status'] == 'completed'
assert r['source_unchanged'] and r['tools_unchanged']
for name, expected in r['artifact_sha256'].items():
    assert hashlib.sha256(z.read('reduction-layout/' + name)).hexdigest() == expected
for w in ('linear', 'affine'):
    default = z.read(f'reduction-layout/{w}/default.o')
    for arm in ('shrink_wrap_off', 'shrink_wrap_on', 'default.trace'):
        assert z.read(f'reduction-layout/{w}/{arm}.o') == default
```

All three applicable workflows on the implementation HEAD passed: this
compile-only lane, actual-host ABI, and upstream C++ host qualification.
Those statuses do not qualify the later evidence commit or establish a
speedup. The original performance gate is unchanged.

`authority=DENY_ALL`, `production_activation_allowed=false`,
`performance_qualified=false`, `timing_performed=false`.
