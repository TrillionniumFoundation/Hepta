# Hepta / HIA

HIA is a typed virtual assembly language for programs authored by AI agents and verified optimization, with independent Core semantics, ownership and resource checks, interpretation, and direct LLVM compilation.

This `main` branch currently provides the discovery and installation entry for the fixed candidate below. Use that candidate for the capabilities described here. Complete historical source integration into `main` remains unfinished; existing release gates continue to apply.

## Fixed candidate

- **Source:** [`d21359485776c0a9687e88d0f69c8ec06a3b3b98`](https://github.com/TrillionniumFoundation/Hepta/tree/d21359485776c0a9687e88d0f69c8ec06a3b3b98)
- **Manifest SHA-256:** `4c1e62181f9a611f7e02c00c1b4244e4f343c133b18658260b13bdad8b157a12`
- **Download:** [candidate bundle, 999,453 bytes](https://github.com/TrillionniumFoundation/Hepta/raw/636c3189722e9bb48c39913e779d688c4e8cbcb3/releases/hia/20261106/candidate-d21359485776.zip), with [offline installation instructions](https://github.com/TrillionniumFoundation/Hepta/blob/636c3189722e9bb48c39913e779d688c4e8cbcb3/releases/hia/20261106/README.md).
- **Evidence snapshot:** [`636c3189722e9bb48c39913e779d688c4e8cbcb3`](https://github.com/TrillionniumFoundation/Hepta/tree/636c3189722e9bb48c39913e779d688c4e8cbcb3)
- **Recorded CI run:** [candidate checks](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42263076114)

The full local qualification passed 123 regression tests and 20 application tests, with zero skips, identical rebuild bytes and installed native execution. The [recorded remote candidate job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42263076114/job/128047788052) subsequently completed successfully on 2026-11-06 at 18:23 UTC for the exact source `d21359485776c0a9687e88d0f69c8ec06a3b3b98`, including the clean-source, application and installed-candidate verification step and artifact upload. This is the status of that candidate run, not production qualification or evidence for later source changes.

The full source commit and manifest digest identify this candidate. Branch names and earlier CI results do not substitute for those identities.

## Rebuild, verify, and install

Use Python 3.11+ and Git on Linux, with the directories below absent. Fetch the complete commit explicitly:

```sh
set -eu
git init hia-candidate
git -C hia-candidate remote add origin https://github.com/TrillionniumFoundation/Hepta.git
git -C hia-candidate fetch --depth=1 origin d21359485776c0a9687e88d0f69c8ec06a3b3b98
git -C hia-candidate checkout --detach FETCH_HEAD
cd hia-candidate
test "$(git rev-parse HEAD)" = "d21359485776c0a9687e88d0f69c8ec06a3b3b98"
python3 tools/build_hia_candidate.py --output-directory ../hia-bundle
python3 tools/build_hia_candidate.py --output-directory ../hia-bundle-repeat
cmp ../hia-bundle/SHA256SUMS ../hia-bundle-repeat/SHA256SUMS
python3 tools/verify_hia_candidate.py --candidate-directory ../hia-bundle \
  --expected-manifest-sha256 4c1e62181f9a611f7e02c00c1b4244e4f343c133b18658260b13bdad8b157a12 --output ../hia-installed.json
cd ..
python3 -m venv hia-env
hia-env/bin/python -I -m pip install --no-index --no-deps hia-bundle/hepta_language-0.2.0+hia.gd21359485776.s0ca27dca9ad8-py3-none-any.whl
hia-env/bin/python -I -m hepta hia run hia-bundle/counter.hia \
  --function increment --arguments '[40]'
```

The counter must return `41`. The verifier checks exact package bytes and exercises installed verification, interpretation, LLVM emission, and the quota application's initialization, reservation, upgrade, and recovery. For native compilation and execution with an explicit supported Clang 20+ toolchain, follow the [candidate delivery guide](https://github.com/TrillionniumFoundation/Hepta/blob/d21359485776c0a9687e88d0f69c8ec06a3b3b98/docs/HIA_RELEASE_CANDIDATE.md).

## Scope and evidence

This is an experimental, installable candidate. Production qualification, HIA performance or Agent productivity gains, and NDU net benefit are not claimed. The linked receipts record the checks actually performed; LLVM emission alone does not establish execution on another architecture.

See the pinned [compatibility contract](https://github.com/TrillionniumFoundation/Hepta/blob/d21359485776c0a9687e88d0f69c8ec06a3b3b98/docs/HIA_COMPATIBILITY.md), [quota application](https://github.com/TrillionniumFoundation/Hepta/blob/d21359485776c0a9687e88d0f69c8ec06a3b3b98/docs/HIA_QUOTA_APPLICATION.md), and [intelligence and value protocol](https://github.com/TrillionniumFoundation/Hepta/blob/d21359485776c0a9687e88d0f69c8ec06a3b3b98/docs/HIA_INTELLIGENCE_CONTRACT.md) for supported behavior and remaining limits.
