# Fixed installable HIA candidate

This directory publishes the exact locally qualified candidate from source
`d21359485776c0a9687e88d0f69c8ec06a3b3b98`. The archive contains a standard wheel,
its manifest and checksums, the standalone verifier, exact packaging metadata
and two HIA smoke inputs. No Git checkout is needed to verify and install it.

- Version: `0.2.0+hia.gd21359485776.s0ca27dca9ad8`.
- [Bundle](candidate-d21359485776.zip), 999,453 bytes.
- Archive SHA-256: `a2af74269272b6663481f9f8f68b6fe9e38b6f864d5b0d50da8a2c790f980f51`.
- Manifest SHA-256: `4c1e62181f9a611f7e02c00c1b4244e4f343c133b18658260b13bdad8b157a12`.
- [Machine-readable identity](CANDIDATE.json).
- [Complete evidence](../../../evidence/hia_delivery_20261106/README.md).

After downloading the archive, use Python 3.11+ with venv/pip on Linux and new
output directories:

```sh
set -eu
printf '%s  %s\n' a2af74269272b6663481f9f8f68b6fe9e38b6f864d5b0d50da8a2c790f980f51 candidate-d21359485776.zip | sha256sum -c -
python3 -m zipfile -e candidate-d21359485776.zip hia-bundle
python3 hia-bundle/verify_hia_candidate.py --candidate-directory hia-bundle \
  --expected-manifest-sha256 4c1e62181f9a611f7e02c00c1b4244e4f343c133b18658260b13bdad8b157a12 \
  --output hia-installed.json
python3 -m venv hia-env
hia-env/bin/python -I -m pip install --no-index --no-deps \
  hia-bundle/hepta_language-0.2.0+hia.gd21359485776.s0ca27dca9ad8-py3-none-any.whl
hia-env/bin/python -I -m hepta hia run hia-bundle/counter.hia \
  --function increment --arguments '[40]'
hia-env/bin/python -I -m hepta.apps.quota --ledger worker-quota init --initial 100
hia-env/bin/python -I -m hepta.apps.quota --ledger worker-quota apply task-1 reserve 40
hia-env/bin/python -I -m hepta.apps.quota --ledger worker-quota upgrade upgrade-1
hia-env/bin/python -I -m hepta.apps.quota --ledger worker-quota status
```

The counter returns 41; the quota is available=60, held=40 under v2. Verification
uses a temporary isolated installation; the explicit pip command creates the
environment kept for your own use. Add `--clang /path/to/clang-20` to the verifier
for actual native counter compilation/execution on a supported Linux host.

The complete local gate passed 123 regressions and 20 quota tests with zero skips,
equal rebuild bytes and installed native execution. This remains an experimental
candidate. The current remote CI state, failed local attempts, application scope
and unqualified production/productivity claims are retained in the evidence.
