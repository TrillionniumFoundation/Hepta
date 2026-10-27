# QEMU locked package source repair

The two earlier hosted failures and one local GET returned HTTP 503 from the
configured Ubuntu snapshot URL. This observation does not establish the
service or network root cause. The same local probe downloaded 14,709,858 bytes
from the explicit Ubuntu archive URL with the existing locked package digest.
`source-observation.json` preserves both actual results and their timestamps.

The lock changes only `source`. Package digest, executable digest and version
are unchanged. The installer still uses a single configured URL, strict
content checks, a fresh staging directory and publication after verification.

## Actual fresh installation

The actual `bootstrap_verification.py --qemu-only` invocation used a new target,
downloaded from that configured source, unpacked the package and returned zero.
The resulting 6,245,816-byte executable has the locked SHA-256:

```text
e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e
```

`fresh-install.json` retains the exact command, source and lock hashes, native
version execution and log hashes. Its additional raw version-string equality
check returned false because the executable writes one terminal LF while the
lock stores no terminal LF; its original `ok=false` is preserved. `review.json`
records the subsequent data-only check: the actual bytes equal the lock text
plus exactly one LF and match the existing `validate_cross.py` normalization
(`stdout.strip()`). No download, installation or version execution was repeated
to replace the original observation.

The executable identity check and actual installer return code succeeded. This
repair does not change the compiler, benchmark protocol or toolchain content,
and it is not evidence that a later hosted CI qualification completed. The
downloaded package and installed tool remain in temporary local directories;
this directory retains their identities and logs, not their full binary bytes.

The checkout base was `8dcb0d0d8aabfa6bd260305c57344ce15ef72eca`; the recorded
lock hash identifies the explicit source edit tested before publication.

Run `python verify.py` in this directory to verify retained bytes and the
specific source/identity observations without any network or native execution.
