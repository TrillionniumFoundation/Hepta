# P3 native-host evidence retention

Exact base PR #43: `3937cfd964d5ec3e58ed1f00d5012a547c14b1df`.

The Windows 2025 x86_64 real-host ABI job failed on the parent source:
`host compile/link/run trace differs`. The previous error handler replaced
the entire completed raw trace with a minimal error JSON. Consequently the
failing compiler argv/paths were inaccessible in artifact evidence.

This diagnostic increment preserves the *unqualified* command transcript and
relevant object/toolchain identities in a **failed** report. The strict
compile/link/execute command comparison remains unchanged; a more informative
mismatch includes exact expected and observed argv, without making any string
normalization assumption. Negative unit tests guarantee that both rejection
paths return exit 1 and status failed; they do not qualify Windows ABI.

Run `python -m unittest tests.test_native_host_evidence -v` and the
Windows-only source-bound workflow. Use the resulting raw mismatch to
determine whether the path identity is a normalizable representation
difference or an actually wrong executable target. Do not change equality
until the evidence supports a safe canonicalization rule.

All P0–P7/P01–P12 blockers remain OPEN/PARTIAL.
