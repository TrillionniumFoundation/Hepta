# Original metadata-review CodeQL failure

The original [run 42568595280](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42568595280)
belongs to head `9d30ae193e1b316dd14042100017f95e9733a3ee`, attempt 1.
Three jobs succeeded. Rust job `129000513550` failed during Initialize CodeQL:
the official `codeql-bundle-v2.27.4/codeql-bundle-rust-linux64.tar.zst` download,
including the Action's own fallback and retries, returned HTTP 504. Autobuild
and Rust analysis did not run. The underlying gateway cause is unknown.

`files.json` preserves the original run, all four job records, the complete
24,373-byte Rust log and the observer's failure review without changes. The
original manifest SHA256 is
`63dd6d099ad724e9e9e210fbd2546058117cd9fd6c05500d76a620307df76671`;
the original log SHA256 is
`1b1f4410e87d72afcb3419a58d4a3cb131906f42c5b210404684ad0c4e130877`.

After verifying those retained files, the integrating reviewer requested one
standard GitHub rerun of only the failed job. GitHub returned HTTP 403:
`Jobs in this workflow run cannot be re-run`. The full returned envelope and
request subject are in `rerun-request-result.json`. No attempt 2 was created.
The original observer's zero-rerun field predates that integrating-reviewer
request and remains unchanged.

The original run has event `dynamic` and path
`dynamic/github-code-scanning/codeql`. GitHub's [Default setup debugging guidance](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/logs-not-detailed-enough#creating-codeql-debugging-artifacts-for-codeql-default-setup)
describes triggering new analysis with a new pull-request commit. This evidence
addition therefore receives its own normal default-setup analysis. It does not
disable, weaken, replace or mark successful the failed check. No scanning
configuration, retry setting, source implementation or permissions were changed.
The next commit's result must be recorded under its own identity.
