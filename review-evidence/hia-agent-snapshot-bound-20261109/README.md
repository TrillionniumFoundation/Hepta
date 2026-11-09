# Bound actual new-file capture in the repository Agent recorder

Base: `20eace37747fde9aa0fc9c14cdb0159db30f5161` (the #816 source merge).

The original recorder charged a path's earlier `stat().st_size`, then used an
unbounded `read_bytes()`. A growing or replaced file could make retained bytes
exceed the frozen new-file allowance and make `new_files_total_bytes` disagree
with the retained evidence. The authored stale-stat control reproduces the
accounting defect: the original charges 1 byte while retaining 9 bytes.

The fix reads through retained directory descriptors with `O_NOFOLLOW`, checks
the opened file's regular-file/one-link contract, reads at most the remaining
allowance plus one rejection byte, counts actual retained bytes, and rejects
size or metadata changes across the read. The existing 32 MiB allowance is
unchanged. This is not an atomic whole-repository snapshot or a security sandbox.

Validation:

- `original-regression.log`: one expected failure on the original source;
  no error or skip. Replay from the repository root with
  `PYTHONPATH=. python3 -B review-evidence/hia-agent-snapshot-bound-20261109/replay_original.py`.
- `fixed-tests.log`: the entire repository-trial module passes **26/26**,
  zero failures/errors/skips. Four new controls cover actual-byte accounting,
  growth beyond the remaining cap, same-length mutation, and symlink parents.
- `python3 -B tools/generate_hia_selfhost_contract.py --check` passes for the
  existing v13 profile and 251 source files. This recorder is not a selfhost
  implementation dependency.

These are authored local transport tests. They contact no model/provider or
installed service and establish no new stranger-Agent task outcome or fee.
The original select extension still requires preservation on the old accepted
source domain and specified semantics on its new domain. The current four-claim
interface has no checker proving that language-extension relation for the frozen
compiler. General compiler lowering proof and the original provider interaction,
invoice and complete monetary costs remain **HOLD/unknown**.
