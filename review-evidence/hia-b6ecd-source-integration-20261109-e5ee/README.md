# Qualified v16 source integration

**Both source baselines now point to the same qualified commit: `6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35`.**

Before either ref update, the original qualification cohort was read back as 19 successful workflows: 17 on attempt 1, Shared on attempt 2 and Guarded on attempt 3. Its 115 latest job records comprise 114 successes and one conditional workflow-dispatch skip. The complete [frozen CI packet](../hia-b6ecd-ci-final-20261109-e5ee/final-readback.md) retains original failures, reruns, logs, job identities and checkout scope.

Two normal expected-SHA, non-force fast-forwards retained the qualified source commit and its existing ancestry:

| Baseline | Previous SHA | New SHA | GitHub PR closure |
| --- | --- | --- | --- |
| `codex/hia-sixgap-source-5e6c-20261108` | `20eace37747fde9aa0fc9c14cdb0159db30f5161` | `6ecd8023615a6e0b2dc269379fb059c656b38b6f` | [PR817](https://github.com/TrillionniumFoundation/Hepta/pull/817), merged 06:21:19 UTC |
| `codex/hia-sixgap-source-6d5c-20261108` | `2598f4309791d3a023cd5df585ad26810b20c744` | `6ecd8023615a6e0b2dc269379fb059c656b38b6f` | [PR808](https://github.com/TrillionniumFoundation/Hepta/pull/808), merged 06:21:21 UTC |

The files retain the actual precondition snapshot, exact commit tree and parents, update responses, both post-update Git refs and merged PR metadata. GitHub's PR wrapper retained stale base-SHA fields at this observation; the actual Git-ref endpoints independently bind the new baselines. The qualified final commit has parents `20eace37747fde9aa0fc9c14cdb0159db30f5161` and `50262236d9d1807ca8df0eccfb9f5f7ee9f6206c`.

Integration itself creates no different source tree. It does not merge the full source into the metadata-only main branch, select a new default release, or activate an online runtime. Public main was still `74063163ad19d096a4ff9a66a6f25728e6ce0d8f`, selecting the qualified v9 lock.

New runs automatically triggered by these baseline updates form a **separate post-integration cohort**. The original successful 19-run snapshot does not hide or override new failures. In particular, post-integration [Guarded attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42572528876) failed after four pinned-Lean HTTP 504 download responses; its proof step did not run. Its separate record retains that failure.

The broader six-track acceptance remains HOLD for the outstanding Core, general-correctness, original Agent task and economic obligations. Source qualification and integration are bounded engineering results.

