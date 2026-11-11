# Isolated Actions authoring control, r5

Status: STATIC, UNEXECUTED. No create trigger ref has been created by this control author.

The fixed product base is 0d653c0987e941c7f6afb4db67e23fccf854f4e0 / 821414603284a005f0957a1f0ac93c48c3c51e5a. Fifteen exact input files come from 93cb486293799da333f80f65351ba71d20f45547; they include the shared terminal guard and implementation identity dependencies. The only candidate product changes admitted are the eighteen paths in policy.json. A successful source snapshot has 3,941 regular leaves, versus 3,933 in the base. The original three workflows remain byte-for-byte intact.

Control commit A contains these scripts and immutable inputs but no additional workflow. Workflow commit B is a direct successor of A adding only .github/workflows/hia-instructions-authoring-isolated.yml. The root agent must independently review B before creating the one branch named in policy.json. All control, workflow and eventual evidence commit messages contain [skip ci]. There is no dispatch, schedule, push or PR trigger for the new workflow. Its create guard requires the exact repository, branch, ref_type=branch and run_attempt=1.

## Execution scope

The author job has contents:read. It checks out the exact product base into source and A into control, independently, both depth one and without persisted credentials. Python 3.14.4 setup is separate from authoring. The actual interpreter binary SHA and version are recorded; the desktop interpreter hash is not claimed. No unnecessary toolchain/dependencies are installed.

The source worker copies all fifteen verified files, parses Python inputs, generates the HIA source, repeats the complete public assembly render/parse roundtrip and the original document_caps function copied verbatim from the frozen desktop worker, then generates coverage and support, checks support and source scope, and verifies the exact eighteen-path real Git index delta. All source leaves and source pins are retained. Its unchanged source-bound process owner imposes 180 seconds plus the original 3-second cleanup; each existing author command retains its 120-second local timeout. Setup and post-owner evidence capture have separate records. The GitHub step has a 4-minute transport ceiling, which is not a product deadline extension.

No native image is compiled or executed. No product test, 12-method component, original 51-caller suite, cold qualification or full discovery executes. Earlier desktop UNKNOWN/failures and older state passes are not reclassified. The shared state guard/identity changes still require their own 12+51 requalification.

## Publication and failure preservation

The publisher is a distinct job. It alone receives contents:write; its token is explicitly provided only to the final publisher step. It does not check out or execute candidate code and launches no subprocess. Two public fixed control files are downloaded from A and hash-checked before the token-bearing step. The Actions artifact action carries the original author bundle between jobs; the publisher checks its entire membership and bytes, the original owner/commands, run/control identity, source snapshots, and allowlist. It independently reconstructs the Git tree hash.

Only the frozen eighteen product paths plus a new run-specific experiment prefix can enter a result tree based on the exact product base tree. Earlier base leaves and workflows are checked intact. The result commit has the product base as first parent and the actual reviewed workflow commit B as its additional parent. A result ref includes the fixed prefix and actual run ID/attempt. Only POST git/refs creates it. No PATCH, force update, default/PR branch update, pull request or dispatch is used.

Every original author file is either directly readable UTF-8 or represented by complete 49,152-byte base64 pieces plus offsets, SHA256 and original Git blob SHA. Oversize/binary original files remain recoverable; bytes are not summarized in place of originals. A failure is still published with HOLD and available raw outputs. Invalid/missing author evidence cannot supply product paths or a source PASS. The publisher's own final requests/responses and receipt remain in a separate always-uploaded artifact because a commit cannot contain its own final acknowledgement. Git content and the exact final ref are read back before success.

Mutating API calls are never replayed. A lost blob/tree acknowledgement may only be reconciled by GET of its independently computed Git ID. A lost commit acknowledgement remains HOLD. A lost create-ref acknowledgement may only be reconciled by GET of that precise ref and exact expected commit. No replacement key/ref or new attempt is synthesized. A successful publication is custody, and does not qualify native execution.

## Source boundaries

The control prepares a new Actions run. It is not a repair or replay of the original remote r2, the two extra automatic CI runs, or the frozen exact608 full attempt. Python orchestration here is an explicitly retained development/qualification control, not a claim that production HIA self-rewrite is finished.

Primary documentation reviewed: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#create ; https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs ; https://docs.github.com/en/actions/concepts/security/github_token . The create event uses the created branch/tag; skip markers apply to push/PR. No default-branch workflow change is needed for this isolated create event. Repository policy can still reject write permission or a workflow; that is a HOLD rather than an invitation to request a broader token.
