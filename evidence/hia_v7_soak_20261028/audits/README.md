# Independent execution audits

The tested source is `f5b6598bdd88db92c4ef2b17e10deda9a90bdd59`. These audits read retained evidence; they did not execute new project tests, native calls, compiler invocations or hosted retries.

- [System audit view](system-final-v1.summary.json): 2,729 unique Python IDs, 56 Rust tests, 35 executed gates / 34 passed. Its complete 1,938,268-byte audit is retained at `independent/final/system-final-v1.json` in the raw archive, SHA256 `8d9ba853c62f085f1cd0e4e85c84a07902408584b7dbc12fd2d5d6ec8da06f96`.
- [Hosted failure audit](soak-failure-v1.json): 23,852 journal records, 4,982 attempts/starts/reaps and 4,981 complete observations. Evidence integrity does not turn the failed qualification into a pass.
- [Separate causal review](soak-causal-review.json): the five-second observation failure is recorded; its underlying cause is unresolved. No code correction or retry was justified by the recorded evidence.
- [Initial inventory assumption](soak-failure-v1.initial-inventory-assumption.json): an explicitly superseded audit draft. It incorrectly assumed the filesystem registration inventory was a subset of the Git-tracked inventory. The final audit distinguishes the scopes and verifies 1,155 common files plus 117 extra registered ignored NDU inputs. This was an audit assumption error, not observed source drift. The draft and correction script remain in the raw archive.

Audit assertion counts, repeated observations and overlapping native controls are not additional unique project tests. Performance remains unqualified, hosted qualification remains failed, and the original broader obligations remain open.
