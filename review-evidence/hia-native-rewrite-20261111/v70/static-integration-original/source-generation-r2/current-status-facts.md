## Current v70 candidate: reconstructed static budget integration, qualification pending

This candidate starts from the published `8ca2197693c98e48d0d16ab3c077efc7cd535653`
tree `d9a0a779301d25ffbfdc1601ed86ce0d76a9236b`. Its 2,994 retained
paths were restored and checked against their exact Git blob identities and
modes. The lost local `92fbc134f522c9cff616419b9555056e7cdd7d51`
commit object, author identity and tree have not been recovered. The current
candidate is **NEW_RECONSTRUCTION_FROM_SAVED_OWNER_FILES**: the 14 complete
source files in the verified `9028d181` archive plus the preserved 17-path
registration recipe. It does not inherit the lost integration's Git identity,
unknown source-gate result or qualification. The original attempt to admit the
incremental bundle failed because prerequisite `f5bb6d4a2014fc43a14737b92bc94e21e5b3be4b`
was absent; that failure and the unchanged bundle remain retained.

The original complete `e03c82d1` qualification has finished with **HOLD**.
All 32 stages actually ran. Total runner time was 6,760.128471506992 seconds.
Full discovery ran 4,583 tests with four failures and one error, and zero skips,
expected failures or unexpected successes. Unittest reported 3,464.998 seconds;
the enclosing full-retained step took 3,468.475736 seconds. The five top-level
failures were an identity-worker empty-JSON error, the namespace caller wrapper,
the ledger caller wrapper, and two scalar-proof identity assertions that
expected `unknown` but observed `proved`. The nested manifest fixture for
the identity-worker case was later repaired in `7d664e7d`; that later
observation does not change the original error.

The original full-run namespace and ledger nested panels each reported one
failure and one error across their 35 and 48 controls. Their original
three-second and 1,000-millisecond deadlines are unchanged. A subsequent complete
read of the original compact evidence identified the two reference-loop
`RequestJournalUnknown` causes: the test callback's
`assertGreater(remaining, 0)` failed with remaining values
`-0.7292891502380371` and `-0.7449177265167236`, with the message
`fixture preparation exhausted the original context budget`. The original
trace runs through ticket `run`/`encode_response(invoke())`, service
`evaluate`, and the test callback. The unknown acknowledgement classification
remains intact; it is not recast as an ordinary `E_BUDGET` result or a pass.
Earlier records that had not yet recovered this cause remain historical evidence.
The complete original compact observation is 36,308 bytes, SHA256
`391f270c3bdca4465455c54c3e4912f41521323aa14b9a9ca028eb38693fe2e5`, retained as
[Git blob b3da5d03](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/b3da5d034fbbf90ed65216477b8fc9e4ea251c2f).
For context, the original e03 source closure has 751 entries totaling 20,198,062
bytes. Multiplying that static size by 98 preparations gives 1,979,410,076 bytes;
this is a static estimate, not measured runtime I/O.

All three original `8ca` Core CI runs failed:

| Run | Original native-stage result | Later result |
| --- | --- | --- |
| `43070250214` | Cold timeout after 180.185358450 seconds | Source job also failed on stale coverage support identity |
| `43070309546` | Cold passed 11/11 checks in 135.457622031 seconds | Stopped at `validate_inventory`; actual language cases did not run |
| `43070317835` | Cold timeout after 180.210550521 seconds | Source job also failed on stale coverage support identity |

The two timed-out cold runs recorded only six of eleven checks; owned process
cleanup completed. The original 180-second plus three-second cleanup bounds
remain unchanged. The earlier 26-control source panel did not include the
failing inventory gate and therefore did not establish a complete source-CI
pass.

The two original scalar-proof fixtures patched only `totality.__file__`,
while `checker_source_identity` reads `checker_identity.__file__`.
The repaired fixture adds the actual owner's path patch and positive assertions
that its source-lock SHA changes and is restored, retaining the original three
test names and assertions. Its exact source SHA256 is
`03cbde73f488afc7b44dbc0fd25b785a35ffa4acd8cda19feabc72c10558be0e`.
A separate e03 fixture candidate passed 3/3 controls with no failure, error or
skip: unittest 0.135 seconds, runner 0.141893857 seconds. After copying that
fixture to the restored 8ca tree, the original `coverage_manifest` generation
and `validate_inventory` passed. That 176,645-byte coverage file changed only
its semantic support identity and had SHA256
`1da737da6e955e75b5d20bf18230827467b27a3e78e2d0f81bf5ce986d3ac049`.
Those are two-file repair observations. The static candidate must generate its
own coverage and rerun the original three controls; the earlier hash and results
are not imposed on the new source.

The original proof failures, exact fixture candidate, patch, freeze, summary,
raw test log, published-source restoration, static archive restoration and
two-file application record are retained in
[the fixed v70 recovery commit](https://github.com/TrillionniumFoundation/Hepta/tree/cc79242ffb316ce3fbc1f2fd858a99886d2b5bb7/review-evidence/hia-native-rewrite-20261111/v70/recovery).
The original full-run failure index is retained in
[the fixed e03 evidence revision](https://github.com/TrillionniumFoundation/Hepta/blob/378d60da59ada59690768757849d2ac3fa836510/review-evidence/hia-native-rewrite-20261111/v69/recovery/e03-final-failure-index.json).
The reconstruction recipe and unavailable-workspace custody are retained in
[the fixed recovery recipe commit](https://github.com/TrillionniumFoundation/Hepta/tree/70bc0a6c57d9536664c7cba4bc665a3dc8ada854/review-evidence/hia-native-rewrite-20261111/v69/recovery).

Whole-native delivery, default activation, live migration and old-stack deletion
remain **false**. Adding the structural-budget candidate does not close public
live-heap policy, complete public normalization, all general backend profiles,
service and worker behavior, CLI/build/provider paths, or scalar-proof policy.
The `541a` normalization candidate still has its two cause-preservation
boundaries, physical stack behavior and Python 3.14 exception-note behavior open.
The structural owner also retains its explicit heap and final JSON/hash foreign
continuations. Final retirement is authorized, but it requires actual native
replacements and a fresh qualified chain before old owners can be removed.

