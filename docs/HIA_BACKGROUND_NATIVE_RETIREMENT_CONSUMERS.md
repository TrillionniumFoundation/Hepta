# Background retirement consumers: offline source checkpoint

This checkpoint changes the owned background continuations to consume explicit
release outcomes. The original authoring verifier accepts the generated HIA
within the existing limits. The source-policy probes exercise 67 concrete
consumption and retirement observations. They execute the development policy
text; they are **not native product tests**. Native construction, original API
comparisons, fault controls, concurrency tests, and whole-background
qualification remain pending while the ROG build host is unavailable.

The earlier execution and business-worker reports belong to their earlier
dependency images. They do not qualify this new combination.

## Ownership rule

The release status and consumption are separate facts. Every caller validates
the fixed child's new reply before interpreting its consumption fields.

| Actual reply | Caller action |
| --- | --- |
| Known, not consumed | Keep the same owned reference; a cleanup continuation can retry a proven pre-consumption failure. |
| Known, consumed, retirement retained | Clear the owned reference immediately. Retain the enclosing context and retry only its recorded retirement. |
| Known, consumed, dependency error without a retirement record | Clear the reference, preserve the failed context, and quarantine without replay. |
| Unknown or contradictory reply | Preserve the call record in quarantine. Do not repeat the effect or infer ownership from a status code. |

`tools/hia_background_retirement_source.py` emits the common HIA response
policy. It is a development author dependency, not an installed Python runtime
dependency. The final generated policies contain the selected native helper
functions directly.

Mutable values use `HIABVQ02` operations 29 and 31. The producer's actual
operation-29 statuses are 0, 1, 6, and 11; operation 31 uses only 0, 6, and 11.
A known consumed reference can have status 0 or 11. Unknown status numbers or
contradictory status/consumption pairs are rejected before clearing a slot.
A reply with status 11,
known 1, consumed 1, and pending 0 is a real post-consumption dependency error.
It clears the old capability and enters non-replayable quarantine; it is not
treated as success or as a mapping eligible for operation 31. Reserved reply
words and contradictory flags are rejected.

Jobs use `HIABJO03` operations 11 and 12, with contexts created by operation 13.
The constructor must bind the actual external Future cell and the new Job
retirement mode. An old operation-9 Job context is not silently upgraded.

Future references use `HIABFP03` operation 26. The controller retains its actual
factory lease after a consumed failure. It attempts public operation 20 and
queries the same factory's actual cell with `HIABFQ04` operation 21. Only a
successful locked observation of known 1 / pending 0 clears that obligation.
Operation 20 alone does not establish an empty retirement list. This is
separate from factory-lease retirement operations 27/28 and global close 29.

The older immutable payload and decimal owners have been read at source commit
`485a339defe2bc4b92e298610afff699d6c4eabf`. Their operation-3 status 1, 5, and 6
paths occur before nonce consumption. Their actual release ends in status zero
after node deallocation; cleanup's futex wake does not change that status.
Only those three existing errors are treated as established pre-consumption
failures. Other statuses or malformed replies remain quarantined.

## Changed continuations

| Continuation | Change |
| --- | --- |
| Submission | Releases user/owner Future references and Job references with the new facts; retains pending value, Job, and cell cleanup separately. |
| Account | Applies the same policy to the actual retained Job, Future, report, receipt, and cost references. A retry runs only cleanup and never settles the ledger again. |
| Execution | Clears a consumed reference before recording retained cleanup. Unknown dependency outcomes preserve the exclusive frame without repeating rank, verification, or publication. |
| Business worker | Uses the same fixed consumption policy across normal and fatal-drain releases. A clean account result of actual MemoryError leaves the queue condition before constructing the original fatal error. |
| Shutdown | Cancels selected Futures outside the condition, preserves callback error identity and join precedence, then releases references through explicit consumption and retained cleanup. |

Business retained cleanup after actual pthread exit is still an open part of
the whole controller. These source changes do not turn the previously refused
business operation 3 into a complete cleanup API.

## Captured dependency fields

These pointers and contexts are private constructor captures. They are never
public submit fields or caller-declared proof facts.

| Captured frame | Actual cell entry / context / extent |
| --- | --- |
| Submission, `HIABSSC1` | 800 / 808 / 816; records still start at 1024. |
| Account, `HIABACC1` | Existing 192 / 200 / 208. |
| Business, `HIABWBC1` | 384 / 392 / 400; worker-failure value still starts at 512. |
| Shutdown, `HIABSHC1` | 192 / 200 / 208. |

The constructor obtains each triple from actual public Future operation 17 and
checks that the modules share the same captured factory. It keeps the code,
value context, Job context, factory lease, and all retained frames alive until
their corresponding cleanup is complete. None of these frames may outlive a
borrowed context record.

## Qualification still required

The next live gates must use one coherent build of the extended value owner,
Future/cell owner, Jobs, reference adapter, and queue. They must preserve every
old request domain and then test pre-consumption failure, post-consumption
failure, real unmap errors, pending work claimed by another thread, failed
rollback, repeated cleanup without double drop, source capture, and final
context lifetime. The original execution, account, business worker, shutdown,
callback, and public-constructor behavior must be compared again on that exact
combination. No release, activation, or old-tree retirement is authorized by
this offline source record.
