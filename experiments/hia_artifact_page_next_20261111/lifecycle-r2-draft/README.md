# Private continuation lifecycle correction

The authored guard and five controls in this directory now have actual original/fixed results in `../development-r2-lifecycle/`. The preceding Git checkpoint recorded this same candidate before execution. Both invocations used the real page image f2aaee2be275fb3f8831ae994e4c03f0ec6a12c53892fe8840eb4a4fa8270d3d and source-matching wire image 249f133cd5429956c549917932b8b66ade8431bf47862a4b76e98fb4ea486e31, admitted normally from root source c6067e0d13376e82d72fc28506cb74d77ea69b97. Every observed source/image identity is retained before and after in the raw JSON.

The original adapter passed the ordinary and successful-terminal controls but failed three private API boundaries: stale observe after malformed ACK executed SQL twice; repeated observe before ACK executed SQL twice; and direct foreign BaseException allowed a second attempted SQL operation, changing the same exception's traceback. Row counts alone would conceal INSERT OR IGNORE repetition, so attempted INSERT calls are recorded separately.

The correction checks finished state and consumes an observation permission before calling a foreign operation. A foreign BaseException closes the session and is re-raised unchanged. All five candidate controls passed. The malformed-ACK case executes no SQL; duplicate observe executes the original operation once; foreign failure keeps the original exception object, traceback tail, held traceback identity after refusal, and handled ambient context. No HIA source or page image changed.

The two runs took 13.312895ms and 10.294156ms within a single 316.060151ms bounded process, under the five-second cap. The leader was reaped and its process group was absent. These isolated in-memory SQLite tests establish private continuation behavior, not persistence durability, installed selection, complete AgentStore semantics, large-artifact coverage or whole-native delivery.

The control script accepts explicit --source-root, --draft-root, --adapter, --wire-manifest, fresh --output, and --expect observe/fixed. Raw original failures are immutable; the candidate result does not rewrite them.
