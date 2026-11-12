# OPEN draft: exact singleton truth inside the existing HIA continuation

## Intended narrow ownership

The proposed change only handles runtime TRUTH requests whose staged object handle is 1, 2 or 3. The existing literal decoder requires the first three values to be None, False and True, checks exact bool types, and rejects duplicate object identities. LoweringSession initially builds values = [None, *owner.literals], then maps the identities of those entries to their indices. Constant truth is already folded by Function.truth; this draft concerns runtime references that become those handles.

The HIA helper returns a tag: 0 means retain the original foreign observation; 1 means false; 2 means true. It reads the exact handle already staged at output offset64. The existing effect_lines code still checks sequence overflow first, increments the sequence, writes phase1, the next PC, opcode, zero result destinations and the complete original request header. Only after those exact writes does a recognized singleton change workspace flag40 and phase8 to the state that a successful original ACK would have produced, then use the existing internal return4.

This preserves logical sequence numbers and the prepared header/state for later effects under the stated invariant. It avoids a second host type classifier and uses the existing HIA get/put helpers. It changes neither the literal pool nor the IR instruction inventory, CHUNK64, protocol magic, image routing, or the other 18 primitive implementations. A shared scalar helper is appended only to control units containing opcode10; pool_source and all existing helper definitions are unchanged.

## Blocking lifetime counterexample

There is no proven lifetime invariant in the current source. LoweringSession.values is a publicly writable Python list; handles is a writable dictionary. NativeCoreLowering.literals can also be rebound. register checks an existing id-to-value mapping only when register is called; value(handle) subsequently reads the current values list directly. No phase-boundary validation freezes that list.

Consequently, after a session has been initialized, replacing values[2] with an object whose __bool__ returns true or raises causes the original hosted TRUTH operation for handle2 to observe that object. The proposed classifier would instead return false without the callback. A foreign callback holding the session can perform the same mutation. Rebinding the owner pool before session construction can also invalidate initialization assumptions. Private-method replacement of value/_primitive or mutation of the builtins.bool lookup presents further unclosed domains; these are not silently assumed away.

A source-level witness, not an executed test:

    class TruthWitness:
        def __bool__(self):
            events.append("observed")
            return True

    # session is a valid current LoweringSession constructed by a future control.
    session.values[2] = TruthWitness()
    # Original _primitive(10, (2,), ()) calls bool(session.value(2)).
    # Proposed HIA tag2-handle rule would classify False and skip the callback.

This experiment has NOT executed that witness, built a fixture, or claimed a regression result. It is a direct control-flow counterexample visible in the exact source and blocks integration of the unconditional draft. A future design must either maintain the original observable mutability or establish an approved, explicit immutable-session boundary. Merely rechecking the pool at construction, putting the check in a docstring, or trusting the initial hashes does not solve it.

## Step, observe, sequence and error boundary

The existing public methods step/observe expose each TRUTH request as status1 plus a one-use observation permission. A direct caller can inspect its opcode/header, submit an invalid ACK, or mutate state between those methods. The draft removes that intermediate return for three handles. Even with an immutable registry, it therefore cannot claim full step/observe trace equivalence. Its prospective semantic claim could only concern an explicitly bounded higher-level invocation contract. No such scope decision is made by this draft.

The complete original sequence-overflow refusal precedes the classifier, including when the handle is a known singleton. Unknown handle0 and every handle outside1..3 use the unchanged foreign path and retain its value validation and Python truth behavior. The shape guard requires opcode10, one argument, no vector and zero destinations; other shapes retain the original request. All original state/header preparation remains before the new branch. Directly observable native-step counts would decrease and must be measured again; the previous v2 matrices cannot be reused.

Known-handle registry mutation, value/_primitive replacement, bool lookup replacement and asynchronous exception windows around removed host returns remain OPEN. This draft does not label their behavior equivalent or weaken the session's pending/finished guards.

## Source artifacts and validation boundary

candidate/generate_hia_core_lowering.py.txt is a complete source-text candidate intended only for review. It is not installed at the product path. Removing its three recorded textual edits reproduces the exact original renderer bytes. No Python parse, IR generation, HIA rendering, native compilation, Core VM execution, fixture or workflow has run for it. No generated HIA asset or manifest is supplied.

Before any later integration, the lifetime and direct-protocol issues above must be resolved. Then a new source-bound authoring revision must regenerate all affected units, preserve the old per-function block/SSA/parameter/edge caps and produce an exact regenerated bundle. Keep the existing complete v2 denominator (15 component methods plus51 original machine plus50 original Core,116 total), a single original180/3 owner for complete qualification, all original cold/build limits and all refusal controls. Do not substitute three development groups for that complete gate.

Additional controls must distinguish all three singleton values from int0/int1, empty/nonempty values, foreign __bool__/__len__, and invalid/forged handles; preserve foreign callback and exception order; compare post-ACK workspace/header/sequence at internal boundaries; exercise maximum sequence refusal, cross-unit handoff, yield/resume and one-use permission. Mutation and direct-step counterexamples must be included with an explicit expected contract, not removed. These are planned controls only.

No speedup is claimed. No product selector, workflow, shared contract, original39-source custody or existing116 result is changed.

