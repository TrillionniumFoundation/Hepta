# Complete native batch edit-context renderer

This development component implements the complete `render_batch_context` sequence using two HIA kernels and the source-bound native owners for caller-specific input policy 2, single-query rendering and general Graph JSON wire. No hosted renderer, JSON decoder, canonical comparer, signature lookup or batch merge algorithm is used by the forwarding loop.

Revision 2 closes two direct-interface controls recorded against revision 1. The initial Graph default root must be a valid one-based node, even when the command selects another valid subtree. Revision 1 deferred an invalid default root to the real bounded-input peer, which already rejected it; this was not acceptance by the complete public pipeline. More substantially, a forged prefix error code outside the fixed policy-2 set was previously copied after GROW as a semantic error. Revision 2 rejects it as BAD before reserving diagnostic storage. Policy-2 errors are exactly code 2/cause 0/detail 0; code 30 with cause 1/detail 0..2 or cause 2/detail 0; and code 1000 plus a public decoder code (1..6 or 101..120), with cause 3/detail 0. These are private issued-frame checks. Original public error ordering and all inventory/presentation algorithms are unchanged.

The control image owns normalization coordination, top/site/nested validation, snapshot comparisons, ordered single-renderer admission, signature/block/operation conflict checks and all batch inventories. The emit image owns complete function/block/operation/callee display construction, ordering, native subtree-wire continuations and final bytes. Both use one private workspace. Image dispatch is a fixed event operation; it does not return a host-interpreted semantic plan.

Public incremental capture of arbitrary Python objects, Python subclass lookup/equality behavior and installation of a public exception wrapper remain separate work. A Graph supplied by a trusted mechanical test issuer is not proof of those open boundaries.

## Original order and normalized source

The first native call is the existing bounded-input owner with policy 2. It alone preserves the batch query's original 1 MiB text/bytes/general-object ordering, full wire wrapping, and subsequent public integer JSON decoding. The batch controller does not duplicate or weaken that prefix.

On successful prefix completion, HIA selects the complete actual normalized Graph view. The executor makes this exact issued view immutable and rebinds the first input for the next call. Root, complete Graph header and extent are pinned by HIA. This is a private issued-view transition, not acceptance of an arbitrary header with the same nonce.

After normalization, each site retains the original order:

1. Exact site identity and nested query/schema.
2. Base and input snapshot comparisons in the original key order, including actual native wire calls before the single-renderer gate.
3. Context/selector shape.
4. The complete actual native single renderer, whose successful output may be discarded only after its final event.
5. The current site's selected-instruction overlap, signature/function, block metadata, source operations, edit marker, callees and downstream inventories in their original order.
6. Only then the next site.

A later malformed site cannot replace an earlier conflict diagnostic. The component retains all original 1..16 sites, single-query limits and arbitrary-width nonnegative source-operation indices.

## Canonical comparison proof

For values retained from two sites, both enclosing single queries have already passed their complete original bounded-wire gate. Under the same immutable graph and serialization profile, every referenced subtree is no larger in structural traversal or canonical byte length than its admitted enclosing query. Its later wire call therefore cannot add a refusal.

The normalized Graph contains the original integer JSON subset with unique string object keys. On this domain, equal canonical bytes are equivalent to structural equality with exact JSON kinds/scalars, ordered arrays and unordered object keys. The HIA comparer implements that relation, including complete arbitrary-width integer magnitudes and signs. It does not use Python equality (which could conflate bool/int), does not ignore unknown operation metadata, and does not compare only displayed fields. Dictionary key lookup and the equality stack are native. This replaces only non-refusing later comparisons, not the earlier snapshot wire calls.

## Growth and inventory commit

The normalized tree supplies a finite count of actual nodes. Name and pair tables derive their capacity from that count. Dictionary-key entries, retained callee occurrences and affected-name occurrences can each be charged to distinct nodes in the normalized tree, so their combined pair-table capacity introduces no additional language quota. These tables store native Graph IDs and offsets.

A current site's inventory pass may repeat after workspace growth. Each persistent insertion either allocates its complete record before publishing it or commits a value already proven canonically equal to the previous one. Linked-list insertion occurs only for new keys. The selected-instruction marker includes the current site number: repeating that same site's pass is idempotent; a different site remains an overlap error. Thus successful partial commits cannot conceal a later conflict or reorder the first conflict. No semantic call is hidden in the host and no pending external peer is repeated during such growth.

After collection, presentation planning uses a separate arena checkpoint. GROW may rebuild this pure rope plan while preserving the complete inventory. Final subtree wire filling retains all actual native calls and output bytes. The final display has no extra 1 MiB output cap.

## Entry and BEGIN

Both images use RWW buffers: current immutable issued Graph, a second buffer borrowed read-only, and the same private mutable workspace. Initial workspace is zero and at least 32,768 bytes. Short buffers return BAD; when state is writable its failure marker is persistent. Every BAD lease must be discarded.

The control kernel takes the initial 64-byte command:

`[HIABRC01, graphLease, request, rootNode, integerDigitLimit, 0, 0, 0]`

Lease/request are nonzero and rootNode belongs to the initial Graph. Correlation fields are not external source authentication.

## Events

Ordinary return is 256. The 32 u64 words at workspace offset zero are:

`[HIABRE01, action, lease, request, phase, neededWorkspace, peerKind, serviceSequence,`
` sourceView, sourceOffset, sourceBytes, commandOffset, commandBytes, peerInitialWorkspace,`
` outputOffset, outputBytes, errorDomain, errorCode, causeKind, abiReason, pendingRoot,`
` nextKernel, keepSecondOnGrow, 0,0,0,0,0,0,0,0,0]`

Actions:

- 0: complete display; view is owned by this workspace.
- 1: grow workspace, copy all old bytes, keep the current first Graph. Preserve the exact second input when keepSecondOnGrow is 1; otherwise replace it with the empty buffer.
- 2: invoke a fixed peer with the selected source/command views.
- 3: complete public refusal text in the owned output view.
- 4: rebind the first Graph to the exact selected view in the current second reply; next second input is empty.
- 5: dispatch to the emit kernel (nextKernel=2), preserving workspace/current Graph and using an empty second input.

Source view 0 is the current first Graph; view 1 is the current second reply. Command views are always in this workspace. For the three peer kinds the selected source is the complete current Graph.

Peer kinds are 1 (native Graph wire), 2 (native bounded-input policy 2), and 3 (complete native single renderer). Each request contains the actual complete corresponding 64-byte HIA command. The executor must not derive a replacement command by parsing fields.

Peer response is the following 64-byte header followed by the complete actual final peer workspace:

`[HIABRR01, lease, request, peerKind, serviceSequence, actualReturn, workspaceBytes, 0] + workspace`

ActualReturn is 128 for all three existing peers. The controller validates correlation, extent and complete terminal metadata. Before any terminal branch, it pins the full transport and event headers across GROW, so a success-to-error substitution cannot bypass the check. Identical headers still do not authenticate changed payload bytes; fixed immutable issuer custody remains required.

The prefix-success Graph view remains in the actual peer allocation until the executor has made the issued rebind view immutable. The batch workspace retains only offsets and copied metadata. Subsequent sources must preserve the exact pinned Graph header and extent.

## Errors and states

Error domain 1 is a batch-owned diagnostic; 2 is a Graph-wire diagnostic; 3 is the complete bounded-input diagnostic; 4 is the complete single-renderer diagnostic. HIA renders or copies the complete original text. Domain/cause metadata does not manufacture Python exception objects or tracebacks.

Phases 1, 14, 15, 16 and 42 may require the same second reply during GROW; the explicit event flag is authoritative for the executor. Phase 3 consumes the issued Graph transition. Phases 8/10/11/12/20 collect and phases 40/41/43 present using empty continuations as indicated. Final phase 90 is success and 99 is refusal. Neither can be restarted.

Private source/header/workspace mutation controls and complete public differential evidence are recorded separately. This protocol document and a generated image alone are not qualification.

