def validate_execution_observation(status, ledger, *, steps, max_steps, max_heap_bytes,
                                   error_code=None, with_chains=False, allow_host_memory=False,
                                   live_external_roots=0):
    """Check finite wire/accounting invariants, without running or admitting Core.

    Return, program trap and evaluator stop remain distinct. In particular a
    stopped invocation may retain resources; its observation must not erase
    those resources by contradicting the allocation/owner/loan counters. This
    validates a summary, not the truth of a producer or any program semantics.
    Normal errors and cooperative cancellation represented as values obey the
    ordinary-return rule. Host termination and arbitrary unwinding are absent.
    A reference adapter may supply separately checked live external roots as
    context, never as Core heap allocations or wire-ledger fields. The default
    remains the closed, VM-owned-root contract used by raw/native observers.
    """
    def need(condition, message):
        if not condition:
            raise ExecutionObservationRejected("E_HIA_EXECUTION_CONTRACT: " + message)

    need(type(status) is str and status in {"returned", "trapped", "budget_exceeded"},
         "unknown execution outcome")
    need(type(with_chains) is bool and type(allow_host_memory) is bool, "exact profile flags required")
    need(type(live_external_roots) is int and 0 <= live_external_roots < 1 << 64,
         "external root count must be an exact unsigned u64 integer")
    fields = EXECUTION_RESOURCE_FIELDS | (EXECUTION_CHAIN_FIELDS if with_chains else frozenset())
    need(type(ledger) is dict and set(ledger) == fields, "resource field inventory differs")
    need(all(type(value) is int and 0 <= value < 1 << 64 for value in ledger.values()),
         "resource counters must be exact unsigned u64 integers")
    need(type(steps) is int and type(max_steps) is int and 1 <= max_steps <= 10_000_000
         and type(max_heap_bytes) is int and 0 <= max_heap_bytes <= 1024 * 1024 * 1024,
         "invalid explicit evaluator limits")
    allocated, freed = ledger["allocations"], ledger["frees"]
    created, dropped, live = ledger["owners_created"], ledger["owners_dropped"], ledger["live_owners"]
    nonempty = allocated - freed
    need(freed <= allocated <= ledger["allocation_attempts"] and allocated <= created
         and freed <= dropped <= created and live == created - dropped,
         "allocation and owner conservation differ")
    need(0 <= nonempty <= live and nonempty <= ledger["live_bytes"]
         and (nonempty == 0) == (ledger["live_bytes"] == 0),
         "live payload is inconsistent with live allocation/owner counts")
    need(ledger["loans_ended"] <= ledger["loans_started"]
         and ledger["live_local_loans"] == ledger["loans_started"] - ledger["loans_ended"],
         "local loan conservation differs")
    need(live > 0 or live_external_roots > 0 or ledger["live_local_loans"] == 0,
         "a live loan has no live byte owner")
    need(ledger["live_bytes"] <= ledger["peak_bytes"] <= max_heap_bytes,
         "live/peak payload exceeds the explicit heap policy")
    if with_chains:
        need(ledger["chains_consumed"] <= ledger["chains_created"]
             and ledger["live_chains"] == ledger["chains_created"] - ledger["chains_consumed"]
             and ledger["chain_nodes_dropped"] <= ledger["chain_nodes_created"]
             and ledger["live_chain_nodes"] == ledger["chain_nodes_created"] - ledger["chain_nodes_dropped"],
             "recursive chain conservation differs")
        # Each still-live chain node owns its distinct payload and node-storage
        # byte owners, even after a quota interrupts iterative destruction.
        need(2 * ledger["live_chain_nodes"] <= live, "chain nodes have missing byte owners")
    if status == "returned":
        need(error_code is None, "ordinary return cannot carry an error outcome")
        need(live == ledger["live_local_loans"] == 0
             and (not with_chains or ledger["live_chains"] == ledger["live_chain_nodes"] == 0),
             "ordinary scalar return retains resources")
    else:
        permitted = TRAP_CODES if status == "trapped" else frozenset({"steps", "heap", "calls"})
        if status == "budget_exceeded" and allow_host_memory:
            permitted |= {"host_memory"}
        need(type(error_code) is str and error_code in permitted, "unknown or misclassified stop code")
    tick_stop = status == "budget_exceeded" and error_code == "steps"
    need(steps == max_steps + 1 if tick_stop else 1 <= steps <= max_steps,
         "tick count contradicts the execution outcome")
