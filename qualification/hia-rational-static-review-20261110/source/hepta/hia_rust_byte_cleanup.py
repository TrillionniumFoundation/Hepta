"""Bounded cleanup journal/request checks; no Python semantic admission.

The pinned Rust Machine performs discharge. This module checks the retained
wire's complete parent/root graph, topological release order, exact counters,
static reservation identity and unchanged original stop. It never releases a
resource, runs the Core or imports a verifier/normalizer/evaluator.
"""
MAX_CLEANUP_ACTIONS = 32768


def validate_cleanup(report, request, body, entry_bound):
    # Local import avoids a module initialization cycle; only wire primitives
    # are reused, not a Python resource analysis or execution oracle.
    from .hia_rust_byte_dag import _keys, _equal, _unsigned, _reject
    bound, cleanup = report["cleanup_bound"], report["cleanup"]
    maximum_formals = max(sum(p["type"] in {"readbuf", "mutbuf"} for p in f["params"])
                          for f in body["functions"])
    actions_bound = (entry_bound["max_allocator_interactions"]
                     + entry_bound["max_vm_ticks"] * (1 + maximum_formals))
    if not actions_bound <= request["cleanup_policy"]["max_cleanup_actions"] <= MAX_CLEANUP_ACTIONS:
        _reject("cleanup reservation does not cover the structural inventory bound")
    _equal(bound, {
        "schema": "hepta.hia.scoped-abort-cleanup-bound.v1",
        "program_sha256": request["program_sha256"],
        "function": request["function"], "arguments": request["arguments"],
        "max_allocator_interactions": entry_bound["max_allocator_interactions"],
        "max_vm_ticks": entry_bound["max_vm_ticks"],
        "max_borrowed_parameters": maximum_formals,
        "action_bound": actions_bound,
        "limit_actions": request["cleanup_policy"]["max_cleanup_actions"],
        "fixed_action_limit": MAX_CLEANUP_ACTIONS,
        "claims": {
            "independent_static_reservation_before_execution": True,
            "every_allocator_outcome_including_empty_owner_counted": True,
            "call_formal_witnesses_counted_separately": True,
            "runtime_observation_used_to_establish_bound": False,
            "process_rss_or_cpu_bound_proved": False,
        },
    }, "cleanup static bound and exact request")
    run = report["runtime"]["execution"]
    stopped = run["status"] != "returned"
    fixed = {
        "schema": "hepta.hia.scoped-abort-cleanup.v1",
        "status": "completed" if stopped else "not_needed",
        "scope": "entire_private_scalar_invocation", "error": None,
        "reserved_actions": actions_bound, "call_formal_loans_after": 0,
        "before": run["resources"],
        "claims": {
            "explicit_machine_resource_discharge": True,
            "cleanup_uses_reserved_actions_not_execution_ticks": True,
            "journal_reserved_before_language_execution": True,
            "user_destructors_or_callbacks_executed": False,
            "host_panic_oom_or_termination_cleanup_guaranteed": False,
            "process_rss_or_cpu_bound_proved": False,
            "general_unwind_or_native_cleanup_proved": False,
        },
    }
    _keys(cleanup, set(fixed) | {"inventory_records", "inventory_records_checked",
          "call_formal_loans_before", "actions", "events", "after"}, "scoped cleanup report")
    _equal({k: cleanup[k] for k in fixed}, fixed, "cleanup phase/pre-ledger/claims")
    events = cleanup["events"]
    if type(events) is not list or len(events) > actions_bound:
        _reject("cleanup journal exceeds its pre-execution reservation")
    _equal(cleanup["actions"], len(events), "cleanup action count")
    loans, owners = {}, {}
    owner_phase = False
    previous_loan = previous_owner = 1 << 64
    for event in events:
        if type(event) is not dict:
            _reject("cleanup event is not an object")
        if event.get("op") == "end_loan" and not owner_phase:
            _keys(event, {"op", "loan", "root_owner", "parent_kind", "parent",
                          "mutable", "call_formal"}, "cleanup loan event")
            for key in ("loan", "root_owner", "parent"):
                if not 1 <= _unsigned(event[key], key) <= actions_bound:
                    _reject("cleanup loan identity is outside admitted inventory")
            if (event["loan"] >= previous_loan or event["parent_kind"] not in {"loan", "owner"}
                    or type(event["mutable"]) is not bool or type(event["call_formal"]) is not bool):
                _reject("cleanup loan order or flags are invalid")
            previous_loan = event["loan"]
            loans[event["loan"]] = event
        elif event.get("op") == "drop_owner":
            owner_phase = True
            _keys(event, {"op", "owner", "bytes"}, "cleanup owner event")
            identity = _unsigned(event["owner"], "owner identity")
            _unsigned(event["bytes"], "released payload")
            if not 1 <= identity < previous_owner or identity > run["resources"]["owners_created"]:
                _reject("cleanup owner identity/order differs from runtime inventory")
            previous_owner = identity
            owners[identity] = event
        else:
            _reject("cleanup must end every loan before releasing any owner")
    for identity, event in loans.items():
        if event["root_owner"] not in owners:
            _reject("cleanup loan has no discharged owner root")
        if event["parent_kind"] == "owner":
            if event["parent"] != event["root_owner"] or event["call_formal"]:
                _reject("cleanup owner-parent or formal provenance is invalid")
        else:
            parent = loans.get(event["parent"])
            if (parent is None or event["parent"] >= identity
                    or parent["root_owner"] != event["root_owner"]
                    or event["mutable"] and not parent["mutable"]):
                _reject("cleanup loan parent/root graph is incomplete or cyclic")
    before = run["resources"]
    formals = sum(event["call_formal"] for event in loans.values())
    local_loans = len(loans) - formals
    if (len(owners) != before["live_owners"] or local_loans != before["live_local_loans"]
            or local_loans != before["loans_started"] - before["loans_ended"]
            or sum(event["bytes"] for event in owners.values()) != before["live_bytes"]
            or sum(event["bytes"] != 0 for event in owners.values())
                != before["allocations"] - before["frees"]):
        _reject("cleanup journal does not discharge the complete original ledger")
    records = len(events)
    _equal({key: cleanup[key] for key in ("inventory_records", "inventory_records_checked",
           "call_formal_loans_before")}, {
        "inventory_records": records, "inventory_records_checked": records if stopped else 0,
        "call_formal_loans_before": formals,
    }, "cleanup inventory/formal checks")
    if not stopped and events:
        _reject("normal return must already be clean without an abort repair")
    after = {**before, "live_owners": 0, "live_bytes": 0, "live_local_loans": 0,
             "owners_dropped": before["owners_dropped"] + len(owners),
             "loans_ended": before["loans_ended"] + local_loans,
             "frees": before["frees"] + sum(event["bytes"] != 0 for event in owners.values())}
    _equal(cleanup["after"], after, "exact post-cleanup ledger")
