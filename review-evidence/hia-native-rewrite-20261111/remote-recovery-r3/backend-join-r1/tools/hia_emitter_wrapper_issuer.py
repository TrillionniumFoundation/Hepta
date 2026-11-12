"""Wrapper tape -> real Code command/ACK continuation, entirely HIA.
The unchanged Function issuer is a source dependency, never a runtime callback.
Every edit below is anchored to one exact original fragment, then pruned by the
real entry call graph. A new namespace keeps Function sessions incompatible.
"""
import ast
FUNCTION_ISSUER_SHA="f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219"
TAPE_OWNER_SHA="332a8633a13f09fcc6021ebdf1f916e97b65b93f4b875b57264abf7eb93b0287"
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
def once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
RESULT_BODY=r'''
def result(s:readbuf, w:mutbuf) -> u64:
    total = 256 + get(w, S_NAME_N)
    fill_range(w, COMMAND_AT, total, 0)
    put(w, COMMAND_AT, RESULT)
    put(w, COMMAND_AT + 8, 1)
    put(w, COMMAND_AT + 16, get(w, S_LEASE))
    put(w, COMMAND_AT + 24, get(w, S_REQUEST))
    put(w, COMMAND_AT + 32, get(w, CONFIG + 80))
    put(w, COMMAND_AT + 40, get(w, S_CODE_LEASE))
    put(w, COMMAND_AT + 48, get(w, S_CODE_SEQ))
    put(w, COMMAND_AT + 56, get(w, S_BEGIN))
    put(w, COMMAND_AT + 64, get(w, S_CODE_N))
    put(w, COMMAND_AT + 72, word(s, TAPE_BASE + 112))
    put(w, COMMAND_AT + 80, get(w, S_SERIAL))
    put(w, COMMAND_AT + 88, COMMAND_AT + 256)
    put(w, COMMAND_AT + 96, get(w, S_NAME_N))
    put(w, COMMAND_AT + 104, COMMAND_AT + 256)
    put(w, COMMAND_AT + 112, get(w, S_NAME_N))
    put(w, COMMAND_AT + 120, total)
    put(w, COMMAND_AT + 128, word(s, TAPE_BASE + 144))
    put(w, COMMAND_AT + 136, word(s, TAPE_BASE + 152))
    put(w, COMMAND_AT + 144, 1)
    copy_bytes(w, s, COMMAND_AT + 256, get(w, S_NAME_AT), get(w, S_NAME_N))
    put(w, S_RESULT_N, total)
    return 0
'''
def source(frame_owner,function_issuer):
    body,constants,_=function_issuer.source(frame_owner)
    # ast.unparse is deliberately not used to locate the exact old edits:
    # the frozen BODY, rather than a version-dependent pretty print, is pinned.
    text=function_issuer.BODY
    text=once(text,"def issue_function(","def issue_wrapper(")
    text=once(text,"    message(w)\n","")
    text=once(text,"if word(s, TAPE_BASE + 80) == 0 or word(s, TAPE_BASE + 80) > word(s, TAPE_BASE + 88):",
                   "if word(s, TAPE_BASE + 80) > word(s, TAPE_BASE + 88):")
    text=once(text,"    at = TAPE_BASE + 144\n",'''    kind = word(s, TAPE_BASE + 144)
    extent = word(s, TAPE_BASE + 152)
    if kind != 1 and kind != 2:
        return fail(w, 66)
    if (kind == 1 and extent != 0) or (kind == 2 and (extent == 0 or extent > 1048576)):
        return fail(w, 67)
    frame = word(s, TAPE_BASE + 112)
    if frame == 0 or frame > 65536 or (frame & 15) != 0 or word(s, TAPE_BASE + 136) != 96:
        return fail(w, 68)
    at = TAPE_BASE + 160
''')
    text=once(text,"if effect > 3 or (effect != 0 and opcode != 2):",
                   "if effect > 3 or effect == 2 or (effect != 0 and opcode != 2):")
    text=once(text,'''    if effect == 2 and get(w, S_CODE_N) > 16777216:
        put(w, S_ACTION, 2)
        put(w, S_DOMAIN, 2)
        put(w, S_ERROR, 1)
        put(w, S_RESULT_AT, TEXT_AT)
        put(w, S_RESULT_N, MESSAGE_N)
        return 0
''',"")
    text=once(text,"get(w, S_NAME_N) > MAX - COMMAND_AT - 320",
                   "get(w, S_NAME_N) > MAX - COMMAND_AT - 256")
    text=once(text,"put(w, S_NEED, COMMAND_AT + 320 + get(w, S_NAME_N))",
                   "put(w, S_NEED, COMMAND_AT + 256 + get(w, S_NAME_N))")
    old_nodes={n.name:n for n in ast.parse(body).body}
    new_nodes={n.name:n for n in ast.parse(text).body}
    new_nodes["result"]=ast.parse(RESULT_BODY).body[0]
    # Preserve the already expanded eight-byte primitives and shared arity
    # implementation. No Function state or output view is accepted at runtime.
    for name in ("word","get","put"):
        new_nodes[name]=old_nodes[name]
    names=dict(old_nodes);names.update(new_nodes)
    live={"issue_wrapper"};pending=["issue_wrapper"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    order=["issue_wrapper"]+[n.name for n in ast.parse(text).body if n.name!="issue_wrapper"]
    order += [name for name in old_nodes if name not in order]
    nodes=[names[name] for name in order if name in live]
    constants=dict(constants)
    constants.update(STATE=magic("HIAWIS01"),INPUT=magic("HIAWIC01"),
        EVENT=magic("HIAWIE01"),TAPE=magic("HIAWRT01"),
        TAPE_EVENT=magic("HIAWRE01"),RESULT=magic("HIAWIR01"))
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="WRAPPER_TAPE_ACTUAL_CODE_COMMAND_ACK",
        function_issuer_reference_sha256=FUNCTION_ISSUER_SHA,wrapper_tape_sha256=TAPE_OWNER_SHA,
        original_private_admitted_Core_and_manifest_required=True,
        scalar_serial_zero_allowed=True,wrapper_global_symbol_name_copied_from_actual_tape=True,
        no_wrapper_block_budget_added=True,actual_Code_error_and_partial_state_preserved=True,
        own_GROW_before_commit=True,Code_GROW_exact_same_immutable_command=True,
        every_failed_private_ABI_permanently_poisons_lease=True,header_is_authentication=False,
        whole_Emitter=False,whole_backend=False,installed=False,cold=False)
