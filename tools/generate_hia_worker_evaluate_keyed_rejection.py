"""Carry authenticated, keyed Evaluate refusals through the original Journal transaction."""

INGRESS = '''
def refuse_business(o:mutbuf,w:mutbuf,reason:u64) -> u64:
    # Baseline and the original scalar tag have their existing identities.
    # The other workload planner codes are shifted by ten in this envelope.
    if reason != 1 and reason != 2 and (reason < 11 or reason > 28 or reason == 12):
        return close_store(o,w,CLOSE_REFUSED)
    put(w,BUSINESS_REASON,reason)
    return close_store(o,w,CLOSE_ERROR)

def classify_workload(o:mutbuf,w:mutbuf,fd:u64,size:u64) -> u64:
    hold(w,WORKLOAD_BODY,fd,0,size)
    if get(w,BASE_METADATA+16) == 0:
        return close_store(o,w,CLOSE_REFUSED)
    store(o,HEADER,91)
    store(o,496,44)
    use_span(w,o,BASE_METADATA,0)
    fragment(o,1,INLINE_FRAGMENT,496,1)
    fragment(o,2,fd,0,size)
    return action(o,w,CASE_OPERANDS,MAKE,0,0,3,1)

def claimed_rejection(o:mutbuf,w:mutbuf) -> u64:
    if get(w,CLAIM_ACTIVE) != 1 or get(w,JOURNAL_STAGE) != 2 or get(w,JOURNAL_NEXT) != 11 or slot_bytes(w,STORE_RESULT) != 56:
        return BAD
    put(o,HEADER,REJECTION)
    put(o,HEADER+8,get(w,64))
    put(o,HEADER+16,get(w,CLAIM_UTC))
    put(o,HEADER+24,get(w,BUSINESS_REASON))
    put(o,HEADER+32,512)
    put(o,HEADER+40,64)
    put(o,HEADER+48,8)
    copy_private(w,o,BUSINESS_CONTEXT,HEADER+56,36)
    copy_private(w,o,JOURNAL_STATE,HEADER+92,512)
    copy_private(w,o,JOURNAL_ROUTE,HEADER+604,64)
    fragment(o,0,slot_fd(w,STORE_RESULT),0,8)
    if get(w,BUSINESS_REASON) == SHAPE_REASON:
        put(o,HEADER,SCHEMA_QUERY)
        after_prefix(w,o,ARGUMENT_FD,1)
        return action(o,w,ERROR_CLAIMED,MAKE,0,0,2,668)
    return action(o,w,ERROR_CLAIMED,MAKE,0,0,1,668)

def rejection_progress(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    fd = input_word(s,32)
    size = input_word(s,40)
    if state == BASE_SCOPE:
        if plan_ok(s) == False or size != 24 or input_word(s,72) != BUSINESS:
            return close_store(o,w,CLOSE_REFUSED)
        reason = input_word(s,80)
        if reason == 28:
            return refuse_business(o,w,reason)
        if reason != 0:
            return close_store(o,w,CLOSE_REFUSED)
        return retain_body(o,w,slot_fd(w,RAW_BODY),slot_bytes(w,RAW_BODY))
    if state == EARLY_LIMIT:
        if plan_ok(s) and size == 24 and input_word(s,72) == BUSINESS and input_word(s,80) == 23:
            return refuse_business(o,w,23)
        if plan_ok(s) == False or size != 24 or input_word(s,72) != CONTEXT_WINDOW:
            return close_store(o,w,CLOSE_REFUSED)
        total = input_word(s,80)
        if total < 1 or total > 86400000:
            return close_store(o,w,CLOSE_REFUSED)
        put(w,LIMIT_WALL,total)
        put(w,CHECK_CONTEXT_WINDOW,1)
        return read_span(o,w,CREATION_OBSERVED,get(w,CREATION),get(w,CREATION+8),get(w,CREATION+16))
    if state == CASE_OPERANDS:
        store(o,496,93)
        fragment(o,0,fd,0,size)
        fragment(o,1,INLINE_FRAGMENT,496,1)
        return action(o,w,CASE_CHECKED,RUN,BINDING_ROLE,0,2,0)
    if state == CASE_CHECKED:
        if plan_ok(s) == False or size != 24 or input_word(s,72) != BUSINESS:
            return close_store(o,w,CLOSE_REFUSED)
        reason = input_word(s,80)
        if reason > 0:
            return refuse_business(o,w,reason)
        return retain_body(o,w,get(w,WORKLOAD_BODY),get(w,WORKLOAD_BODY+16))
    if state == ERROR_CLAIMED:
        if get(w,BUSINESS_REASON) == SHAPE_REASON:
            if slot_bytes(w,ARGUMENT_FD) <= 8 or size != 668+slot_bytes(w,ARGUMENT_FD) or input_word(s,64) != SCHEMA_QUERY:
                return BAD
        elif size != 676 or input_word(s,64) != REJECTION:
            return BAD
        fragment(o,0,fd,0,size)
        return action(o,w,INTAKE_PUBLISHED,PUBLISH,0,0,1,0)
    return BAD
'''


def ingress(driver, policy, controls, constants):
    constants.update(BUSINESS=int.from_bytes(b'HIAEQB01','little'),
                     REJECTION=int.from_bytes(b'HIAERJ01','little'), BUSINESS_REASON=3224,
                     BUSINESS_CONTEXT=3240,BASE_METADATA=3280,WORKLOAD_BODY=3312,CLOSE_ERROR=58,
                     CASE_OPERANDS=104,CASE_CHECKED=105,ERROR_CLAIMED=106,EARLY_LIMIT=107,BASE_SCOPE=109,
                     CONTEXT_WINDOW=int.from_bytes(b'HIAEWD01','little'),CHECK_CONTEXT_WINDOW=3352)
    constants.update(SHAPE_REASON=256,SCHEMA_QUERY=int.from_bytes(b'HIAESQ01','little'))
    constants.update(EVALUATE_BASE_OBSERVE=int.from_bytes(b'HIAEAR01','little'),
                     EVALUATE_ARTIFACT_REFUSAL=int.from_bytes(b'HIAEAR02','little'))
    policy=policy.replace('    put(o, HEADER, RETAINED_OBSERVED)',
                          '    put(o,HEADER,choose(get(w,SELECTOR) == 1,EVALUATE_BASE_OBSERVE,RETAINED_OBSERVED))')
    policy=policy.replace('    if state == ART_OBSERVED:', '''    if state == ART_OBSERVED:
        if get(w,SELECTOR) == 1 and get(w,ACTIVE_KIND) == 7 and plan_ok(s) and size == 24 and input_word(s,72) == EVALUATE_ARTIFACT_REFUSAL:
            reason = input_word(s,80)
            if reason == 26 or reason == 27:
                return refuse_business(o,w,reason)
            return close_store(o,w,CLOSE_REFUSED)''')
    policy=policy.replace('    if state == INPUT_SCHEMA:', '''    if state == INPUT_SCHEMA:
        if reply_word(s,1):
            put(w,BUSINESS_REASON,SHAPE_REASON)
            put(w,CLAIM_ACTIVE,1)
            return send_journal(o,w,9)''')
    driver=driver.replace('    return intake(s, o, w, state)',
                          '    if (state >= CASE_OPERANDS and state <= EARLY_LIMIT) or state == BASE_SCOPE:\n'
                          '        return rejection_progress(s,o,w,state)\n    return intake(s, o, w, state)')
    policy=policy.replace('    if state == CTX_OBSERVED:', '    if state == CTX_OBSERVED:\n'
                          '        if plan_ok(s) and size == 24 and input_word(s,72) == CONTEXT_OBSERVED_TAG:\n'
                          '            status = input_word(s,80)\n'
                          '            if status == 1 or status == 2:\n                return refuse_business(o,w,22)')
    policy=policy.replace('    if state == DOCUMENT_BOUND:\n        observe_slot(s, w, BIND_PREFIX)',
                          '    if state == DOCUMENT_BOUND:\n        observe_slot(s, w, BIND_PREFIX)\n'
                          '        if get(w,SELECTOR) == 0 or get(w,SELECTOR) == 1:\n'
                          '            store(o,496,93)\n            whole_slot(w,o,BIND_PREFIX,0)\n'
                          '            fragment(o,1,INLINE_FRAGMENT,496,1)\n'
                          '            return action(o,w,choose(get(w,SELECTOR) == 0,EARLY_LIMIT,BASE_SCOPE),RUN,BINDING_ROLE,0,2,0)')
    policy=policy.replace('        deadline = get(w, UTC_DEADLINE)\n        if now >= deadline',
                          '        deadline = get(w, UTC_DEADLINE)\n'
                          '        if get(w,CHECK_CONTEXT_WINDOW) == 1:\n'
                          '            put(w,CHECK_CONTEXT_WINDOW,0)\n'
                          '            if now > deadline:\n                return refuse_business(o,w,21)\n'
                          '            return retain_body(o,w,slot_fd(w,RAW_BODY),slot_bytes(w,RAW_BODY))\n'
                          '        if now >= deadline')
    policy=policy.replace('        hold(w, ACTIVE_REFERENCE, fd, 16, 100)',
                          '        copy_span(s,w,80,BUSINESS_CONTEXT,36)\n        hold(w, ACTIVE_REFERENCE, fd, 16, 100)')
    policy=policy.replace('        if index < retained:\n            return append_binding',
                          '        if index == 1:\n'
                          '            hold(w,BASE_METADATA,get(w,METADATA_SPAN),get(w,METADATA_SPAN+8),get(w,METADATA_SPAN+16))\n'
                          '        if index < retained:\n            return append_binding')
    policy=policy.replace('            put(w, WORKLOAD_FD, fd)',
                          '            put(w, WORKLOAD_FD, fd)\n            return classify_workload(o,w,fd,size)')
    policy=policy.replace('    if state == RUNTIME_BOUND:', '    if state == RUNTIME_BOUND:\n'
                          '        if plan_ok(s) and size == 24 and input_word(s,72) == BUSINESS and (input_word(s,80) == 1 or input_word(s,80) == 24 or input_word(s,80) == 25):\n'
                          '            return refuse_business(o,w,input_word(s,80))')
    policy=policy.replace('    if purpose == CLOSED_RESERVATION:', '    if purpose == CLOSE_ERROR:\n'
                          '        put(w,CLAIM_ACTIVE,1)\n        return send_journal(o,w,9)\n'
                          '    if purpose == CLOSED_RESERVATION:\n'
                          '        if get(w,BUSINESS_REASON) != 0:\n            return claimed_rejection(o,w)')
    policy=policy.replace('        if now < get(w, WINDOW_UTC) or now >= deadline or deadline - now < 1000000:',
                          '        if now == 0 or (get(w,BUSINESS_REASON) == 0 and (now < get(w,WINDOW_UTC) or now >= deadline or deadline-now < 1000000)):')
    return driver, policy+INGRESS, controls

# The bounded Worker transport has a 2048-byte command buffer. The public
# reply, Journal update, and error for cost accounting use the same sealed fd.
def closeout_literals():
    import json
    from hepta.hia_evaluation_native import _WORKLOAD_REFUSALS
    from tools.generate_hia_evaluate_settlement import LITERALS
    reasons = [('baseline_error','E_HIA_BASELINE','evaluation baseline differs from the frozen Core snapshot','execution')]
    reasons.append(('stale_context','E_HIA_CONTEXT_STALE','context binds a different installed implementation','context'))
    reasons.extend((('profile_error','E_HIA_EXECUTION_PROFILE','evaluation requires retained direct shared images','execution'),
                    ('abi_error','E_HIA_ABI','baseline and candidate frozen public ABI differ','execution')))
    reasons.extend((('unissued_artifact','E_HIA_ARTIFACT_IDENTITY','artifact reference was not issued in this runtime namespace','admission'),
                    ('wrong_native_kind','E_HIA_ARTIFACT_AUTHORITY','input bytes cannot impersonate a retained native','admission')))
    reasons.append(('native_scope','E_HIA_RECEIPT_BINDING','native artifact belongs to a different context or implementation','admission'))
    reasons.append(('unknown_context','E_HIA_CONTEXT_IDENTITY','context is not a retained server record','context'))
    reasons.append(('expired_context','E_HIA_BUDGET','context total wall budget has expired','context'))
    for code, (error, message) in sorted(_WORKLOAD_REFUSALS.items()):
        reasons.append((f'workload_error_{code}',error,message,'admission'))
    values = {'rejected_begin':LITERALS['envelope_begin']+LITERALS['envelope_error'],
              'request_prefix':LITERALS['envelope_request'], 'rejected_end':LITERALS['envelope_rejected']}
    values.update(declared_prefix=LITERALS['refused_prefix'],declared_suffix=LITERALS['refused_suffix'])
    for name, code, message, phase in reasons:
        values[name] = json.dumps(dict(code=code,details_artifact=None,message=message,phase=phase,
                                       retry_action='correct_input'),sort_keys=True,separators=(',',':'))
    lines=[]
    for name, value in values.items():
        data=value.encode('ascii')
        lines.append(f'def {name}(o:mutbuf,at:u64) -> u64:')
        for at in range(0,len(data),8):
            lines.append(f'    put(o,at+{at},{int.from_bytes(data[at:at+8],"little")})')
        lines.append(f'    return at+{len(data)}')
    lines.append('def error_document(o:mutbuf,at:u64,reason:u64) -> u64:')
    lines.extend(('    if reason >= 512 and reason < 1024:',
                  '        index = reason-512', '        p = declared_prefix(o,at)',
                  '        tens = divide_ten(index)', '        hundreds = divide_ten(tens)',
                  '        if hundreds != 0:', '            store(o,p,48+hundreds)', '            p = p+1',
                  '        if tens != 0:', '            store(o,p,48+tens-10*hundreds)', '            p = p+1',
                  '        store(o,p,48+index-10*tens)', '        return declared_suffix(o,p+1)'))
    lines.extend(('    if reason == 1:', '        return baseline_error(o,at)'))
    lines.extend(('    if reason == 28:', '        return native_scope(o,at)'))
    lines.extend(('    if reason == 26:', '        return unissued_artifact(o,at)',
                  '    if reason == 27:', '        return wrong_native_kind(o,at)'))
    lines.extend(('    if reason == 24:', '        return profile_error(o,at)',
                  '    if reason == 25:', '        return abi_error(o,at)'))
    lines.extend(('    if reason == 23:', '        return stale_context(o,at)'))
    lines.extend(('    if reason == 22:', '        return unknown_context(o,at)'))
    lines.extend(('    if reason == 21:', '        return expired_context(o,at)'))
    for code in sorted(_WORKLOAD_REFUSALS):
        tag = 2 if code == 2 else 10 + code
        lines.extend((f'    if reason == {tag}:', f'        return workload_error_{code}(o,at)'))
    lines.append('    return 0')
    return '\n'.join(lines)+'\n'


CLOSEOUT = '''
def refusal_header(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s) != 740 or input_word(s,72) == 0 or input_word(s,80) == 0 or input_word(s,96) != 512 or input_word(s,104) != 64 or input_word(s,112) != 8:
        return BAD
    shape = input_word(s,64) == KEYED_SCHEMA and input_word(s,88) == SHAPE_REASON
    if shape:
        if slot_bytes(w,ORIGINAL) <= 678 or slot_bytes(w,ORIGINAL) > 676+DIAGNOSTIC_LIMIT:
            return BAD
        put(w,GLOBAL_COST,1)
    elif input_word(s,64) != KEYED_REFUSAL or input_word(s,88) == SHAPE_REASON or (input_word(s,120) & 4294967295) != CONTEXT_PREFIX:
        return BAD
    if input_word(s,156) != CLAIM_STATE or input_word(s,668) != CLAIM_ROUTE:
        return BAD
    if input_word(s,676) != 2 or input_word(s,684) != 11 or input_word(s,692) != 0 or input_word(s,724) != 512 or input_word(s,732) != INTENT:
        return BAD
    i = 0
    while i < 64:
        if is_hex(byte(s,220+i)) == False or is_hex(byte(s,284+i)) == False or byte(s,220+i) != byte(s,350+i):
            return BAD
        if shape and i < 36 and byte(s,120+i) != 0:
            return BAD
        if shape == False and i < 32 and is_hex(byte(s,124+i)) == False:
            return BAD
        i = i+1
    if byte(s,348) != 114 or byte(s,349) != 45:
        return BAD
    put(w,FINAL_STATUS,2)
    put(w,ADMISSION_NS,input_word(s,72))
    put(w,CLAIM_TIME,input_word(s,80))
    copy_span(s,w,120,FINAL_CONTEXT,36)
    copy_span(s,w,220,CLAIM_DIGEST,64)
    copy_span(s,w,284,CLAIM_KEY,64)
    copy_span(s,w,348,CLAIM_PUBLIC,66)
    first = rejected_begin(o,HEADER)
    if shape:
        extent = slot_bytes(w,ORIGINAL)-676
        put(w,ERROR_BODY+8,first-HEADER)
        put(w,ERROR_BODY+16,extent)
        fragment(o,0,0,676,extent)
        suffix = request_prefix(o,400)
        copy_private(w,o,CLAIM_PUBLIC,suffix,66)
        last = rejected_end(o,suffix+66)
        fragment(o,1,INLINE_FRAGMENT,400,last-400)
        return action(o,w,ERROR_REPLY,MAKE,0,0,2,first-HEADER)
    reason = input_word(s,88)
    if reason == 22 or reason == 23:
        put(w,GLOBAL_COST,1)
    end = error_document(o,first,reason)
    if end == 0:
        return BAD
    put(w,ERROR_BODY+8,first-HEADER)
    put(w,ERROR_BODY+16,end-first)
    public = request_prefix(o,end)
    copy_private(w,o,CLAIM_PUBLIC,public,66)
    last = rejected_end(o,public+66)
    return action(o,w,ERROR_REPLY,MAKE,0,0,0,last-HEADER)

def refusal_products(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    fd = input_word(s,32)
    size = input_word(s,40)
    if state == ERROR_REPLY:
        if size < 240 or size > choose(get(w,GLOBAL_COST) == 1,DIAGNOSTIC_LIMIT+256,1024) or get(w,ERROR_BODY+8)+get(w,ERROR_BODY+16) > size:
            return BAD
        hold(w,FINAL_REPLY,fd,0,size)
        put(w,ERROR_BODY,fd)
        put(o,HEADER,UPDATE_WIRE)
        put(o,HEADER+8,1)
        put(o,HEADER+16,1)
        put(o,HEADER+24,0)
        put(o,HEADER+32,2)
        put(o,HEADER+40,3)
        put(o,HEADER+48,88)
        put(o,HEADER+56,size)
        put(o,HEADER+64,3)
        put(o,HEADER+72,88+size)
        put(o,HEADER+80,64)
        fragment(o,0,fd,0,size)
        copy_private(w,o,CLAIM_KEY,400,64)
        fragment(o,1,INLINE_FRAGMENT,400,64)
        return action(o,w,ERROR_UPDATE,MAKE,0,0,2,88)
    if state == ERROR_UPDATE:
        if size != 152+get(w,FINAL_REPLY+16):
            return BAD
        hold(w,FINAL_STMT,fd,0,size)
        put(o,144,0)
        return action(o,w,FINAL_CLOCK,CLOCK,0,0,0,0)
    return BAD
'''
