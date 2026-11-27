"""Read recorded byte effects and structural traces, without a product VM.

This module imports no project. It never calls a provider or computes lexer
policy. Byte replay checks the recorded actual load/store witnesses. A finite
structural trace recognizer checks the recorded opcode path and charged ticks;
it does not evaluate HIA scalar instructions or choose a branch predicate.
"""
import copy,json,re

def require(value,message):
    if not value:raise ValueError(message)

def parameters(text):return [] if not text else [{'name':p.split(':')[0],'type':p.split(':')[1]} for p in text.split(',')]
def names(text):return [] if not text else text.split(',')
def parse_program(raw):
    lines=raw.decode().splitlines();header=lines.pop(0).split()
    require(len(header)==3 and header[0]=='hia-asm.v1','actual header differs')
    doc={'schema':header[1],'module':header[2],'functions':[]};function=None;block=None
    for line in lines:
        if not line:continue
        m=re.fullmatch(r'fn (f\d+)\(([^)]*)\) -> \(([^)]*)\) effects\(([^)]*)\) entry\(([^)]*)\)',line)
        if m:
            require(function is None,'nested function text')
            name,params,returns,effects,entry=m.groups()
            function={'name':name,'params':parameters(params),'returns':names(returns),'effects':names(effects),'entry':entry,'blocks':[]}
            doc['functions'].append(function);continue
        if line=='end':require(function is not None,'end without function');function=None;block=None;continue
        require(function is not None,'line outside function')
        m=re.fullmatch(r'block (b\d+)\(([^)]*)\)',line)
        if m:
            block={'id':m[1],'params':parameters(m[2]),'ops':[]};function['blocks'].append(block);continue
        require(block is not None,'line outside block')
        m=re.fullmatch(r'  (v\d+:\w+|_) = ([a-z0-9_.]+)\(([^)]*)\)(?: (.*))?',line)
        if m:
            out,op,args,attrs=m.groups()
            block['ops'].append({'op':op,'args':names(args),'out':[] if out=='_' else parameters(out),'attrs':{} if attrs is None else json.loads(attrs)});continue
        m=re.fullmatch(r'  ret\(([^)]*)\)',line)
        if m:block['term']={'op':'ret','values':names(m[1])};continue
        m=re.fullmatch(r'  jump (b\d+)\(([^)]*)\)',line)
        if m:block['term']={'op':'jump','target':m[1],'args':names(m[2])};continue
        m=re.fullmatch(r'  branch (v\d+) (b\d+)\(([^)]*)\) (b\d+)\(([^)]*)\)',line)
        if m:
            block['term']={'op':'branch','cond':m[1],'then':{'target':m[2],'args':names(m[3])},'else':{'target':m[4],'args':names(m[5])}};continue
        raise ValueError('unrecognized actual assembly line')
    require(function is None and all('term' in b for f in doc['functions'] for b in f['blocks']),'incomplete actual functions')
    return doc

def trace_structure(document,entry,events,effects,expected_steps,status):
    """Recognize the exact recorded path, preserving every call and effect.

    States are positions in the fixed Core CFG, not runtime scalar values.
    Empty-block cycles are rejected as not independently reconstructible from
    this observer's record. No synthetic HIA invocation is performed.
    """
    functions={f['name']:f for f in document['functions']}
    blocks={name:{b['id']:b for b in f['blocks']} for name,f in functions.items()}
    reachable=set();pending=[entry]
    while pending:
        name=pending.pop()
        if name in reachable:continue
        require(name in functions,'recorded entry/callee absent');reachable.add(name)
        for b in functions[name]['blocks']:
            for op in b['ops']:
                if op['op']=='call':pending.append(op['attrs']['function'])
    def check_empty(name,node,visiting,done):
        if node in done:return
        require(node not in visiting,'empty-block cycle cannot be reconstructed')
        b=blocks[name][node]
        if b['ops']:done.add(node);return
        visiting.add(node);t=b['term']
        targets=() if t['op']=='ret' else (t['target'],) if t['op']=='jump' else (t['then']['target'],t['else']['target'])
        for target in targets:check_empty(name,target,visiting,done)
        visiting.remove(node);done.add(node)
    for name in reachable:
        done=set()
        for node in blocks[name]:check_empty(name,node,set(),done)
    start=(entry,functions[entry]['entry'],0,(),1)
    def closure(inputs):
        todo=list(inputs);ready=set();returned=set();seen=set()
        while todo:
            state=todo.pop()
            if state in seen:continue
            seen.add(state);name,node,index,stack,steps=state;b=blocks[name][node]
            if index<len(b['ops']):ready.add(state);continue
            require(index==len(b['ops']),'invalid structural op cursor')
            term=b['term'];steps+=1
            if term['op']=='ret':
                if stack:
                    old_name,old_node,old_index=stack[-1]
                    todo.append((old_name,old_node,old_index,stack[:-1],steps))
                else:returned.add(steps)
            elif term['op']=='jump':todo.append((name,term['target'],0,stack,steps))
            else:
                require(term['op']=='branch','unexpected structural terminator')
                for edge in ('then','else'):todo.append((name,term[edge]['target'],0,stack,steps))
        return ready,returned
    states={start};effect_at=0;observed=[];last_candidates=[]
    for position,event in enumerate(events):
        require(type(event)is dict and set(event)=={'op','depth','out'},'actual operation event shape differs')
        ready,_=closure(states);next_states=set();matched=[];step_ends=set()
        for name,node,index,stack,steps in ready:
            op=blocks[name][node]['ops'][index]
            if {'op':op['op'],'depth':len(stack),'out':[o['name'] for o in op['out']]}!=event:continue
            matched.append(op);step_ends.add(steps+1)
            if op['op']=='call':
                callee=op['attrs']['function']
                next_states.add((callee,functions[callee]['entry'],0,stack+((name,node,index+1),),steps+2))
            else:next_states.add((name,node,index+1,stack,steps+1))
        require(matched,'actual opcode event is not an admitted fixed-Core path')
        require(all(op==matched[0] for op in matched),'actual operation path is semantically ambiguous')
        ins=matched[0];observed.append(ins)
        if ins['op']=='call' or ins['op'].startswith('buffer.'):
            require(effect_at<len(effects),'missing actual effect record');effect=effects[effect_at];effect_at+=1
            require(effect['op']==ins['op'] and effect['depth']==event['depth'] and effect['attrs']==ins['attrs'],
                'actual effect/op association differs')
            require(len(effect['args'])==len(ins['args']) and effect['outcome'] in ('completed','raised'),'actual effect shape differs')
            if effect['outcome']=='completed':require(len(effect['values'])==len(ins['out']),'actual effect result arity differs')
        states=next_states;last_candidates=step_ends
    require(effect_at==len(effects),'extra actual effect record')
    if status=='returned':
        _,returned=closure(states);require(expected_steps in returned,'actual returned charged ticks differ from the fixed-Core path')
    else:
        require(status in ('trapped','rejected') and events and expected_steps in last_candidates,
            'actual first-error charged ticks differ from the fixed-Core path')
    require(0<expected_steps<=10000000,'original VM fuel differs')
    return observed

def expected_physical_state(case):
    if case['kind']=='scalar':return {},0
    states={}
    shared_expired=case['same_physical_owner'] and any(case[r+'_view']=='expired_owner' for r in ('source','workspace'))
    for role in ('source','workspace'):
        mode=case[role+'_view']
        states[role]={'view_active':mode!='expired_view','view_mutable':mode=='mutable',
            'owner_active':mode!='expired_owner' and not shared_expired}
    return states,1 if case['same_physical_owner'] else 2

def replay_bytes(case,effects,initial,after,state):
    """Validate recorded byte effects against the actual complete byte spans."""
    physical,count=expected_physical_state(case)
    if case['kind']=='scalar':
        require(initial==after=={} and effects==[],'scalar fixture invented physical storage');return {}
    require(set(initial)==set(after)=={'source','workspace'},'two complete logical roles missing')
    if case['same_physical_owner']:
        require(initial['source']==initial['workspace'],'shared physical preimage differs')
        buffer=bytearray(initial['source']);buffers={'source':buffer,'workspace':buffer}
    else:buffers={k:bytearray(v) for k,v in initial.items()}
    first_error=None;written={r:set() for r in buffers}
    def rejection(message):return {'type':'HIAProgramRejected','code':'E_HIA_RUNTIME_INVARIANT','message':'E_HIA_RUNTIME_INVARIANT: '+message}
    def trap(message):return {'type':'HIAProgramTrap','code':'bounds','message':'E_HIA_TRAP_BOUNDS: '+message}
    for event in effects:
        op=event['op']
        if op=='call':
            if event['outcome']=='raised':require(event['error']==state['error'],'propagated actual call error differs')
            continue
        require(first_error is None,'an actual buffer effect follows the first failing effect')
        require(op in ('buffer.load','buffer.len','buffer.store','buffer.fill_range'),'unaccounted actual buffer effect')
        args=event['args'];require(type(args[0])is dict and set(args[0])=={'borrowed_view'},'actual view binding differs')
        role=args[0]['borrowed_view'];require(role in buffers,'actual role outside fixed two views')
        if op!='buffer.len':require(type(args[1])is int and 0<=args[1]<(1<<64),'non-usize actual byte index')
        if op=='buffer.fill_range':require(type(args[2])is int and 0<=args[2]<(1<<64),'non-usize actual fill length')
        buf=buffers[role];view=physical[role];error=None;values=[]
        if not view['view_active']:error=rejection('expired/cyclic runtime view')
        elif not view['owner_active']:error=rejection('expired runtime owner')
        elif op=='buffer.store' and not view['view_mutable']:error=rejection('write through non-mutable view')
        elif op=='buffer.fill_range' and not view['view_mutable']:error=rejection('range fill requires unique mutable loan')
        elif op in ('buffer.load','buffer.store') and args[1]>=len(buf):
            error=trap('byte load outside the borrowed buffer' if op=='buffer.load' else 'byte store outside the borrowed buffer')
        elif op=='buffer.fill_range' and (args[1]>len(buf) or args[2]>len(buf)-args[1]):error=trap('fill range exceeds owned extent')
        if error is not None:
            require(event['outcome']=='raised' and event['error']==error==state['error'],'first real byte error differs')
            first_error=error;continue
        require(event['outcome']=='completed','nonfailing byte operation reported raised')
        if op=='buffer.load':values=[buf[args[1]]]
        elif op=='buffer.len':values=[len(buf)]
        else:
            start=args[1];length=1 if op=='buffer.store' else args[2];value=args[2] if op=='buffer.store' else args[3]
            require(type(value)is int and 0<=value<256,'non-u8 actual store witness')
            buf[start:start+length]=bytes([value])*length
            for target in (tuple(written) if case['same_physical_owner'] else (role,)):written[target].update(range(start,start+length))
        require(event['values']==values,'actual observed load value or write result differs')
    require((first_error is None)==(state['error']is None),'actual terminal error has no corresponding first buffer error')
    require(all(bytes(buffers[r])==after[r] for r in buffers),'complete actual after bytes differ from the real recorded writes')
    return {r:len(initial[r])==len(after[r]) and all(v==after[r][i] for i,v in enumerate(initial[r]) if i not in written[r]) for r in buffers}
