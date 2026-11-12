"""Explicit private PRNG framing refusals; no external receipt authentication.

Every case is fresh from a complete earlier VM/native-equal snapshot. A second
valid-looking invocation confirms sticky refusal where eight workspace bytes
were available to write the poison marker. Shorter workspaces cannot store it.
"""
from __future__ import annotations
CONTROL_NAMES=["initial-magic","initial-command","initial-context","initial-call","initial-api-zero","initial-api-four","initial-N-outside-u32","initial-destination-not-bool","initial-reserved64","initial-reserved120","initial-reserved248","initial-save-N","initial-restore-destination","initial-source-length-0","initial-source-length-8","initial-source-length-255","initial-source-length-257","short-workspace-0","short-workspace-7","short-workspace-8","short-workspace-4095","short-output-0","short-output-1","short-output-255","dirty-initial-workspace-200","dirty-initial-workspace-512","dirty-initial-workspace-4095","pending-magic","pending-command","pending-context16","pending-context24","pending-call","pending-action","pending-operation","pending-scalar-u32","pending-payload-extent","pending-peer-id","pending-generation","pending-completed-entry","pending-reserved96","pending-reserved248","pending-request-copy","pending-request-phase-copy","pending-short511","pending-extra513","mutex-enter-scalar","VFS-not-bool","entropy-short555","entropy-extra557","mutex-leave-scalar","grow-changed-N","grow-wrong-command","compute-changed-N","compute-wrong-command","completed-stale","completed-gap","completed-context","completed-exhausted","workspace-phase","workspace-action","workspace-pending","workspace-current-n","workspace-saved-padding","workspace-issued-event","action-exhausted"]
def run_controls(support,pair,snapshots):
    p,q=support.p,support.q;BAD=support.BAD
    cases=[]
    op=dict(api=1,n_bits=1,destination=1)
    initial=dict(s=support.begin(1,op),o=bytes(257),w=bytes(4096))
    def add(name,base,source=None,output=None,workspace=None):
        cases.append((name,dict(s=base["s"] if source is None else bytes(source),
                                o=base["o"] if output is None else bytes(output),
                                w=base["w"] if workspace is None else bytes(workspace)),
                      dict(base)))
    def edit(raw,at,value):
        raw=bytearray(raw);p(raw,at,value);return bytes(raw)
    for name,at,value in [["magic",0,0],["command",8,0],["context",16,0],["call",32,0],["api-zero",40,0],["api-four",40,4],["N-outside-u32",48,4294967296],["destination-not-bool",56,2],["reserved64",64,1],["reserved120",120,1],["reserved248",248,1]]:
        s=bytearray(initial["s"]);p(s,at,value)
        if name=="context":p(s,24,0)
        add("initial-"+name,initial,source=s)
    s=bytearray(initial["s"]);p(s,40,2)
    add("initial-save-N",initial,source=s)
    s=bytearray(initial["s"]);p(s,40,3);p(s,48,0)
    add("initial-restore-destination",initial,source=s)
    for n in (0,8,255,257):
        add("initial-source-length-"+str(n),initial,source=(initial["s"]+b"\0")[:n])
    for n in (0,7,8,4095):
        add("short-workspace-"+str(n),initial,workspace=bytes(n))
    for n in (0,1,255):
        add("short-output-"+str(n),initial,output=bytes(n))
    for at in (200,512,4095):
        w=bytearray(initial["w"]);w[at]=1
        add("dirty-initial-workspace-"+str(at),initial,workspace=w)
    pending=snapshots["pending-1"]["after"]
    for name,at,value in [["magic",0,0],["command",8,1],["context16",16,0],["context24",24,0],["call",32,0],["action",40,0],["operation",48,0],["scalar-u32",56,4294967296],["payload-extent",64,1],["peer-id",72,0],["generation",80,0],["completed-entry",88,0],["reserved96",96,1],["reserved248",248,1],["request-copy",256,0],["request-phase-copy",312,0]]:
        add("pending-"+name,pending,source=edit(pending["s"],at,value))
    add("pending-short511",pending,source=pending["s"][:511])
    add("pending-extra513",pending,source=pending["s"]+b"\0")
    for name,kind,value in (("mutex-enter-scalar",2,1),("VFS-not-bool",3,2),("mutex-leave-scalar",5,1)):
        base=snapshots["pending-"+str(kind)]["after"]
        add(name,base,source=edit(base["s"],56,value))
    base=snapshots["pending-4"]["after"]
    add("entropy-short555",base,source=base["s"][:555])
    add("entropy-extra557",base,source=base["s"]+b"\0")
    base=snapshots["grow"]["after"]
    add("grow-changed-N",base,source=edit(base["s"],48,q(base["s"],48)+1))
    add("grow-wrong-command",base,source=edit(base["s"],8,3))
    base=dict(snapshots["compute"]["after"])
    base["s"]=edit(snapshots["compute"]["original"],8,3)
    add("compute-changed-N",base,source=edit(base["s"],48,q(base["s"],48)+1))
    add("compute-wrong-command",base,source=edit(base["s"],8,1))
    base=dict(snapshots["completed"]["after"])
    original_call=q(base["w"],32)
    base["s"]=edit(base["s"],32,original_call+1)
    add("completed-stale",base,source=edit(base["s"],32,original_call))
    add("completed-gap",base,source=edit(base["s"],32,original_call+2))
    add("completed-context",base,source=edit(base["s"],16,q(base["s"],16)+1))
    add("completed-exhausted",base,workspace=edit(base["w"],32,(1<<64)-1))
    for name,at,value in (("workspace-phase",8,99),("workspace-action",40,0),
                          ("workspace-pending",48,0),("workspace-issued-event",1792,0)):
        add(name,pending,workspace=edit(pending["w"],at,value))
    w=bytearray(pending["w"]);w[640]=65
    add("workspace-current-n",pending,workspace=w)
    w=bytearray(pending["w"]);w[899]=1
    add("workspace-saved-padding",pending,workspace=w)
    s=bytearray(pending["s"]);w=bytearray(pending["w"])
    for at in (40,256+40):p(s,at,(1<<64)-1)
    for at in (40,1792+40):p(w,at,(1<<64)-1)
    add("action-exhausted",pending,source=s,workspace=w)
    assert len(cases)==len(CONTROL_NAMES)==65
    assert len(set(name for name,_,_ in cases))==len(cases)
    assert set(name for name,_,_ in cases)==set(CONTROL_NAMES)
    results=[]
    for name,bad,good in cases:
        returned,o,w=pair.call("protocol/"+name,bad["s"],bad["o"],bad["w"])
        assert returned==BAD,(name,returned)
        persistent=False
        if len(w)>=8:
            assert q(w,0)==support.POISON,name
            extended=w+bytes(max(0,4096-len(w)))
            output=o+bytes(max(0,256-len(o)))
            reason=q(extended,152)
            again,after_o,after_w=pair.call("protocol/"+name+"/persistent",
                                            good["s"],output,extended)
            assert again==BAD and q(after_w,0)==support.POISON and q(after_w,152)==reason
            persistent=True
        row=dict(name=name,refused=True,persistent=persistent,
                 persistence_scope="COMPLETE_POISON_RANGE" if persistent else "FEWER_THAN_EIGHT_WRITABLE_BYTES",
                 input=pair.cas.put(bad["s"]),initial_output=pair.cas.put(bad["o"]),initial_workspace=pair.cas.put(bad["w"]),
                 output=pair.cas.put(o),workspace=pair.cas.put(w))
        pair.log(dict(kind="protocol",**row));results.append(row)
    # A full positive C-int request can ask for GROW without allocating 2GiB.
    huge=dict(api=1,n_bits=0x7fffffff,destination=1)
    source=support.begin(1,huge)
    returned,o,w=pair.call("private-positive/max-positive-int-GROW",source,bytes(256),bytes(4096))
    assert returned==2 and q(o,88)==256+0x7fffffff
    assert q(o,40)==q(o,48)==q(o,72)==q(o,80)==0
    pair.log(dict(kind="private-positive",name="max-positive-int-GROW",returncode=returned,
                  output=pair.cas.put(o),workspace=pair.cas.put(w),
                  original_C_not_allocated=True,no_new_byte_quota=True))
    return results
