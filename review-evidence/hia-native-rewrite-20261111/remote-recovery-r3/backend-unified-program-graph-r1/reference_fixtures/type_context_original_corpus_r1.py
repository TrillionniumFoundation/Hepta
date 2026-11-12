"""Original public type-oracle plans, completed before any native entry.

The raw commands are the exact existing private type-owner protocol. Predicted
issued identifiers are fixture expectations, not host-created authorities:
each predecessor actual identifier must match before its next command is used.
"""
from __future__ import annotations
import copy,json
from types import SimpleNamespace

PRIMITIVES=("bool","unit","i8","i16","i32","i64","u8","u16","u32","u64",
            "isize","usize","buffer","readbuf","mutbuf","chain")
OPS={"init":1,"parameters":2,"resolve":3,"partial":4,"origins":5,"task_protocol":6}

def field(name="x",typ="unit"):return {"name":name,"type":typ}
def record(name="R",fields=None,params=None):
    return {"name":name,"params":[] if params is None else params,"kind":"record",
            "fields":[] if fields is None else fields}
def enum(name="Choice",variants=None):
    return {"name":name,"params":[],"kind":"enum",
            "variants":[{"name":"some","fields":[]}] if variants is None else variants}
def task():
    return {"name":"Work","params":[],"kind":"task","state":"unit","result":"unit",
            "poll":"poll","cancel":"cancel"}
def init(definitions=(),recursive=True,partial=True):
    return {"op":"init","definitions":list(definitions),
            "recursive_chain":recursive,"partial_records":partial}
def step(command,error=0,where=0,identifier=None,mixed=False):
    return dict(command=copy.deepcopy(command),error=error,where=where,
                identifier=identifier,mixed_bad_prefix=mixed)
def scenario(label,steps):
    return dict(label=label,steps=steps)
def named_fixture(where,bad,code=5):
    if where in (15,17,18):
        if where==15:
            command={"op":"parameters","params":[field(bad)]}
        else:
            command={"op":"origins","params":[["p",14]],"returns":[14],
                     "return_loans":[{"param":bad if where==17 else "p",
                                      "fields":[] if where==17 else [bad]}]}
        return [step(init()),step(command,code,where)]
    if where==1:defs=[record(bad)]
    elif where==2:defs=[record(params=[bad])]
    elif where==4:defs=[enum(variants=[{"name":bad,"fields":[]}])]
    elif where in (5,6):
        item=task();item["poll" if where==5 else "cancel"]=bad;defs=[item]
    elif where==8:defs=[record(fields=[field(bad)])]
    elif where==9:defs=[record(fields=[field("x",bad)])]
    elif where==11:
        defs=[record("R",[field()]),record("U",[field("p",{"partial":"R","initialized":[bad]})])]
    elif where==13:defs=[record(fields=[field("x",{"name":bad,"args":[]})])]
    else:raise AssertionError(where)
    return [step(init(defs),code,where)]

def plans(group):
    rows=[]
    if group in ("names-declarations-a","names-declarations-b"):
        selected=(1,2,4,5,6) if group.endswith("-a") else (8,9,11,13)
        for where in selected:
            for code,bad in ((5,"9bad"),(6,"h2internal_x")):
                rows.append(scenario("where-"+str(where)+"-error-"+str(code),
                                     named_fixture(where,bad,code)))
    elif group=="names-parameters-origins":
        for where in (15,17,18):
            for code,bad in ((5,"9bad"),(6,"h2internal_x")):
                rows.append(scenario("where-"+str(where)+"-error-"+str(code),
                                     named_fixture(where,bad,code)))
        rows.append(scenario("parameter-shape",[
            step(init()),step({"op":"parameters","params":[{"name":"p"}]},1,14)]))
        rows.append(scenario("origin-shape",[
            step(init()),step({"op":"origins","params":[["p",14]],"returns":[14],
                              "return_loans":[{"param":"p"}]},1,16)]))
    elif group=="shapes":
        for kind in ("record","enum","task"):
            value=record() if kind=="record" else enum() if kind=="enum" else task()
            del value[{"record":"fields","enum":"variants","task":"cancel"}[kind]]
            rows.append(scenario("nominal-"+kind+"-shape",[step(init([value]),1,1)]))
        rows.extend([
            scenario("variant-shape",[step(init([enum(variants=[{"name":"some"}])]),1,3)]),
            scenario("field-shape",[step(init([record(fields=[{"name":"x"}])]),1,7)]),
            scenario("partial-shape",[step(init([record("R",[field()]),
                record("U",[field("p",{"partial":"R","initialized":[],"extra":1})])]),1,10)]),
            scenario("generic-shape",[step(init([record(fields=[field("x",{"name":"Other"})])]),1,12)])])
    elif group=="first-error-order":
        rows.extend([
            scenario("all-registration-before-field-validation",[step(init([
                record("First",[field("9bad")]),record("9bad")]),5,1)]),
            scenario("unknown-kind-before-name",[step(init([
                {"name":"9bad","params":[],"kind":"unknown"}]),4)]),
            scenario("parameter-name-before-duplicates",[step(init([
                record(params=["9bad","9bad"])]),5,2)]),
            scenario("field-name-before-unknown-type",[step(init([
                record(fields=[field("9bad","Missing")])]),5,8)]),
            scenario("first-variant-fields-before-second-variant-name",[step(init([
                enum(variants=[{"name":"first","fields":[field("9bad")]},
                               {"name":"9bad","fields":[]}])]),5,8)]),
            scenario("state-type-before-poll-name",[step(init([
                dict(task(),state="Missing",poll="9bad")]),18)]),
            scenario("invalid-state-before-poll-name",[step(init([
                dict(task(),state="9bad",poll="9bad")]),5,9)]),
            scenario("disabled-partial-is-generic-v1",[step(init([
                record("R",[field()]),record("U",[field("p",{"partial":"R","initialized":[]})])],
                recursive=False,partial=False),1,12)]),
            scenario("disabled-partial-is-generic-v2",[step(init([
                record("R",[field()]),record("U",[field("p",{"partial":"R","initialized":[]})])],
                recursive=True,partial=False),1,12)])])
        for where,bad in ((1,"h2internal_bad$"),(8,"h2internal_bad/"),
                          (9,"h2internal_é"),(15,"h2internal_bad$"),(17,"h2internal_bad$")):
            values=named_fixture(where,bad)
            values[-1]["mixed_bad_prefix"]=True
            rows.append(scenario("mixed-prefix-where-"+str(where),values))
        rows.append(scenario("name-length-129",[step(init([record("x"*129)]),5,1)]))
        rows.append(scenario("name-length-128",[step(init([record("x"*128)]))]))
        rows.append(scenario("exact-elaborator-prefix",[step(init([record("h2internal_")]),6,1)]))
    elif group=="lifecycle":
        rows.append(scenario("context-reset-after-resolve-parameters-origins",[
            step(init()),step({"op":"resolve","ref":"9bad"},5,9),
            step({"op":"resolve","ref":"unit"},identifier=2),
            step({"op":"parameters","params":[field("9bad")]},5,15),
            step({"op":"parameters","params":[field("p")]}),
            step({"op":"origins","params":[["p",14]],"returns":[14],
                  "return_loans":[{"param":"9bad","fields":[]}]},5,17),
            step({"op":"origins","params":[["p",14]],"returns":[14],
                  "return_loans":[{"param":"p","fields":[]}]}),
            step({"op":"resolve","ref":"unit"},identifier=2)]))
        rows.append(scenario("partial-complete-and-rejected-continuation",[
            step(init([record("R",[field()])])),
            step({"op":"resolve","ref":"R"},identifier=17),
            step({"op":"partial","base":17,"initialized":[]},identifier=18),
            step({"op":"partial","base":17,"initialized":["missing"]},22),
            step({"op":"resolve","ref":"R"},identifier=17)]))
        rows.append(scenario("descriptor-commit-before-late-parameter-name",[
            step(init([record("R",[field()])])),
            step({"op":"parameters","params":[field("r","R"),field("9bad")]},5,15),
            step({"op":"resolve","ref":"R"},identifier=17),
            step({"op":"parameters","params":[field("r","R")]})]))
        defs=[task(),enum("Step",[{"name":"pending","fields":[field("state")]},
                                 {"name":"ready","fields":[field("result")]}])]
        functions=[["poll",[2],[18]],["cancel",[2],[]]]
        rows.append(scenario("all-six-ops-task-protocol-and-context-reset",[
            step(init(defs)),step({"op":"resolve","ref":"Work"},identifier=17),
            step({"op":"resolve","ref":"Step"},identifier=18),
            step({"op":"task_protocol","task":17,"functions":functions},identifier=18),
            step({"op":"parameters","params":[field("9bad")]},5,15),
            step({"op":"task_protocol","task":17,"functions":functions},identifier=18)]))
    else:raise AssertionError(group)
    assert len(rows)==GROUPS[group]
    return rows

GROUPS={"names-declarations-a":10,"names-declarations-b":8,
        "names-parameters-origins":8,"shapes":7,"first-error-order":17,"lifecycle":4,
        "reader-protocol":0}

def predeclare(composite,rows):
    from hepta.hia_program import HIAProgramRejected
    result=[]
    for scenario in rows:
        current=None;by_id={};steps=[]
        for planned in scenario["steps"]:
            cmd=planned["command"];op=cmd["op"];value=None;message=None
            try:
                if op=="init":
                    current=composite._Types(cmd["definitions"],
                        recursive_chain=cmd["recursive_chain"],partial_records=cmd["partial_records"])
                    by_id={i:current.resolve(name) for i,name in enumerate(PRIMITIVES,1)
                           if name!="chain" or cmd["recursive_chain"]}
                elif op=="resolve":value=current.resolve(cmd["ref"])
                elif op=="parameters":
                    value=composite._Elaborator._reference_parameters(SimpleNamespace(types=current),cmd["params"])
                elif op=="partial":value=current.partial_record(by_id[cmd["base"]],cmd["initialized"])
                elif op=="origins":
                    fn={} if "return_loans" not in cmd else {"return_loans":cmd["return_loans"]}
                    value=composite._Elaborator.loan_origins(fn,
                        [(name,by_id[identifier]) for name,identifier in cmd["params"]],
                        [by_id[identifier] for identifier in cmd["returns"]])
                elif op=="task_protocol":
                    functions={name:{} for name,params,returns in cmd["functions"]}
                    signatures={name:(tuple(("p"+str(i),by_id[n]) for i,n in enumerate(params)),
                                      tuple(by_id[n] for n in returns))
                                for name,params,returns in cmd["functions"]}
                    value=composite._Elaborator._reference_check_task(
                        SimpleNamespace(functions=functions,signatures=signatures),by_id[cmd["task"]])
                else:raise AssertionError(op)
            except HIAProgramRejected as exc:message=str(exc)
            assert (message is not None)==(planned["error"]!=0),(scenario["label"],cmd,message,planned)
            if message is not None:
                assert message.startswith("E_HIA_") and ": " in message,message
            if planned["identifier"] is not None and value is not None:
                by_id[planned["identifier"]]=value
            wire=json.dumps(cmd,ensure_ascii=False,allow_nan=False,separators=(",",":")).encode("utf-8")
            assert len(wire)<=8388608+128
            steps.append(dict(planned,wire=wire,operation=OPS[op],public_message=message,
                original_public_exception=None if message is None else "HIAProgramRejected",
                oracle_type_key=repr(getattr(value,"key",None))))
        result.append(dict(label=scenario["label"],steps=steps))
    return result
