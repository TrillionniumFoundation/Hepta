"""Independent public input fixtures for all 33 native context messages.

Original public verify/render creates the expected result before the first
native call. The native reader's table is only an asserted coverage inventory;
it never replaces the original public oracle or supplies actual result bytes.
"""
from __future__ import annotations
import copy
from pathlib import Path

GROUPS={"public-type-names":48,"public-type-shapes":18,"public-type-order":34}

def program(ns,scenario):
    steps=scenario["steps"];assert 1<=len(steps)<=2
    first=steps[0]["command"];assert first["op"]=="init"
    version=3 if first["partial_records"] else 2 if first["recursive_chain"] else 1
    value=ns["composite"](version)
    value["types"]=copy.deepcopy(first["definitions"])
    if len(steps)==2:
        command=steps[1]["command"]
        fn=value["functions"][0]
        if command["op"]=="parameters":
            fn["params"]=copy.deepcopy(command["params"])
        else:
            assert command["op"]=="origins"
            assert command["params"]==[["p",14]] and command["returns"]==[14]
            value["schema"]="hepta.hia.composite.v4"
            fn["params"]=[{"name":"p","type":"readbuf"}]
            fn["returns"]=["readbuf"]
            fn["return_loans"]=copy.deepcopy(command["return_loans"])
            fn["blocks"][0]["params"]=[{"name":"p","type":"readbuf"}]
            fn["blocks"][0]["ops"]=[]
            fn["blocks"][0]["term"]={"op":"ret","values":["p"]}
    return value

def plan(ns,group):
    import type_context_original_corpus_r1 as corpus
    inventory=ns["json"].loads(ns["pin"](ns["bundle"]["native_type_context_reader_inventory"]))
    texts={(r["code"],r["where"],r["mask"]):r["text"].encode("ascii") for r in inventory["rows"]}
    assert len(texts)==33
    if group=="public-type-names":
        cases=[]
        for where in (1,2,4,5,6,8,9,11,13,15,17,18):
            for code,bad in ((5,"9bad"),(6,"h2internal_x")):
                cases.append(corpus.scenario("where-"+str(where)+"-error-"+str(code),
                                            corpus.named_fixture(where,bad,code)))
        assert len(cases)==24
    elif group=="public-type-shapes":
        cases=corpus.plans("shapes")
        cases.extend(x for x in corpus.plans("names-parameters-origins")
                     if x["label"] in ("parameter-shape","origin-shape"))
        assert len(cases)==9
    else:
        assert group=="public-type-order"
        cases=corpus.plans("first-error-order");assert len(cases)==17
    evidence=[]
    for scenario in cases:
        value=program(ns,scenario);last=scenario["steps"][-1]
        for tree in (0,1):
            label=group+"-"+scenario["label"]+"-tree"+str(tree)
            ns["add"](label,1,value,tree=tree,accept=last["error"]==0)
            row=ns["PLAN"][-1]
            trace=None
            if last["error"]!=0:
                trace=ns["reference_trace"](ns["transport"](value))
            if last["where"]:
                candidates=[text for (code,where,mask),text in texts.items()
                            if code==last["error"] and where==last["where"]]
                assert row["expected"]["payload"] in candidates,(label,row["expected"],candidates)
            evidence.append(dict(label=label,original_scenario=scenario,
                original_public_oracle=ns["cas"](row["expected"]["payload"]),
                original_public_trace=trace,source=ns["cas"](row["source"]),
                typed_object_transport=bool(tree),all_expected_before_native=True))
    assert len(ns["PLAN"])==GROUPS[group]
    ns["save"](ns["OUT"]/"type-context-public-before-native.json",dict(
        schema="hia-worker-public-native-type-context-fixtures-r1",group=group,
        count=len(evidence),cases=evidence,
        original_public_oracle_never_replaced_by_native_enum=True,
        input_and_actual_context_not_host_constructed_during_native=True,
        actual_native_not_started=True))
