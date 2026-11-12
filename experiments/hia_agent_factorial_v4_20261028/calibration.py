"""Independent native coding calibration; no solution is supplied to inference."""
from __future__ import annotations

import copy

from tools.provider_adapter.llama_cpp_engine import canonical
from experiments.hia_agent_factorial_v4_20261028 import fixtures


def problems():
    templates = {t["provider"]: t for t in fixtures.make_fixtures()}
    result = []
    entries = [
        ("json_scalar_reasoning", "span", "Implement span(a:u32,b:u32)->u64 = 4*a+b using mathematical arithmetic, including full-width u32 values. entrypoint(a:u32,b:u32,c:u32)->u64 must call span exactly once with a,b and return its result plus c. Replace both files.",
         "pub fn span(a:u32,b:u32)->u64 { (a as u64)+(b as u64) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b) }",
         "pub fn span(a:u32,b:u32)->u64 { 4*(a as u64)+(b as u64) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b)+(c as u64) }",
         "use crate::api; pub fn provider_probe(a:u32,b:u32,c:u32)->u64 { let _=c; api::span(a,b) }"),
        ("two_file_signature_repair", "span", "Upgrade span(a:u16,b:u16)->u32 to span(a:u32,b:u32)->u64. It now returns the full mathematical product a*b. Update entrypoint(a:u32,b:u32,c:u32)->u64 to call it once without narrowing and return the product plus c. Both files must migrate atomically.",
         "pub fn span(a:u16,b:u16)->u32 { (a as u32)*(b as u32) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::span(a as u16,b as u16) as u64)+(c as u64) }",
         "pub fn span(a:u32,b:u32)->u64 { (a as u64)*(b as u64) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b)+(c as u64) }",
         "use crate::api; pub fn provider_probe(a:u32,b:u32,c:u32)->u64 { let _=c; api::span(a,b) }"),
        ("owner_flow_repair", "touch", "Repair owner flow. touch(buf:Vec<u8>,x:u8)->Vec<u8> receives a nonempty zeroed Vec, writes x+1 modulo 256 into byte 0 and returns the same Vec without a new allocation. entrypoint(a:u32,b:u32,c:u32)->u64 creates one zeroed Vec of length (a AND 7)+1, transfers it once to touch with low byte of b, then reads the RETURNED owner and returns its byte0 plus 16*its_length. c is ignored. Release the owner before returning. Never read the moved original owner.",
         "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { buf[0]=x; buf }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _=c; let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(buf[0] as u64)+16*(buf.len() as u64); drop(out); value }",
         "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { buf[0]=x.wrapping_add(1); buf }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _=c; let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(out[0] as u64)+16*(out.len() as u64); drop(out); value }",
         "use crate::api; pub fn provider_probe(a:u32,b:u32,c:u32)->u64 { let _=c; let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(out[0] as u64)+16*(out.len() as u64); drop(out); value }")]
    cases = [[0,0,0], [3,9,5], [7,255,17], [70000,80000,31], [fixtures.MAX32,fixtures.MAX32,0], [fixtures.MAX32,1,fixtures.MAX32]]
    for ident, provider, spec, api_old, client_old, api_good, client_good, probe in entries:
        task = copy.deepcopy(templates[provider])
        task.update(id=ident, category="independent_calibration", specification=spec,
                    original_rust={"api.rs": api_old, "client.rs": client_old}, correct_rust={"api.rs": api_good, "client.rs": client_good}, probe_rust=probe)
        expected = []
        for a,b,c in cases:
            value = 4*a+b if ident == "json_scalar_reasoning" else a*b if ident == "two_file_signature_repair" else ((b+1)%256)+16*((a&7)+1)
            expected.append([value+c if ident != "owner_flow_repair" else value, value])
        task["public_cases"], task["public_expected"] = cases[:2], expected[:2]
        task["hidden_cases"], task["hidden_expected"] = cases[2:], expected[2:]
        task["cases"], task["expected"] = cases, expected
        result.append(task)
    return result


def prompt(task):
    return ("Return ONLY JSON {\"files\":{\"api.rs\":\"complete Rust source\",\"client.rs\":\"complete Rust source\"}}."
            + "\n" + task["specification"]
            + "\nEach file has one public function. client.rs keeps use crate::api; and one provider call. No comments, attributes, strings, unsafe, loops, closures, extra functions/imports or paths. Allowed types: u8,u16,u32,u64,usize,bool,Vec<u8>. Allowed methods: "
            + ",".join(fixtures.RUST_METHODS) + ". Only vec![byte;length], drop(value), and api provider calls are allowed non-method calls."
            + "\nPublic examples [arguments,[entrypoint,provider_probe]]: " + canonical(list(zip(task["public_cases"], task["public_expected"]))).decode()
            + "\nCurrent files: " + canonical(task["original_rust"]).decode())
