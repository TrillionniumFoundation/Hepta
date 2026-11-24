"""Reproduce a native input-diagnostic flat or the unchanged original Rust oracle."""
from __future__ import annotations
import argparse
from hashlib import sha256
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL_EXTERNS={
    'anyhow':'libanyhow-db0ef1feb57ec46b.rlib',
    'regex':'libregex-21f34a03d8138aa9.rlib',
    'serde_json':'libserde_json-2767d385e605b4d5.rlib',
    'sha2':'libsha2-6391106c65fe76fe.rlib',
    'rmcp':'librmcp-aecb752a0e64d8c2.rlib',
}


def native(compiler,output):
    from tools.generate_hia_mcp_input_diagnostic import SOURCE,CATALOG,source_program
    from tools.generate_hia_mcp_service import document
    from tools.generate_hia_worker_request import data_source,decimal_program
    from hepta.hia_agent_assembly import render_assembly
    compiler=Path(compiler).resolve(strict=True)
    output=Path(output).resolve();output.mkdir(mode=0o700)
    dependencies={SOURCE,CATALOG,Path(__file__),Path(inspect.getfile(source_program)),
        Path(inspect.getfile(document)),Path(inspect.getfile(data_source)),
        Path(inspect.getfile(decimal_program)),Path(inspect.getfile(render_assembly)),
        ROOT/'tools/qualify_hia_mcp_input_diagnostic.py',
        ROOT/'tests/hia_mcp_input_diagnostic_cases.py',
        ROOT/'tests/hia_mcp_input_diagnostic_raw_cases.py'}
    captured={p:p.read_bytes() for p in dependencies}
    selected=compiler.read_bytes()
    authored=source_program(captured[CATALOG])
    module=document(authored,'mcp_input_diagnostic')
    generated=render_assembly(module).encode()
    if captured[SOURCE]!=generated:
        raise ValueError('checked-in HIA input diagnostic differs from the current authoring source')
    run=subprocess.run([str(compiler),'compile'],input=captured[SOURCE],
        capture_output=True,env={'PATH':''},timeout=240)
    (output/'compile.stdout').write_bytes(run.stdout)
    (output/'compile.stderr').write_bytes(run.stderr)
    if run.returncode or run.stderr or not 0<len(run.stdout)<=1<<20:
        raise AssertionError(('native source build rejected diagnostics',run.returncode,run.stderr[:1000]))
    if compiler.read_bytes()!=selected or any(path.read_bytes()!=raw for path,raw in captured.items()):
        raise ValueError('diagnostic source/compiler custody changed during construction')
    image=output/'mcp_input_diagnostic.flat';image.write_bytes(run.stdout)
    report={'schema':'hepta.hia.mcp-input-diagnostic-source-custody.v1',
        'scope':'NATIVE_MCP_INPUT_DIAGNOSTIC_COMPONENT_SOURCE_CUSTODY',
        'compiler':str(compiler),'compiler_sha256':sha256(selected).hexdigest(),
        'whole_cold_source_admission_claimed':False,
        'sources':{str(p.relative_to(ROOT)):sha256(body).hexdigest() for p,body in captured.items()},
        'flat':str(image),'flat_sha256':sha256(run.stdout).hexdigest(),'flat_bytes':len(run.stdout),
        'functions':len(module['functions']),
        'blocks':sum(len(f['blocks']) for f in module['functions']),
        'operations':sum(len(b['ops']) for f in module['functions'] for b in f['blocks'])}
    (output/'construction.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


def oracle(runtime_source,dependencies,rustc,output):
    runtime_source=Path(runtime_source).resolve(strict=True)
    dependencies=Path(dependencies).resolve(strict=True)
    rustc=Path(rustc).resolve(strict=True)
    output=Path(output).resolve();output.mkdir(mode=0o700)
    contract=runtime_source/'src/mcp/hia_contract.rs'
    catalog=runtime_source/'src/mcp/hia_tool_catalog.json'
    constants=runtime_source/'src/utils/truncation.rs'
    captured={p:p.read_bytes() for p in (contract,catalog,constants)}
    match=re.search(r'pub const MAX_RESULT_BYTES: usize = ([^;]+);',captured[constants].decode())
    if not match or match[1]!='8 * 1024 * 1024':
        raise ValueError('the original unused output helper constant changed')
    code='''mod utils { pub mod truncation { pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024; } }
#[path = CONTRACT_PATH]
mod original;
use std::io::{self,BufRead,Write};
use serde_json::{Value,json};
fn main() {
    let stdout=io::stdout();let mut out=stdout.lock();
    for line in io::stdin().lock().lines() {
        let request:Value=serde_json::from_str(&line.unwrap()).unwrap();
        let tool=request["tool"].as_str().unwrap();
        let arguments=&request["arguments"];
        let result=match original::validate_input(tool,arguments) {
            Ok(()) => json!({"ok":true,"canonical":serde_json::to_string(arguments).unwrap()}),
            Err(error) => {
                let rpc=json!({"code":-32602,"message":format!("HIA input does not match its advertised contract: {error}")});
                json!({"ok":false,"error":error.to_string(),"rpc_encoded":serde_json::to_string(&rpc).unwrap(),
                    "rpc":rpc,"canonical":serde_json::to_string(arguments).unwrap()})
            }
        };
        writeln!(out,"{}",serde_json::to_string(&result).unwrap()).unwrap();out.flush().unwrap();
    }
}
'''.replace('CONTRACT_PATH',json.dumps(str(contract)))
    driver=output/'original_contract_oracle.rs';driver.write_text(code)
    image=output/'original_contract_oracle'
    version=subprocess.check_output([str(rustc),'--version'],text=True).strip()
    command=[str(rustc),'--edition=2021','-Awarnings','-O','-C','panic=abort',
        str(driver),'-L','dependency='+str(dependencies),'-o',str(image)]
    libraries={}
    for name,relative in ORIGINAL_EXTERNS.items():
        path=dependencies/relative
        libraries[path]=sha256(path.read_bytes()).hexdigest()
        command+=['--extern',name+'='+str(path)]
    run=subprocess.run(command,capture_output=True,timeout=180)
    (output/'compile.stdout').write_bytes(run.stdout);(output/'compile.stderr').write_bytes(run.stderr)
    if run.returncode:
        raise AssertionError(('original Rust oracle build failed',run.returncode,run.stderr[:4000]))
    if any(path.read_bytes()!=raw for path,raw in captured.items()) or any(sha256(p.read_bytes()).hexdigest()!=digest for p,digest in libraries.items()):
        raise ValueError('original source/dependency custody changed during oracle compilation')
    report={'schema':'hepta.hia.mcp-input-original-oracle.v1',
        'original_functions_unmodified':True,'runtime_source':str(runtime_source),
        'sources':{str(p):sha256(raw).hexdigest() for p,raw in captured.items()},
        'rustc':str(rustc),'rustc_version':version,'command':command,
        'externs':{str(p):digest for p,digest in libraries.items()},
        'driver_sha256':sha256(driver.read_bytes()).hexdigest(),
        'executable':str(image),'executable_sha256':sha256(image.read_bytes()).hexdigest()}
    (output/'oracle.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    n=sub.add_parser('native');n.add_argument('--compiler',type=Path,required=True);n.add_argument('--output',type=Path,required=True)
    r=sub.add_parser('oracle')
    for name in ('runtime-source','dependencies','rustc','output'):r.add_argument('--'+name,type=Path,required=True)
    a=parser.parse_args()
    report=native(a.compiler,a.output) if a.action=='native' else oracle(a.runtime_source,a.dependencies,a.rustc,a.output)
    print(json.dumps({key:report[key] for key in ('flat','flat_sha256','executable','executable_sha256') if key in report},sort_keys=True))
if __name__=='__main__':main()
