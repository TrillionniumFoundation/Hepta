"""Only parse the new text; never import or execute a project/generator body."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).absolute().parent
SCALARS={'u32','u64','bool'}
BUFFERS={'readbuf','mutbuf'}
MAGICS={'REQUEST_MAGIC':b'HIACRQ01','CATALOG_MAGIC':b'HIACAT01','EMPTY_MAGIC':b'HIATBL01'}


def require(value,message):
    if not value:raise AssertionError(message)


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def inspect_policy(raw):
    text=raw.decode('utf-8')
    for key,value in MAGICS.items():text=text.replace('@'+key+'@',str(int.from_bytes(value,'little')))
    require('@' not in text,'unresolved fixed magic')
    tree=ast.parse(text)
    require(all(isinstance(node,ast.FunctionDef) for node in tree.body),'policy only contains functions')
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in tree.body}
    require(len(signatures)==len(tree.body) and tree.body[0].name=='catalog_root','unique entry and functions')
    signatures.update({'h_sha256':(['mutbuf','mutbuf','u64','u64'],'u64')})
    calls=[];alias_checks=[]

    def expr(node,env,owner):
        if isinstance(node,ast.Name):
            require(node.id in env,f'{owner}: use before definite assignment: {node.id}')
            return env[node.id]
        if isinstance(node,ast.Constant):
            require(type(node.value) is int and 0<=node.value<2**64,'only exact u64 constants')
            return 'u64'
        if isinstance(node,ast.BinOp):
            left,right=expr(node.left,env,owner),expr(node.right,env,owner)
            require(type(node.op) in {ast.Add,ast.Sub,ast.Mult,ast.BitAnd,ast.BitOr,ast.BitXor,ast.LShift,ast.RShift}
                    and left==right and left in {'u32','u64'},f'{owner}: integer operand mismatch')
            return left
        if isinstance(node,ast.Compare):
            require(len(node.ops)==1 and isinstance(node.ops[0],(ast.Eq,ast.NotEq,ast.Lt,ast.LtE,ast.Gt,ast.GtE)),
                    f'{owner}: unsupported comparison')
            left,right=expr(node.left,env,owner),expr(node.comparators[0],env,owner)
            require(left==right and left in SCALARS,f'{owner}: comparison operand types {left}/{right}')
            return 'bool'
        if isinstance(node,ast.BoolOp):
            require(isinstance(node.op,(ast.And,ast.Or)) and all(expr(item,env,owner)=='bool' for item in node.values),
                    f'{owner}: bool operand mismatch')
            return 'bool'
        if isinstance(node,ast.Call):
            require(isinstance(node.func,ast.Name) and not node.keywords,f'{owner}: only fixed direct calls')
            name=node.func.id;actual=[expr(arg,env,owner) for arg in node.args]
            if name=='length':
                require(len(actual)==1 and actual[0] in BUFFERS,f'{owner}: length ABI');return 'u64'
            if name=='byte':
                require(len(actual)==2 and actual[0] in BUFFERS and actual[1]=='u64',f'{owner}: byte ABI');return 'u64'
            if name=='store':
                require(actual==['mutbuf','u64','u64'],f'{owner}: store ABI');return None
            require(name in signatures,f'{owner}: unknown direct target {name}')
            parameters,returns=signatures[name]
            require(len(actual)==len(parameters),f'{owner}: call arity')
            for have,want in zip(actual,parameters):
                require(have==want or have in {'u32','u64'} and want in {'u32','u64'},f'{owner}: call type {name}')
            buffer_args=[ast.dump(arg,include_attributes=False) for arg,typ in zip(node.args,parameters) if typ in BUFFERS]
            require(len(buffer_args)==len(set(buffer_args)),f'{owner}: repeated buffer argument in {name}')
            if len(buffer_args)>1:alias_checks.append({'caller':owner,'callee':name,'line':node.lineno})
            calls.append({'caller':owner,'callee':name,'line':node.lineno})
            return returns
        raise AssertionError(f'{owner}: unsupported expression {type(node).__name__}')

    def block(nodes,env,owner,returns):
        env=dict(env)
        for node in nodes:
            if isinstance(node,ast.Assign):
                require(len(node.targets)==1 and isinstance(node.targets[0],ast.Name),'simple assignments only')
                value=expr(node.value,env,owner);require(value in SCALARS,'no buffer alias assignment')
                env[node.targets[0].id]=value
            elif isinstance(node,ast.Expr):expr(node.value,env,owner)
            elif isinstance(node,ast.Return):
                require(expr(node.value,env,owner) in {'u32','u64'} and returns in {'u32','u64'},'integer return')
                return env,False
            elif isinstance(node,ast.If):
                require(expr(node.test,env,owner)=='bool','if must be bool')
                left,llive=block(node.body,env,owner,returns);right,rlive=block(node.orelse,env,owner,returns)
                if not llive and not rlive:return env,False
                if not llive:env=right
                elif not rlive:env=left
                else:
                    common=left.keys()&right.keys()
                    require(all(left[name]==right[name] for name in common),'join type mismatch')
                    env={name:left[name] for name in common}
            elif isinstance(node,ast.While):
                require(not node.orelse and expr(node.test,env,owner)=='bool','ordinary while only')
                after,live=block(node.body,env,owner,returns)
                if live:require(all(after.get(name)==typ for name,typ in env.items()),'loop back-edge type mismatch')
            else:raise AssertionError(f'{owner}: unsupported statement {type(node).__name__}')
        return env,True

    for node in tree.body:
        require(not node.decorator_list and not node.args.defaults and node.returns.id in SCALARS,'fixed signature required')
        env={arg.arg:arg.annotation.id for arg in node.args.args}
        require(all(value in SCALARS|BUFFERS for value in env.values()),'fixed HIA type domain')
        _,live=block(node.body,env,node.name,node.returns.id)
        require(not live,f'{node.name}: ordinary fallthrough')
    return {'functions':list(signatures),'policy_functions':len(tree.body),
            'fixed_direct_calls':calls,'distinct_syntactic_buffer_argument_checks':alias_checks,
            'static_typed_DSL_subset':True,'core_verification_executed':False,
            'borrow_or_physical_alias_verification_claimed':False}


def main():
    policy=(ROOT/'catalog_root_policy.py.txt').read_bytes()
    generator=(ROOT/'generate_hia_store_catalog_root.py').read_bytes()
    ast.parse(generator)
    details=inspect_policy(policy)
    result={'schema':'hepta.hia.store-catalog-root-author-static.v1',
            'status':'PASS_STATIC_AUTHOR_TEXT_ONLY','policy':pin(policy),'generator':pin(generator),
            'details':details,'project_imports':0,'generator_calls':0,'native_compile':0,'vm_calls':0,
            'filesystem_effect_calls':0,'default_or_original_source_changes':0,
            'not_proved':['Core verification','runtime path coverage','SHA projection execution',
                         'Native/VM equality','fuel/size','durability','catalogue closure','production selection']}
    output=ROOT/'STATIC-REVIEW.json'
    with output.open('xb') as stream:stream.write((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({'status':result['status'],'policy_functions':details['policy_functions'],'output':str(output)}))


if __name__=='__main__':main()
