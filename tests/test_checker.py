"""Behavioral contracts for the bootstrap checker, including ownership escapes."""
import unittest

from hepta.ast import Expr, Function, Program, Stmt, Type
from hepta.checker import check
from hepta.parser import parse


class _CheckerAssertions:
    def check_ok(self, source):
        result = check(parse(source))
        self.assertTrue(result.ok, [(d.code, d.message) for d in result.diagnostics])
        return result

    def rejects(self, source, code):
        result = check(parse(source))
        self.assertFalse(result.ok)
        self.assertIn(code, [d.code for d in result.diagnostics], [(d.code, d.message) for d in result.diagnostics])
        return result


class CheckerTests(_CheckerAssertions, unittest.TestCase):
    def test_pure_wrapping(self):
        result = self.check_ok('fn f(a:u64,b:u64)->u64 effects {} { return wrapping_add(a,b); }')
        self.assertEqual(result.effects['f'], set())

    def test_integer_arithmetic_has_panic(self):
        for op in ['+', '-', '*', '/', '%', '<<', '>>']:
            with self.subTest(op=op):
                self.rejects(f'fn f(a:i64,b:i64)->i64 effects {{}} {{ return a {op} b; }}', 'E_EFFECT')

    def test_float_arithmetic_does_not_panic(self):
        self.check_ok('fn f(a:f64,b:f64)->f64 effects {} { return a / b + a * b; }')

    def test_transitive_effect_fixed_point(self):
        result = self.rejects('''
            fn top()->Unit effects {} { mid(); }
            fn mid()->Unit effects {io,alloc,panic,block} { low(); }
            fn low()->Unit effects {io,alloc,panic,block} { print_i64(3); }
        ''', 'E_EFFECT')
        self.assertEqual(result.effects['top'], {'io', 'alloc', 'panic', 'block'})

    def test_recursive_effects_terminate(self):
        result = self.rejects('''
            fn a()->Unit effects {} { b(); }
            fn b()->Unit effects {} { a(); assert(true); }
        ''', 'E_EFFECT')
        self.assertIn('panic', result.effects['a'])

    def test_declared_effect_is_modular_upper_bound(self):
        self.rejects('fn f()->Unit effects {block} {} fn g()->Unit effects {} { f(); }', 'E_EFFECT')

    def test_unknown_effect(self):
        self.rejects('fn f()->Unit effects {magic} {}', 'E_UNKNOWN_EFFECT')

    def test_buffer_alloc_release(self):
        self.check_ok('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); release(move b); }')

    def test_buffer_requires_release(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); }', 'E_LINEAR_UNCONSUMED')

    def test_release_needs_move(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); release(b); }', 'E_MOVE_REQUIRED')

    def test_use_after_move(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); release(move b); let n=len(b); }', 'E_USE_AFTER_MOVE')

    def test_duplicate_release(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); release(move b); release(move b); }', 'E_USE_AFTER_MOVE')

    def test_branch_must_consume_on_both_paths(self):
        self.rejects('fn f(p:bool)->Unit effects {alloc,block,panic} { let b=buffer(4); if p {release(move b);} }', 'E_LINEAR_BRANCH')

    def test_branch_both_consume(self):
        self.check_ok('fn f(p:bool)->Unit effects {alloc,block,panic} { let b=buffer(4); if p {release(move b);} else {release(move b);} }')

    def test_early_return_consumes(self):
        self.check_ok('fn f(p:bool)->Unit effects {alloc,block,panic} { let b=buffer(4); if p {release(move b);return;} release(move b); }')

    def test_early_return_leak(self):
        self.rejects('fn f(p:bool)->Unit effects {alloc,block,panic} { let b=buffer(4); if p {return;} release(move b); }', 'E_LINEAR_UNCONSUMED')

    def test_loop_may_run_zero_times(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4); for i in 0..2 {release(move b);} }', 'E_LINEAR_LOOP')

    def test_loop_local_owner_consumed(self):
        self.check_ok('fn f()->Unit effects {alloc,block,panic} { for i in 0..2 {let b=buffer(4);release(move b);} }')

    def test_loop_local_owner_leak(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} { for i in 0..2 {let b=buffer(4);} }', 'E_LINEAR_UNCONSUMED')

    def test_loop_borrows_outer_owner(self):
        self.check_ok('fn f()->Unit effects {alloc,block,panic} { let b=buffer(4);for i in 0..2 {let n=len(b);}release(move b); }')

    def test_while_condition_cannot_consume(self):
        self.rejects('''
            fn done(b:take Buffer<u8>)->bool effects {alloc,block} {release(move b);return false;}
            fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);while done(move b) {} }
        ''', 'E_LINEAR_LOOP')

    def test_short_circuit_cannot_conditionally_consume(self):
        self.rejects('''
            fn done(b:take Buffer<u8>)->bool effects {alloc,block} {release(move b);return false;}
            fn f(p:bool)->Unit effects {alloc,block,panic} {let b=buffer(4);let c=p && done(move b);}
        ''', 'E_LINEAR_SHORT_CIRCUIT')

    def test_take_and_return(self):
        self.check_ok('''
            fn relay(b:take Buffer<u8>)->Buffer<u8> effects {} {return move b;}
            fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);let c=relay(move b);release(move c);}
        ''')

    def test_take_requires_explicit_move(self):
        self.rejects('''
            fn consume(b:take Buffer<u8>)->Unit effects {alloc,block} {release(move b);}
            fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);consume(b);}
        ''', 'E_MOVE_REQUIRED')

    def test_owning_buffer_parameter_requires_take(self):
        self.rejects('fn f(b:Buffer<u8>)->Unit effects {alloc,block} {release(move b);}', 'E_LINEAR_MODE')

    def test_borrowed_buffer_cannot_move(self):
        self.rejects('fn f(b:read Buffer<u8>)->Unit effects {alloc,block} {release(move b);}', 'E_MOVE_BORROW')

    def test_buffer_alias_needs_move(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);let c=b;release(move b);release(move c);}', 'E_MOVE_REQUIRED')

    def test_buffer_reassignment(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} {let mut b=buffer(4);b=buffer(2);release(move b);}', 'E_LINEAR_REASSIGN')

    def test_nested_array_buffer_rejected(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);let a=[move b];}', 'E_NESTED_LINEAR')

    def test_nested_type_buffer_rejected(self):
        for typ in ['[Buffer<u8>;1]', 'Buffer<Buffer<u8>>', 'raw mut Buffer<u8>']:
            with self.subTest(typ=typ):
                self.rejects(f'fn f(b:read {typ})->Unit effects {{}} {{}}', 'E_NESTED_LINEAR')

    def test_struct_buffer_rejected(self):
        self.rejects('struct S { b:Buffer<u8> } fn f()->Unit effects {} {}', 'E_NESTED_LINEAR')

    def test_discard_fresh_buffer(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} {buffer(4);}', 'E_LINEAR_DISCARD')

    def test_len_fresh_buffer_rejected(self):
        self.rejects('fn f()->usize effects {alloc,block,panic} {return len(buffer(4));}', 'E_LINEAR_TEMPORARY')

    def test_len_move_cannot_escape_linearity(self):
        self.rejects('fn f()->usize effects {alloc,block,panic} {let b=buffer(4);return len(move b);}', 'E_LINEAR_TEMPORARY')

    def test_unary_cannot_escape_linearity(self):
        self.rejects('fn f()->Unit effects {alloc,block,panic} {let b=buffer(4);let n=!(move b);}', 'E_UNARY_TYPE')

    def test_cast_cannot_escape_linearity(self):
        self.rejects('fn f()->u64 effects {alloc,block,panic} {let b=buffer(4);return (move b) as u64;}', 'E_CAST')

    def test_index_fresh_buffer_rejected(self):
        self.rejects('fn f()->u8 effects {alloc,block,panic} {return buffer(4)[0];}', 'E_LINEAR_TEMPORARY')

    def test_borrow_buffer_as_slice(self):
        self.check_ok('''
            fn size(x:read [u8])->usize effects {} {return len(x);}
            fn f()->usize effects {alloc,block,panic} {let b=buffer(4);let n=size(read b);release(move b);return n;}
        ''')

    def test_borrow_alias_local_is_unsupported(self):
        self.rejects('fn f(x:read [u8])->Unit effects {} {let a=read x;}', 'E_BORROW_CONTEXT')

    def test_mutation_of_borrowed_input_has_write(self):
        self.rejects('fn f(x:mut [u8])->Unit effects {panic} {x[0]=1;}', 'E_EFFECT')
        self.check_ok('fn f(x:mut [u8])->Unit effects {panic,write} {x[0]=1;}')

    def test_local_mutation_is_not_write_effect(self):
        self.check_ok('fn f()->Unit effects {panic} {let mut x:[u8;1]=[0];x[0]=1;}')

    def test_read_parameter_cannot_mutate(self):
        self.rejects('fn f(x:read [u8])->Unit effects {panic} {x[0]=1;}', 'E_READ_ONLY')

    def test_immutable_assignment(self):
        self.rejects('fn f()->Unit effects {} {let x=1;x=2;}', 'E_IMMUTABLE')

    def test_unknown_names_and_calls(self):
        self.rejects('fn f()->i64 effects {} {return z;}', 'E_UNKNOWN_NAME')
        self.rejects('fn f()->Unit effects {} {missing();}', 'E_UNKNOWN_FUNCTION')

    def test_local_cannot_shadow_function_name(self):
        self.rejects('fn helper()->i64 effects {} {return 1;} fn f()->i64 effects {} {let helper=2;return helper();}', 'E_NAME_COLLISION')

    def test_type_mismatch(self):
        self.rejects('fn f()->i64 effects {} {return true;}', 'E_TYPE')

    def test_array_shape_mismatch(self):
        self.rejects('fn f()->Unit effects {} {let a:[u8;2]=[1];}', 'E_TYPE')

    def test_struct_initialization(self):
        self.check_ok('struct S {x:i32,y:bool} fn f()->i32 effects {} {let s=S{x:1,y:true};return s.x;}')
        self.rejects('struct S {x:i32,y:bool} fn f()->Unit effects {} {let s=S{x:1};}', 'E_STRUCT_FIELDS')

    def test_recursive_layout(self):
        self.rejects('struct A{x:A} fn f()->Unit effects {} {}', 'E_RECURSIVE_LAYOUT')

    def test_c_ffi_call_requires_unsafe(self):
        self.rejects('extern "C" fn c(x:i32)->i32 effects {ffi}; fn f()->i32 effects {ffi,unsafe} {return c(1);}', 'E_UNSAFE_REQUIRED')

    def test_c_ffi_assumptions(self):
        result = self.check_ok('extern "C" fn c(x:i32)->i32 effects {ffi}; fn f()->i32 effects {ffi,unsafe} {unsafe{return c(1);}}')
        self.assertTrue(any(a['kind'] == 'extern_contract' for a in result.assumptions))
        self.assertEqual(result.effects['f'], {'ffi', 'unsafe'})

    def test_c_ffi_must_declare_effect(self):
        self.rejects('extern "C" fn c()->Unit effects {};', 'E_EFFECT')

    def test_c_boundary_rejects_unsound_aggregate_forms(self):
        for typ in ['bool', 'i128', 'u128', '[u8;4]', 'Buffer<u8>', 'Unit']:
            with self.subTest(typ=typ):
                self.rejects(f'extern "C" fn c(x:{typ})->Unit effects {{ffi}};', 'E_C_ABI')

    def test_c_repr_is_recursive(self):
        self.rejects('struct Inner{x:i32} repr(C) struct Outer{x:Inner} extern "C" fn c(x:Outer)->Unit effects {ffi};', 'E_C_ABI')

    def test_c_struct_array_field(self):
        self.check_ok('repr(C) struct S{x:[u8;4]} extern "C" fn c(x:S)->S effects {ffi};')

    def test_c_recursive_pointer(self):
        self.check_ok('repr(C) struct Node{next:raw mut Node,value:i64} extern "C" fn c(x:raw mut Node)->Unit effects {ffi};')

    def test_c_keyword_field_rejected(self):
        self.rejects('repr(C) struct S {int:i32} fn f()->Unit effects {} {}', 'E_C_IDENTIFIER')

    def test_c_keyword_parameter_rejected(self):
        self.rejects('extern "C" fn f(restrict:i32)->Unit effects {ffi};', 'E_C_IDENTIFIER')

    def test_c_keyword_symbol_rejected(self):
        self.rejects('export "C" fn volatile()->Unit effects {} {}', 'E_C_IDENTIFIER')

    def test_c11_keyword_rejected(self):
        self.rejects('repr(C) struct S {_Atomic:i32} fn f()->Unit effects {} {}', 'E_C_IDENTIFIER')

    def test_cpp_keyword_rejected_at_c_boundary(self):
        self.rejects('repr(C) struct S {class:i32} fn f()->Unit effects {} {}', 'E_C_IDENTIFIER')
        self.rejects('extern "C" fn f(template:i32)->Unit effects {ffi};', 'E_C_IDENTIFIER')

    def test_c_typedef_symbol_collision_rejected(self):
        for name in ['size_t', 'int32_t', 'uint_fast64_t']:
            with self.subTest(name=name):
                self.rejects(f'export "C" fn {name}()->Unit effects {{}} {{}}', 'E_C_IDENTIFIER')

    def test_generated_typedef_symbol_collision_rejected(self):
        self.rejects('repr(C) struct S{x:i32} export "C" fn hepta_S()->Unit effects {} {}', 'E_C_IDENTIFIER')

    def test_typedef_parameter_shadowing_rejected(self):
        self.rejects('export "C" fn f(uint32_t:u32,other:u32)->u32 effects {} {return other;}', 'E_C_IDENTIFIER')

    def test_typedef_field_shadowing_rejected(self):
        self.rejects('repr(C) struct S{uint32_t:u32,other:u32}', 'E_C_IDENTIFIER')

    def test_header_macro_collision_rejected(self):
        for name in ['SIZE_MAX', 'INT32_MAX', 'UINT64_C', 'PTRDIFF_MAX', 'NULL', 'offsetof', 'HEPTA_EXAMPLE_H']:
            with self.subTest(name=name):
                self.rejects(f'export "C" fn {name}()->u32 effects {{}} {{return 1;}}', 'E_C_IDENTIFIER')

    def test_implementation_reserved_c_identifier_rejected(self):
        self.rejects('extern "C" fn __attribute__()->Unit effects {ffi};', 'E_C_IDENTIFIER')

    def test_non_ffi_name_may_use_c_keyword(self):
        self.check_ok('struct S {int:i32} fn volatile(restrict:i32)->i32 effects {} {let s=S{int:restrict};return s.int;}')

    def test_raw_load_requires_unsafe(self):
        self.rejects('fn f(p:raw const i64)->i64 effects {unsafe} {return load(p,0);}', 'E_UNSAFE_REQUIRED')

    def test_raw_load_and_store(self):
        self.check_ok('fn f(p:raw mut i64)->i64 effects {unsafe,write} {unsafe{store(p,0,4);return load(p,0);}}')

    def test_raw_store_const_rejected(self):
        self.rejects('fn f(p:raw const i64)->Unit effects {unsafe,write} {unsafe{store(p,0,4);}}', 'E_READ_ONLY')

    def test_integer_pointer_cast_rejected(self):
        self.rejects('fn f()->raw const u8 effects {unsafe} {unsafe{return 1 as raw const u8;}}', 'E_CAST')

    def test_unsafe_effect_call_requires_explicit_unsafe(self):
        self.rejects('fn low()->Unit effects {unsafe} {} fn high()->Unit effects {unsafe} {low();}', 'E_UNSAFE_REQUIRED')
        self.check_ok('fn low()->Unit effects {unsafe} {} fn high()->Unit effects {unsafe} {unsafe{low();}}')

    def test_supported_resource_clauses(self):
        self.check_ok('fn f()->i64 effects {} resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;} {return 1;}')

    def test_resources_reject_unknown(self):
        self.rejects('fn f()->Unit effects {} resources {stack_bytes=1024;} {}', 'E_RESOURCE_UNSUPPORTED')

    def test_resources_do_not_claim_unsupported_bounds(self):
        self.rejects('fn f()->Unit effects {} resources {heap_allocations=1;} {}', 'E_RESOURCE_UNSUPPORTED')

    def test_resource_boolean_not_treated_as_integer(self):
        self.rejects('fn f()->Unit effects {} resources {heap_allocations=false;} {}', 'E_RESOURCE_UNSUPPORTED')

    def test_resource_transitive_violation(self):
        self.rejects('''
            fn f()->Unit effects {alloc,block,panic} resources {heap_allocations=0;} {g();}
            fn g()->Unit effects {alloc,block,panic} {let b=buffer(4);release(move b);}
        ''', 'E_RESOURCE')

    def test_print_is_not_claimed_nonblocking_noalloc(self):
        result = self.rejects('fn f()->Unit effects {io,alloc,block,panic} resources {may_block=false;heap_allocations=0;} {print_i64(1);}', 'E_RESOURCE')
        self.assertEqual(result.effects['f'], {'io', 'alloc', 'block', 'panic'})

    def test_missing_return(self):
        self.rejects('fn f(p:bool)->i64 effects {} {if p{return 1;}}', 'E_MISSING_RETURN')

    def test_both_branches_return(self):
        self.check_ok('fn f(p:bool)->i64 effects {} {if p{return 1;}else{return 2;}}')

    def test_integer_literal_range(self):
        self.rejects('fn f()->u8 effects {} {return 256;}', 'E_INTEGER_RANGE')

    def test_signed_minimum_literal(self):
        self.check_ok('fn f()->i64 effects {panic} {return -9223372036854775808;}')

    def test_every_expression_gets_type(self):
        source = '''struct S{x:i32} fn consume(x:read [i32])->usize effects {} {return len(x);}
        fn f()->i32 effects {panic} {let mut a:[i32;2]=[1,2];let n=consume(read a);let s=S{x:a[0]};a[1]=s.x;return a[1] as i32;}'''
        program = parse(source)
        result = check(program)
        self.assertTrue(result.ok, [d.message for d in result.diagnostics])
        def visit(value):
            if isinstance(value, Expr):
                self.assertIn(id(value), result.expr_types)
                for child in value.children:
                    visit(child)
            elif isinstance(value, Stmt):
                visit(value.data)
            elif isinstance(value, dict):
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        for function in program.functions:
            visit(function.body)

    def test_unknown_ast_unary_fails_closed(self):
        expression = Expr('unary', 'magic', [Expr('int', 1)])
        fn = Function('f', [], Type('Unit'), set(), [Stmt('expr', {'expr': expression})])
        result = check(Program('test', [], [fn], ''))
        self.assertIn('E_UNARY_OPERATOR', [d.code for d in result.diagnostics])


class TaskCheckerTests(_CheckerAssertions, unittest.TestCase):
    worker = '''fn worker(data: take Buffer<u8>, token: read Cancellation) -> u64
        effects {alloc,block} {let stop=cancelled(read token);release(move data);return 7;}'''

    def task_source(self, body, effects='spawn,alloc,block,panic'):
        return self.worker + f'fn f()->Unit effects {{{effects}}} {{let data=buffer(4);{body}}}'

    def test_task_spawn_join(self):
        result = self.check_ok(self.task_source('let task:Task<u64> = spawn(worker,move data);let result=join(move task);'))
        self.assertEqual(result.effects['f'], {'spawn', 'alloc', 'block', 'panic'})

    def test_task_cancel_and_join(self):
        self.check_ok(self.task_source('let task=spawn(worker,move data);let result=cancel_and_join(move task);'))

    def test_task_must_join(self):
        self.rejects(self.task_source('let task=spawn(worker,move data);'), 'E_LINEAR_UNCONSUMED')

    def test_task_cannot_discard(self):
        self.rejects(self.task_source('spawn(worker,move data);'), 'E_LINEAR_DISCARD')

    def test_task_join_needs_move(self):
        self.rejects(self.task_source('let task=spawn(worker,move data);join(task);'), 'E_MOVE_REQUIRED')

    def test_task_duplicate_join(self):
        self.rejects(self.task_source('let task=spawn(worker,move data);join(move task);join(move task);'), 'E_USE_AFTER_MOVE')

    def test_task_move_alias_then_join(self):
        self.check_ok(self.task_source('let task=spawn(worker,move data);let next=move task;join(move next);'))

    def test_task_parameter_escape_rejected(self):
        self.rejects('fn f(t:take Task<u64>)->Unit effects {alloc,block,panic} {join(move t);}', 'E_TASK_SCOPE')

    def test_task_return_escape_rejected(self):
        self.rejects(self.worker + 'fn f()->Task<u64> effects {alloc,block,spawn,panic} {return move spawn(worker,move buffer(4));}', 'E_TASK_SCOPE')

    def test_task_nested_array_rejected(self):
        self.rejects(self.task_source('let task=spawn(worker,move data);let arr=[move task];'), 'E_NESTED_LINEAR')

    def test_task_nested_raw_rejected(self):
        self.rejects('fn f(t:raw mut Task<u64>)->Unit effects {} {}', 'E_NESTED_LINEAR')

    def test_task_wrong_result_type_rejected(self):
        self.rejects(self.task_source('let task:Task<i64> = spawn(worker,move data);join(move task);'), 'E_TASK_TYPE')

    def test_task_worker_must_be_named_local_function(self):
        self.rejects(self.task_source('let task=spawn(missing,move data);join(move task);'), 'E_TASK_WORKER')

    def test_task_worker_signature_checked(self):
        self.rejects('fn worker()->u64 effects {} {return 1;} fn f()->Unit effects {spawn,alloc,block,panic} {let task=spawn(worker,move buffer(4));join(move task);}', 'E_TASK_WORKER')

    def test_task_worker_must_consume_input(self):
        self.rejects('fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {} {return 1;}', 'E_LINEAR_UNCONSUMED')

    def test_task_data_requires_explicit_move(self):
        self.rejects(self.task_source('let task=spawn(worker,data);join(move task);'), 'E_MOVE_REQUIRED')

    def test_task_data_is_moved_into_worker(self):
        self.rejects(self.task_source('let task=spawn(worker,move data);let n=len(data);join(move task);'), 'E_USE_AFTER_MOVE')

    def test_task_branch_join_required(self):
        source = self.worker + 'fn f(p:bool)->Unit effects {spawn,alloc,block,panic} {let task=spawn(worker,move buffer(4));if p{join(move task);}}'
        self.rejects(source, 'E_LINEAR_BRANCH')

    def test_task_loop_local_join(self):
        self.check_ok(self.worker + 'fn f()->Unit effects {spawn,alloc,block,panic} {for i in 0..2{let task=spawn(worker,move buffer(4));join(move task);}}')

    def test_task_worker_cannot_spawn_recursively(self):
        source = '''fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block,spawn,panic} {
            let child=spawn(worker,move data);return join(move child);
        } fn f()->Unit effects {alloc,block,spawn,panic} {let task=spawn(worker,move buffer(4));join(move task);}'''
        self.rejects(source, 'E_TASK_WORKER_EFFECT')

    def test_task_worker_cannot_hide_unsafe_in_helper(self):
        source = '''fn helper()->Unit effects {unsafe} {unsafe{}}
        fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block,unsafe} {
            unsafe{helper();}release(move data);return 1;
        } fn f()->Unit effects {alloc,block,spawn,panic,unsafe} {let task=spawn(worker,move buffer(4));join(move task);}'''
        self.rejects(source, 'E_TASK_WORKER_EFFECT')

    def test_task_worker_weak_effect_annotation_rejected(self):
        source = '''fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {} {release(move data);return 1;}
        fn f()->Unit effects {alloc,block,spawn,panic} {let task=spawn(worker,move buffer(4));join(move task);}'''
        self.rejects(source, 'E_EFFECT')

    def test_task_effects_propagate_worker_io(self):
        source = '''fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block,panic,io} {print_i64(1);release(move data);return 1;}
        fn f()->Unit effects {alloc,block,spawn,panic} {let task=spawn(worker,move buffer(4));join(move task);}'''
        result = self.rejects(source, 'E_EFFECT')
        self.assertIn('io', result.effects['f'])

    def test_cancellation_is_read_only_capability(self):
        self.check_ok('fn f(token:read Cancellation)->bool effects {} {return cancelled(read token);}')
        self.rejects('fn f(token:mut Cancellation)->Unit effects {} {}', 'E_CANCELLATION_TYPE')
        self.rejects('fn f(token:Cancellation)->Unit effects {} {}', 'E_CANCELLATION_TYPE')

    def test_cancellation_cannot_copy_to_local(self):
        self.rejects('fn f(token:read Cancellation)->Unit effects {} {let x=token;}', 'E_CANCELLATION_TYPE')

    def test_cancellation_cannot_be_nested(self):
        self.rejects('fn f(token:read Cancellation)->Unit effects {} {let x=[token];}', 'E_CANCELLATION_TYPE')
        self.rejects('struct S{x:Cancellation}', 'E_CANCELLATION_TYPE')

    def test_cancellation_cannot_return(self):
        self.rejects('fn f(token:read Cancellation)->Cancellation effects {} {return token;}', 'E_CANCELLATION_TYPE')

    def test_cancellation_requires_explicit_borrow(self):
        self.rejects('fn f(token:read Cancellation)->bool effects {} {return cancelled(token);}', 'E_BORROW_MODE')

    def test_task_resource_no_spawn_rejected(self):
        source = self.worker + 'fn f()->Unit effects {alloc,block,spawn,panic} resources {may_spawn=false;} {let task=spawn(worker,move buffer(4));join(move task);}'
        self.rejects(source, 'E_RESOURCE')


if __name__ == '__main__':
    unittest.main()
