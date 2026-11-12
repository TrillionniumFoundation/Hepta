"""Frozen valid neighbours and compile-only rejection candidates for views."""

SHARED = """struct View<'a>{ data:read 'a [u8] }
fn view<'a>(data:read 'a Buffer<u8>)->View<'a> effects {} {return View{data:read data};}
"""
MUTABLE = """struct Edit<'a>{ data:mut 'a [u8] }
fn edit<'a>(data:mut 'a Buffer<u8>)->Edit<'a> effects {} {return Edit{data:mut data};}
fn forward<'a>(value:take Edit<'a>)->Edit<'a> effects {} {return move value;}
"""

POSITIVES = {
    "shared_scalar_and_scoped_shortening": """struct Value<'a>{item:read 'a u64}
fn choose<'a>(a:Value<'a>,b:Value<'a>,right:bool)->Value<'a> effects {} {if right{return b;}return a;}
fn main()->Unit effects {panic} {
    let outer:u64=7;
    if true {let inner:u64=9;let a=Value{item:read outer};let b=Value{item:read inner};
        let chosen=choose(a,b,true);let copy=chosen;assert(copy.item==9);assert(a.item==7);
        let inline=choose(Value{item:read outer},b,false);assert(inline.item==7);}
    assert(outer==7);
}""",
    "disjoint_fields_and_returned_reborrow": """struct Owners{left:Buffer<u8>,right:Buffer<u8>}
struct Split<'a>{output:mut 'a [u8],input:read 'a [u8]}
fn split<'a>(owner:mut 'a Owners)->Split<'a> effects {} {
    return Split{output:mut owner.left,input:read owner.right};
}
fn main()->Unit effects {alloc,block,panic,write} {
    let mut owner=Owners{left:buffer(3),right:buffer(3)};owner.right[0]=41;
    let mut view=split(mut owner);view.output[0]=view.input[0];drop(move view);
    assert(owner.left[0]==41);drop(move owner);
}""",
    "nested_mutable_field_transfer": MUTABLE + """
struct Nest<'a>{inner:Edit<'a>,tag:u64}
fn nest<'a>(value:take Edit<'a>)->Nest<'a> effects {} {return Nest{inner:move value,tag:19};}
fn main()->Unit effects {alloc,block,panic,write} {
    let mut owner=buffer(4);let outer=nest(move edit(mut owner));
    let mut inner=forward(move outer.inner);inner.data[1]=37;assert(outer.tag==19);
    drop(move inner);assert(owner[1]==37);release(move owner);
}""",
    "mutable_view_each_loop_iteration": MUTABLE + """
fn main()->Unit effects {alloc,block,panic,write} {
    let mut owner=buffer(8);
    for i in 0..8 {let mut view=forward(move edit(mut owner));view.data[i as usize]=i as u8;drop(move view);}
    let mut total:u64=0;for i in 0..8 {total=wrapping_add(total,owner[i as usize] as u64);}
    assert(total==28);release(move owner);
}""",
}

# All these sources must pass the structural frontend, then be rejected by
# rustc's actual lifetime/alias checking. No rejected candidate is executed.
NATIVE_REJECTIONS = {
    "copied_shared_view_keeps_owner_live": (SHARED + """
fn main()->Unit effects {alloc,block,panic} {
    let owner=buffer(4);let first=view(read owner);let copied=first;
    release(move owner);assert(copied.data[0]==0);
}""", {"E0505"}),
    "shared_view_blocks_owner_mutation": (SHARED + """
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(4);let first=view(read owner);owner[0]=9;assert(first.data[0]==0);release(move owner);
}""", {"E0502"}),
    "mutable_view_blocks_owner_mutation": (MUTABLE + """
fn main()->Unit effects {alloc,block,panic,write} {
    let mut owner=buffer(4);let value=edit(mut owner);owner[0]=9;assert(value.data[0]==0);
    drop(move value);release(move owner);
}""", {"E0499"}),
    "mutable_view_blocks_owner_read": (MUTABLE + """
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(4);let value=edit(mut owner);assert(owner[0]==0);drop(move value);release(move owner);
}""", {"E0502"}),
    "two_fields_cannot_borrow_same_place_mutably": ("""struct Both<'a>{left:mut 'a [u8],right:mut 'a [u8]}
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(4);let value=Both{left:mut owner,right:mut owner};drop(move value);release(move owner);
}""", {"E0499"}),
    "mutable_and_shared_fields_cannot_overlap": ("""struct Both<'a>{left:mut 'a [u8],right:read 'a [u8]}
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(4);let value=Both{left:mut owner,right:read owner};drop(move value);release(move owner);
}""", {"E0502"}),
    "returned_view_cannot_borrow_local": ("""struct Value<'a>{item:read 'a u64}
fn bad<'a>(input:read 'a u64)->Value<'a> effects {} {
    let local:u64=3;return Value{item:read local};
}
fn main()->Unit effects {} {}
""", {"E0515"}),
    "stored_local_cannot_escape_inner_block": ("""struct Value<'a>{item:read 'a u64}
fn main()->Unit effects {panic} {
    let outer:u64=7;let mut value=Value{item:read outer};
    if true {let inner:u64=9;value=Value{item:read inner};}
    assert(value.item==9);
}""", {"E0597"}),
    "unrelated_lifetime_cannot_satisfy_return": ("""struct Value<'a>{item:read 'a u64}
fn bad<'a,'b>(a:read 'a u64,b:read 'b u64)->Value<'a> effects {} {return Value{item:read b};}
fn main()->Unit effects {} {}
""", {"E_RUSTC"}),
    "owned_parameter_cannot_escape_in_view": (SHARED + """
fn bad<'a>(owner:take Buffer<u8>)->View<'a> effects {alloc,block} {
    let value=view(read owner);release(move owner);return value;
}
fn main()->Unit effects {} {}
""", {"E0505", "E0515"}),
}

FRONTEND_REJECTIONS = {
    "mutable_view_requires_move": (MUTABLE + """
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(3);let value=edit(mut owner);let copied=value;drop(move value);drop(move copied);release(move owner);
}""", "E_MOVE_REQUIRED"),
    "mutable_view_after_function_transfer": (MUTABLE + """
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(3);let value=edit(mut owner);let next=forward(move value);assert(value.data[0]==0);drop(move next);release(move owner);
}""", "E_USE_AFTER_MOVE"),
    "nested_mutable_view_after_field_transfer": (MUTABLE + """
struct Outer<'a>{inner:Edit<'a>}
fn main()->Unit effects {alloc,block,panic} {
    let mut owner=buffer(3);let outer=Outer{inner:move edit(mut owner)};let inner=move outer.inner;
    assert(outer.inner.data[0]==0);drop(move inner);release(move owner);
}""", "E_USE_AFTER_MOVE"),
    "shared_field_cannot_grant_mutation": (SHARED + """
fn main()->Unit effects {alloc,block,panic} {let owner=buffer(3);let mut v=view(read owner);v.data[0]=1;release(move owner);}
""", "E_READ_ONLY"),
    "borrowed_owner_cannot_be_moved_from_field": ("""struct Ref<'a>{data:read 'a Buffer<u8>}
fn main()->Unit effects {alloc,block,panic} {let owner=buffer(3);let v=Ref{data:read owner};release(move v.data);release(move owner);}
""", "E_MOVE_BORROW"),
    "from_origin_conflicts_with_explicit_lifetime": ("""fn bad<'a,'b>(a:read 'a u64,b:read 'b u64)->read 'b u64 from a effects {} {return read a;}
""", "E_LIFETIME_ORIGIN"),
    "undeclared_lifetime": ("struct V<'a>{data:read 'b u64}", "E_LIFETIME_SCOPE"),
    "missing_lifetime_argument": ("struct V<'a>{data:read 'a u64} fn bad(x:V)->Unit effects {} {}", "E_LIFETIME_ARITY"),
    "stored_standalone_reference_local": ("fn main()->Unit effects {} {let x:u64=1;let v:read '_ u64=read x;}", "E_BORROW_STORAGE_PROFILE"),
    "owned_and_borrowed_payload_mixture": ("struct V<'a>{data:read 'a u64,owner:Buffer<u8>}", "E_BORROW_STORAGE_PROFILE"),
    "mixed_type_and_lifetime_parameters": ("struct V<'a,T>{data:read 'a T}", "E_BORROW_STORAGE_PROFILE"),
    "generic_argument_cannot_hide_view": (SHARED + "struct Box<T>{item:T} fn bad<'a>(x:Box<View<'a>>)->Unit effects {} {}", "E_BORROW_STORAGE_PROFILE"),
    "inferred_array_cannot_hide_view": (SHARED + "fn main()->Unit effects {alloc,block,panic}{let x=buffer(1);let a=[view(read x)];release(move x);}", "E_BORROW_STORAGE_PROFILE"),
    "c_boundary_cannot_export_view": (SHARED + "export \"C\" fn bad<'a>(x:View<'a>)->u64 effects {} {return 0;}", "E_LIFETIME_BOUNDARY"),
    "raw_pointer_field_not_supported": ("struct V<'a>{data:read 'a u64,pointer:raw const u64}", "E_BORROW_STORAGE_PROFILE"),
    "reference_cannot_hide_task": ("struct V<'a>{data:read 'a Task<u64>}", "E_NESTED_LINEAR"),
    "reference_cannot_hide_cancellation": ("struct V<'a>{data:read 'a Cancellation}", "E_CANCELLATION_TYPE"),
    "static_lifetime_not_invented": ("struct V<'static>{data:read 'static u64}", "E_LIFETIME_PARAMETER"),
    "enum_cannot_hide_stored_view": (SHARED + "enum Wrapped{Value(View<'_>),Empty}", "E_BORROW_STORAGE_PROFILE"),
    "reference_to_another_view_not_supported": (SHARED + "struct Nested<'a>{value:read 'a View<'a>}", "E_BORROW_STORAGE_PROFILE"),
    "borrowed_record_has_no_c_layout": ("repr(C) struct CView<'a>{data:read 'a u64}", "E_C_ABI"),
    "reference_cannot_hide_io_capability": ("struct V<'a>{data:read 'a IoRequest}", "E_BORROW_STORAGE_PROFILE"),
}
