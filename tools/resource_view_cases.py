"""Fixed local-view neighbours; invalid programs are checked, never executed."""

VIEWS = """struct Bytes<'a>{data:read 'a [u8]}
struct Edit<'a>{data:mut 'a [u8]}
"""

NATIVE_REJECTIONS = {
    "copied_shared_view_keeps_owner_alive": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let owner=buffer(4);let first=Bytes{data:read owner};let copied=first;
 release(move owner);assert(copied.data[0]==0);
}""", {"E0505"}),
    "shared_view_blocks_owner_write": (VIEWS + """
fn main()->Unit effects {alloc,block,panic,write} {
 let mut owner=buffer(4);let first=Bytes{data:read owner};
 owner[0]=9;assert(first.data[0]==0);release(move owner);
}""", {"E0502"}),
    "exclusive_view_blocks_owner_read": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let mut owner=buffer(4);let edit=Edit{data:mut owner};
 assert(owner[0]==0);drop(move edit);release(move owner);
}""", {"E0502"}),
    "exclusive_view_blocks_owner_write": (VIEWS + """
fn main()->Unit effects {alloc,block,panic,write} {
 let mut owner=buffer(4);let edit=Edit{data:mut owner};
 owner[0]=9;assert(edit.data[0]==0);drop(move edit);release(move owner);
}""", {"E0499"}),
    "two_exclusive_views_overlap": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let mut owner=buffer(4);let first=Edit{data:mut owner};let second=Edit{data:mut owner};
 drop(move first);drop(move second);release(move owner);
}""", {"E0499"}),
    "shared_and_exclusive_views_overlap": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let mut owner=buffer(4);let first=Bytes{data:read owner};let second=Edit{data:mut owner};
 assert(first.data[0]==0);drop(move second);release(move owner);
}""", {"E0502"}),
    "owned_field_cannot_move_under_view": (VIEWS + """
struct Owner{data:Buffer<u8>}
fn main()->Unit effects {alloc,block,panic} {
 let owner=Owner{data:buffer(4)};let view=Bytes{data:read owner.data};
 let moved=move owner.data;assert(view.data[0]==0);release(move moved);
}""", {"E0505"}),
}

FRONTEND_REJECTIONS = {
    "exclusive_copy": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let mut owner=buffer(4);let edit=Edit{data:mut owner};let copied=edit;
 drop(move edit);drop(move copied);release(move owner);
}""", "E_MOVE_REQUIRED"),
    "exclusive_use_after_move": (VIEWS + """
fn main()->Unit effects {alloc,block,panic} {
 let mut owner=buffer(4);let edit=Edit{data:mut owner};let next=move edit;
 assert(edit.data[0]==0);drop(move next);release(move owner);
}""", "E_USE_AFTER_MOVE"),
    "shared_write": (VIEWS + """
fn main()->Unit effects {alloc,block,panic,write} {
 let owner=buffer(4);let mut view=Bytes{data:read owner};view.data[0]=7;release(move owner);
}""", "E_READ_ONLY"),
}

SCOPED_NEIGHBOURS = VIEWS + """
struct Pair{left:Buffer<u8>,right:Buffer<u8>}
fn early(data:read [u8],flag:bool)->u8 effects {panic} {
 let view=Bytes{data:read data};if flag{return view.data[0];}return 0;
}
fn main()->Unit effects {alloc,block,panic,write} {
 let mut owner=Pair{left:buffer(4),right:buffer(4)};
 if true {
  let mut edit=Edit{data:mut owner.left};let input=Bytes{data:read owner.right};
  edit.data[0]=input.data[0]+7;drop(move edit);
 }
 for i in 0..4 {
  let value=Edit{data:mut owner.right};let mut moved=move value;
  moved.data[i as usize]=i as u8;drop(move moved);
 }
 if true {
  let first=Bytes{data:read owner.left};let second=first;
  assert(first.data[0]==7);assert(second.data[0]==7);assert(owner.left[0]==7);
 }
 assert(early(read owner.left,true)==7);assert(owner.right[3]==3);drop(move owner);
}
"""
