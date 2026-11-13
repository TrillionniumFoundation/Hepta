"""Layouts for the already verified, local single-slice Resource IR v4 subset.

This is a native layout admission check, not another loan checker. Callers
must first verify the complete source-derived resource graph. The v5 labelled
view profile and all escaping/compound lifetime forms remain unsupported.
"""
from .ast import Type


def local_slice_view_layouts(program, resource_types):
    declarations = {}
    for declaration in program.structs:
        if not declaration.lifetime_params:
            continue
        if (declaration.repr_c or declaration.type_params or len(declaration.lifetime_params) != 1
                or len(declaration.fields) != 1):
            raise ValueError("Native stored views require one local u8 slice field and one lifetime")
        field = declaration.fields[0]
        if (field.type.name not in {"ref_read", "ref_mut"}
                or field.type.args != (Type("slice", (Type("u8"),)),)
                or field.type.lifetimes != declaration.lifetime_params):
            raise ValueError("Native stored view field is outside the local u8 slice profile")
        declarations[declaration.name] = field
    layouts = {}
    for key, descriptor in resource_types.items():
        if descriptor["kind"] != "view":
            continue
        if set(descriptor) != {"kind", "name", "field", "mode", "pointee"}:
            raise ValueError("Only exact Resource IR v4 view layouts reach native code")
        name, mode = descriptor["name"], descriptor["mode"]
        typ = Type(name, lifetimes=("_",))
        field = declarations.get(name)
        if (field is None or key != str(typ) or descriptor["field"] != field.name
                or mode not in {"read", "mut"} or field.type.name != "ref_" + mode
                or descriptor["pointee"] != "[u8]"):
            raise ValueError("Verified local view identity differs from its source layout")
        layouts[typ] = descriptor
    return layouts
