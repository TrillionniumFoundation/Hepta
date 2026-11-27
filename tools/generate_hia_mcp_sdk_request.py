"""Author the native rmcp typed-envelope projection over validated raw JSON.

The SDK's Value grammar and the native HIA wire gate remain separate. This
projection retains spans and the few typed control fields only; unknown SDK
Value fields never consume the stricter HIA retained-node arena.
"""
from tools.generate_hia_mcp_request import tool_names

KEYS = (
    'jsonrpc', 'method', 'id', 'params', 'result', 'error', '_meta',
    'name', 'arguments', 'inputResponses', 'requestState', 'uri',
    'protocolVersion', 'capabilities', 'clientInfo', 'cursor', 'requestId',
    'reason', 'experimental', 'extensions', 'roots', 'sampling', 'elicitation',
    'title', 'version', 'description', 'icons', 'websiteUrl', 'listChanged',
    'tools', 'context', 'form', 'url', 'schemaValidation', 'src', 'mimeType',
    'sizes', 'theme', 'code', 'message', 'data', 'ref', 'type', 'argument', 'value',
    'io.modelcontextprotocol/protocolVersion',
    'io.modelcontextprotocol/clientCapabilities',
)
METHODS = (
    'initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call',
    'resources/list', 'resources/templates/list', 'resources/read',
    'notifications/cancelled', 'server/discover',
    'prompts/list', 'resources/subscribe', 'resources/unsubscribe', 'completion/complete',
)
STANDARD = (
    'prompts/get', 'subscriptions/listen', 'elicitation/create',
    'logging/setLevel', 'roots/list', 'sampling/createMessage',
    'notifications/message', 'notifications/progress',
    'notifications/prompts/list_changed', 'notifications/resources/list_changed',
    'notifications/resources/updated', 'notifications/roots/list_changed',
    'notifications/subscriptions/acknowledged', 'notifications/tools/list_changed',
)
VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28')
# Atomic types: Value, string, bool, JsonObject, map<JsonObject>, strings,
# icons, IconTheme, RequestId, i32, map<string>, Reference, ReferenceTag.
# 100+N denotes a struct, 1000+T Option<T>. Reference retains the SDK's
# internally tagged object and exact tagged-sequence forms.
SCHEMAS = {
    1: (('_meta', 1004), ('name', 2), ('arguments', 1004), ('inputResponses', 1004), ('requestState', 1002)),
    2: (('_meta', 1004), ('uri', 2), ('inputResponses', 1004), ('requestState', 1002)),
    3: (('_meta', 1004), ('protocolVersion', 2), ('capabilities', 107), ('clientInfo', 108)),
    4: (('_meta', 1004), ('cursor', 1002)),
    5: (('requestId', 1009), ('reason', 1002), ('_meta', 1004)),
    6: (('_meta', 1004),),
    7: (('experimental', 1005), ('extensions', 1005), ('roots', 1109), ('sampling', 1110), ('elicitation', 1111)),
    8: (('name', 2), ('title', 1002), ('version', 2), ('description', 1002), ('icons', 1007), ('websiteUrl', 1002)),
    9: (('listChanged', 1003),),
    10: (('tools', 1004), ('context', 1004)),
    11: (('form', 1112), ('url', 1113)),
    12: (('schemaValidation', 1003),),
    13: (),
    14: (('src', 2), ('mimeType', 1002), ('sizes', 1006), ('theme', 1008)),
    15: (('code', 10), ('message', 2), ('data', 1001)),
    16: (('_meta', 1004), ('uri', 2)),
    17: (('_meta', 1004), ('ref', 12), ('argument', 118), ('context', 1119)),
    18: (('name', 2), ('value', 2)),
    19: (('arguments', 1011),),
    20: (('type', 13), ('uri', 2)),
    21: (('type', 13), ('name', 2), ('title', 1002)),
}

SOURCE = r'''
def sdk_message(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if widen(sdk_value(s, w)) != 1:
        return 0
    root = 0
    if length(s) >= 3 and byte(s, 0) == 239:
        root = 3
    root = whitespace(s, root)
    if byte(s, root) != 123:
        return 1
    version = sdk_find(s, w, root, K_jsonrpc)
    method = sdk_find(s, w, root, K_method)
    id = sdk_find(s, w, root, K_id)
    params = sdk_find(s, w, root, K_params)
    result = sdk_find(s, w, root, K_result)
    error = sdk_find(s, w, root, K_error)
    if version == 0 or version >> 63 != 0 or sdk_token(s, w, sdk_at(version)) != T_VERSION:
        return sdk_invalid(s, w, root)
    kind = 0
    if method != 0 and result == 0 and error == 0:
        kind = choose(id == 0, 2, 1)
        if method >> 63 != 0 or sdk_kind(s, method) != 34 or params >> 63 != 0:
            return sdk_invalid(s, w, root)
        if params != 0 and sdk_kind(s, params) != 110 and sdk_kind(s, params) != 123:
            return sdk_invalid(s, w, root)
    elif method == 0 and result != 0 and error == 0:
        kind = 3
        if result >> 63 != 0 or id == 0:
            return sdk_invalid(s, w, root)
    elif method == 0 and result == 0 and error != 0:
        kind = 4
        if error >> 63 != 0 or sdk_struct(s, w, error, 15, 0) == 0:
            return sdk_invalid(s, w, root)
    else:
        return sdk_invalid(s, w, root)
    idkind = 0
    idnumber = 0
    if id != 0 and (kind != 4 or sdk_kind(s, id) != 110):
        idkind = sdk_id(s, w, id)
        if id >> 63 != 0 or idkind == 0:
            return sdk_invalid(s, w, root)
        idnumber = get(w, 20144)
    elif id >> 63 != 0:
        return sdk_invalid(s, w, root)
    index = 0
    while index < 160:
        put(o, index, 0)
        index = index + 8
    put(o, 0, SDK_MAGIC)
    put(o, 8, kind)
    put(o, 24, id)
    put(o, 32, method)
    put(o, 40, params)
    put(o, 64, idkind)
    put(o, 72, idnumber)
    if kind == 3 or kind == 4:
        return 160
    meta = 0
    if sdk_kind(s, params) == 123:
        meta = sdk_find(s, w, sdk_at(params), K__meta)
        if meta >> 63 != 0 or (meta != 0 and sdk_kind(s, meta) != 110 and sdk_kind(s, meta) != 123):
            return sdk_invalid(s, w, root)
    put(o, 80, meta)
    role = sdk_role(sdk_token(s, w, sdk_at(method)))
    typed = 1
    if kind == 1:
        if role == 2 or role == 9:
            role = 0
        if role == 1:
            typed = sdk_struct(s, w, params, 3, 0)
        elif role == 5:
            typed = sdk_struct(s, w, params, 1, 0)
        elif role == 8:
            typed = sdk_struct(s, w, params, 2, 0)
        elif role == 4 or role == 6 or role == 7 or role == 11:
            typed = 1
        elif role == 10:
            typed = sdk_struct(s, w, params, 6, 0)
        elif role == 12 or role == 13:
            typed = sdk_struct(s, w, params, 16, 0)
        elif role == 14:
            typed = sdk_struct(s, w, params, 17, 0)
    else:
        if role == 9:
            if params != 0 and sdk_kind(s, params) != 110:
                typed = sdk_struct(s, w, params, 5, 0)
        elif role != 2:
            role = 0
    if typed == 0:
        role = 0
    put(o, 16, role)
    if role == 5:
        name = sdk_find(s, w, sdk_at(params), K_name)
        put(o, 56, sdk_tool(sdk_token(s, w, sdk_at(name))))
        args = sdk_find(s, w, sdk_at(params), K_arguments)
        if sdk_kind(s, args) == 110:
            args = 0
        put(o, 48, args)
    if role == 8:
        put(o, 48, sdk_find(s, w, sdk_at(params), K_uri))
    if role == 9 and sdk_kind(s, params) == 123:
        target = sdk_find(s, w, sdk_at(params), K_requestId)
        if target != 0 and sdk_kind(s, target) != 110:
            targetkind = sdk_id(s, w, target)
            put(o, 120, target)
            put(o, 128, targetkind)
            put(o, 136, get(w, 20144))
    missing = 3
    if sdk_kind(s, meta) == 123:
        protocol = sdk_find(s, w, sdk_at(meta), K_INLINE_VERSION) & 9223372036854775807
        capabilities = sdk_find(s, w, sdk_at(meta), K_INLINE_CAPS) & 9223372036854775807
        put(o, 88, protocol)
        put(o, 96, capabilities)
        if sdk_kind(s, protocol) == 34:
            missing = missing & 2
            put(o, 112, sdk_version(sdk_token(s, w, sdk_at(protocol))))
        if sdk_struct(s, w, capabilities, 7, 1) == 1:
            missing = missing & 1
    put(o, 104, missing)
    return 160

def sdk_invalid(s:readbuf, w:mutbuf, root:u64) -> u32:
    method = sdk_find(s, w, root, K_method) & 9223372036854775807
    if sdk_kind(s, method) != 34:
        return 1
    token = sdk_token(s, w, sdk_at(method))
    if sdk_standard(token) == 0:
        if sdk_find(s, w, root, K_id) == 0 or sdk_notification_prefix(s, sdk_at(method)) == 1:
            return 0
    return 1

def sdk_at(span:u64) -> u64:
    return (span & 16777215) - 1

def sdk_end(span:u64) -> u64:
    return (span >> 24) & 16777215

def sdk_kind(s:readbuf, span:u64) -> u64:
    if span == 0 or span >> 63 != 0:
        return 0
    return byte(s, sdk_at(span))

def sdk_skip(s:readbuf, at:u64) -> u64:
    first = byte(s, at)
    if first == 34:
        at = at + 1
        while at < length(s):
            ch = byte(s, at)
            at = at + 1
            if ch == 34:
                return at
            if ch == 92:
                at = at + 1
        return at
    if first == 91 or first == 123:
        depth = 1
        at = at + 1
        while depth != 0:
            ch = byte(s, at)
            if ch == 34:
                at = sdk_skip(s, at)
            else:
                if ch == 91 or ch == 123:
                    depth = depth + 1
                if ch == 93 or ch == 125:
                    depth = depth - 1
                at = at + 1
        return at
    while at < length(s):
        ch = byte(s, at)
        if ch == 32 or ch == 9 or ch == 10 or ch == 13 or ch == 44 or ch == 93 or ch == 125:
            return at
        at = at + 1
    return at

def sdk_find(s:readbuf, w:mutbuf, at:u64, field:u64) -> u64:
    if at >= length(s) or byte(s, at) != 123:
        return 0
    answer = 0
    at = whitespace(s, at + 1)
    while byte(s, at) != 125:
        token = sdk_token(s, w, at)
        at = whitespace(s, sdk_skip(s, at))
        at = whitespace(s, at + 1)
        end = sdk_skip(s, at)
        if token == field:
            answer = (end << 24) | (at + 1) | choose(answer != 0, 9223372036854775808, 0)
        at = whitespace(s, end)
        if byte(s, at) == 44:
            at = whitespace(s, at + 1)
    return answer

def sdk_id(s:readbuf, w:mutbuf, span:u64) -> u64:
    put(w, 20144, 0)
    if sdk_kind(s, span) == 34:
        return 2
    ch = sdk_kind(s, span)
    if ch != 45 and (ch < 48 or ch > 57):
        return 0
    at = sdk_at(span)
    end = sdk_end(span)
    negative = choose(ch == 45, 1, 0)
    if stored_integer(s, at, end - at) == 1:
        value = 0
        index = at + negative
        while index < end:
            value = value * 10 + byte(s, index) - 48
            index = index + 1
        if negative == 0 and value > 9223372036854775807:
            return 0
        put(w, 20144, choose(negative == 1, 0 - value, value))
        return 1
    if widen(decimal_convert(s, w, at, end - at)) != 8:
        return 0
    bits = decimal_get(w, 8000)
    magnitude = bits & 9223372036854775807
    if magnitude == 0:
        return 1
    exponent = (bits >> 52) & 2047
    if exponent < 1023 or exponent >= 1076:
        return 0
    shift = 1075 - exponent
    mantissa = (bits & 4503599627370495) | 4503599627370496
    if shift > 52 or (mantissa & ((1 << shift) - 1)) != 0:
        return 0
    value = mantissa >> shift
    put(w, 20144, choose(bits >> 63 == 1, 0 - value, value))
    return 1

def sdk_valid(s:readbuf, w:mutbuf, span:u64, shape:u64, normalized:u64) -> u64:
    if shape >= 1000:
        if span == 0 or sdk_kind(s, span) == 110:
            return 1
        shape = shape - 1000
    if span == 0 or span >> 63 != 0:
        return 0
    ch = sdk_kind(s, span)
    if shape == 1:
        return 1
    if shape == 2:
        return choose(ch == 34, 1, 0)
    if shape == 3:
        if ch == 116 or ch == 102:
            return 1
        return 0
    if shape == 4:
        return choose(ch == 123, 1, 0)
    if shape == 9:
        return choose(sdk_id(s, w, span) != 0, 1, 0)
    if shape == 10:
        if ch != 45 and (ch < 48 or ch > 57):
            return 0
        if stored_integer(s, sdk_at(span), sdk_end(span) - sdk_at(span)) == 0:
            return 0
        if sdk_id(s, w, span) == 0:
            return 0
        value = get(w, 20144)
        if value <= 2147483647 or value >= 18446744071562067968:
            return 1
        return 0
    if shape == 8:
        token = sdk_token(s, w, sdk_at(span))
        if token == T_LIGHT or token == T_DARK:
            return 1
        return 0
    if shape >= 100:
        return sdk_struct(s, w, span, shape - 100, normalized)
    if shape == 12:
        return sdk_reference(s, w, span, normalized)
    if shape == 13:
        return choose(sdk_reference_tag(s, w, span) != 0, 1, 0)
    mapping = choose(shape == 5 or shape == 11, 1, 0)
    if mapping == 1:
        if ch != 123:
            return 0
    elif ch != 91:
        return 0
    at = whitespace(s, sdk_at(span) + 1)
    while byte(s, at) != choose(mapping == 1, 125, 93):
        key = at
        if mapping == 1:
            at = whitespace(s, sdk_skip(s, at))
            at = whitespace(s, at + 1)
        end = sdk_skip(s, at)
        part = (end << 24) | (at + 1)
        child = choose(shape == 5, 4, choose(shape == 6 or shape == 11, 2, 114))
        if sdk_valid(s, w, part, child, normalized) == 0:
            if normalized == 0 or mapping == 0 or sdk_later_key(s, key, end) == 0:
                return 0
        at = whitespace(s, end)
        if byte(s, at) == 44:
            at = whitespace(s, at + 1)
    return 1

def sdk_reference_tag(s:readbuf, w:mutbuf, span:u64) -> u64:
    if span == 0 or span >> 63 != 0:
        return 0
    at = sdk_at(span)
    token = sdk_token(s, w, at)
    if token == T_REFERENCE_RESOURCE:
        return 1
    if token == T_REFERENCE_PROMPT:
        return 2
    if sdk_end(span) == at + 1:
        ch = byte(s, at)
        if ch == 48 or ch == 49:
            return ch - 47
    return 0

def sdk_reference(s:readbuf, w:mutbuf, span:u64, normalized:u64) -> u64:
    ch = sdk_kind(s, span)
    if ch == 123:
        tag = sdk_find(s, w, sdk_at(span), K_type)
    elif ch == 91:
        at = whitespace(s, sdk_at(span) + 1)
        tag = (sdk_skip(s, at) << 24) | (at + 1)
    else:
        return 0
    variant = sdk_reference_tag(s, w, tag)
    if variant == 0:
        return 0
    return sdk_struct(s, w, span, 19 + variant, normalized)

def sdk_struct(s:readbuf, w:mutbuf, span:u64, schema:u64, normalized:u64) -> u64:
    if span == 0 or span >> 63 != 0:
        return 0
    ch = sdk_kind(s, span)
    if ch != 123 and ch != 91:
        return 0
    if ch == 91 and schema <= 6:
        return 0
    info = sdk_schema_info(schema)
    count = info & 255
    seen = 0
    index = 0
    at = whitespace(s, sdk_at(span) + 1)
    while byte(s, at) != choose(ch == 123, 125, 93):
        token = 0
        if ch == 123:
            token = sdk_token(s, w, at)
            spec = sdk_field_spec(schema, token)
            at = whitespace(s, sdk_skip(s, at))
            at = whitespace(s, at + 1)
        else:
            if index >= count:
                return 0
            spec = sdk_sequence_spec(schema, index)
        end = sdk_skip(s, at)
        if spec != 0:
            slot = spec >> 32
            mask = 1 << (slot - 1)
            if normalized == 0 and (seen & mask) != 0:
                return 0
            seen = seen | mask
            part = (end << 24) | (at + 1)
            if normalized == 1 and ch == 123:
                part = sdk_find(s, w, sdk_at(span), token) & 9223372036854775807
            if sdk_valid(s, w, part, spec & 4294967295, normalized) == 0:
                return 0
        at = whitespace(s, end)
        if byte(s, at) == 44:
            at = whitespace(s, at + 1)
        index = index + 1
    if ch == 91:
        return choose(index == count, 1, 0)
    required = info >> 8
    return choose((seen & required) == required, 1, 0)

def sdk_later_key(s:readbuf, key:u64, end:u64) -> u64:
    at = whitespace(s, end)
    while byte(s, at) == 44:
        at = whitespace(s, at + 1)
        if sdk_same_key(s, key, at) == 1:
            return 1
        at = whitespace(s, sdk_skip(s, at))
        at = whitespace(s, at + 1)
        at = whitespace(s, sdk_skip(s, at))
    return 0

def sdk_same_key(s:readbuf, left:u64, right:u64) -> u64:
    left = left + 1
    right = right + 1
    while left < length(s) and right < length(s):
        a = decoded(s, left)
        b = decoded(s, right)
        if (a & 4294967295) != (b & 4294967295):
            return 0
        if (a & 4294967295) == 1114112:
            return 1
        left = a >> 32
        right = b >> 32
    return 0

def sdk_token(s:readbuf, w:mutbuf, at:u64) -> u64:
    if at >= length(s) or byte(s, at) != 34:
        return 0
    at = at + 1
    size = 0
    while at < length(s):
        unit = decoded(s, at)
        value = unit & 4294967295
        at = unit >> 32
        if value == 1114112:
            return sdk_tokens(w, size)
        if value >= 128 or size >= 96:
            return 0
        store(w, 22000 + size, value)
        size = size + 1
    return 0

def sdk_word(w:mutbuf, at:u64, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def sdk_id_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if widen(sdk_value(s, w)) != 1:
        return 4294967280
    start = whitespace(s, 0)
    end = sdk_skip(s, start)
    kind = sdk_id(s, w, (end << 24) | (start + 1))
    if kind == 0:
        return 4294967280
    at = 0
    if kind == 1:
        value = get(w, 20144)
        if value >> 63 == 1:
            store(o, at, 45)
            at = at + 1
            value = 0 - value
        digits = 1
        copy = value
        while copy >= 10:
            digits = digits + 1
            copy = sdk_divide_ten(copy)
        end = at + digits
        index = end
        while index > at:
            index = index - 1
            quotient = sdk_divide_ten(value)
            store(o, index, value - quotient * 10 + 48)
            value = quotient
        return end
    store(o, at, 34)
    at = at + 1
    start = start + 1
    while start < length(s):
        unit = decoded(s, start)
        cp = unit & 4294967295
        start = unit >> 32
        if cp == 1114112:
            store(o, at, 34)
            if at >= 8388608:
                return 4294967280
            return at + 1
        at = sdk_id_scalar(o, at, cp)
        if at > 8388608:
            return 4294967280
    return 4294967280

def sdk_id_scalar(o:mutbuf, at:u64, cp:u64) -> u64:
    if cp == 34 or cp == 92:
        store(o, at, 92)
        store(o, at + 1, cp)
        return at + 2
    if cp < 32:
        store(o, at, 92)
        code = 0
        if cp == 8:
            code = 98
        elif cp == 9:
            code = 116
        elif cp == 10:
            code = 110
        elif cp == 12:
            code = 102
        elif cp == 13:
            code = 114
        if code != 0:
            store(o, at + 1, code)
            return at + 2
        store(o, at + 1, 117)
        store(o, at + 2, 48)
        store(o, at + 3, 48)
        store(o, at + 4, (cp >> 4) + 48)
        low = cp & 15
        store(o, at + 5, choose(low < 10, low + 48, low + 87))
        return at + 6
    if cp < 128:
        store(o, at, cp)
        return at + 1
    if cp < 2048:
        store(o, at, 192 | (cp >> 6))
        store(o, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(o, at, 224 | (cp >> 12))
        store(o, at + 1, 128 | ((cp >> 6) & 63))
        store(o, at + 2, 128 | (cp & 63))
        return at + 3
    store(o, at, 240 | (cp >> 18))
    store(o, at + 1, 128 | ((cp >> 12) & 63))
    store(o, at + 2, 128 | ((cp >> 6) & 63))
    store(o, at + 3, 128 | (cp & 63))
    return at + 4

def sdk_divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = remainder * 2 + ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def sdk_finite(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    index = at
    if byte(s, index) == 45:
        index = index + 1
    integer_digits = 0
    leading = 0
    nonzero = 0
    fraction = 0
    going = 1
    while index < end and going == 1:
        ch = byte(s, index)
        if ch == 101 or ch == 69:
            going = 0
        else:
            if ch == 46:
                fraction = 1
            else:
                if fraction == 0:
                    integer_digits = integer_digits + 1
                if nonzero == 0:
                    if ch == 48:
                        leading = leading + 1
                    else:
                        nonzero = 1
            index = index + 1
    if nonzero == 0:
        return 1
    negative = 0
    exponent = 0
    if index < end:
        index = index + 1
        if byte(s, index) == 43 or byte(s, index) == 45:
            negative = choose(byte(s, index) == 45, 1, 0)
            index = index + 1
        while index < end:
            if exponent < 33554432:
                exponent = exponent * 10 + byte(s, index) - 48
                if exponent > 33554432:
                    exponent = 33554432
            index = index + 1
    order = 67108864 + integer_digits - leading - 1
    if negative == 1:
        order = order - exponent
    else:
        order = order + exponent
    if order < 67109172:
        return 1
    return choose(widen(decimal_convert(s, w, at, size)) == 8, 1, 0)
'''


def program():
    public_tools = (*tool_names(), 'request_history', 'request_archive')
    tokens = tuple(dict.fromkeys((*KEYS, *METHODS, *STANDARD, *public_tools, *VERSIONS, '2.0', 'light', 'dark', 'ref/resource', 'ref/prompt')))
    token = {name: i + 1 for i, name in enumerate(tokens)}
    source = SOURCE
    replacements = {**{'K_' + k: token[k] for k in KEYS if '/' not in k},
                    'K_INLINE_VERSION': token['io.modelcontextprotocol/protocolVersion'],
                    'K_INLINE_CAPS': token['io.modelcontextprotocol/clientCapabilities'],
                    'T_VERSION': token['2.0'], 'T_LIGHT': token['light'], 'T_DARK': token['dark'],
                    'T_REFERENCE_RESOURCE': token['ref/resource'], 'T_REFERENCE_PROMPT': token['ref/prompt'],
                    'SDK_MAGIC': int.from_bytes(b'HIASDK01', 'little')}
    import re
    for key, value in sorted(replacements.items(), key=lambda kv: -len(kv[0])):
        source = re.sub(r'\b' + re.escape(key) + r'\b', str(value), source)
    tables = []
    dispatch = ['def sdk_tokens(w:mutbuf, size:u64) -> u64:']
    for bank in range((len(tokens) + 11) // 12):
        dispatch.extend((f'    value = sdk_tokens_{bank}(w, size)', '    if value != 0:', '        return value'))
        lines = [f'def sdk_tokens_{bank}(w:mutbuf, size:u64) -> u64:']
        for value in tokens[bank * 12:(bank + 1) * 12]:
            raw = value.encode('ascii')
            differences = []
            for at in range(0, len(raw), 8):
                part = raw[at:at+8]
                differences.append(f'(sdk_word(w, {22000 + at}, {len(part)}) ^ {int.from_bytes(part, "little")})')
            lines.extend((f'    if size == {len(raw)}:', '        difference = ' + ' | '.join(differences), '        if difference == 0:', f'            return {token[value]}'))
        lines.append('    return 0'); tables.append('\n'.join(lines))
    dispatch.append('    return 0'); tables.append('\n'.join(dispatch))
    for fn, values in [('sdk_role', METHODS), ('sdk_tool', public_tools), ('sdk_version', VERSIONS)]:
        lines = [f'def {fn}(value:u64) -> u64:']
        for index, value in enumerate(values, 1):
            lines.extend((f'    if value == {token[value]}:', f'        return {index}'))
        lines.append('    return 0'); tables.append('\n'.join(lines))
    values = [token[k] for k in (*METHODS, *STANDARD)]
    tables.append('def sdk_standard(value:u64) -> u64:\n    if ' + ' or '.join(f'value == {i}' for i in values) + ':\n        return 1\n    return 0')
    prefix = 'notifications/'
    lines = ['def sdk_notification_prefix(s:readbuf, at:u64) -> u64:', '    at = at + 1']
    for ch in prefix:
        lines.extend(('    unit = decoded(s, at)', f'    if (unit & 4294967295) != {ord(ch)}:', '        return 0', '    at = unit >> 32'))
    lines.append('    return 1'); tables.append('\n'.join(lines))
    info = ['def sdk_schema_info(schema:u64) -> u64:']
    fields = ['def sdk_field_spec(schema:u64, field:u64) -> u64:']
    seq = ['def sdk_sequence_spec(schema:u64, index:u64) -> u64:']
    for schema, items in SCHEMAS.items():
        required = sum(1 << i for i, (_, shape) in enumerate(items) if shape < 1000)
        info.extend((f'    if schema == {schema}:', f'        return {len(items) | (required << 8)}'))
        if not items:
            continue
        for lines in (fields, seq): lines.append(f'    if schema == {schema}:')
        for i, (key, shape) in enumerate(items):
            spec = ((i + 1) << 32) | shape
            fields.extend((f'        if field == {token[key]}:', f'            return {spec}'))
            seq.extend((f'        if index == {i}:', f'            return {spec}'))
    for lines in (info, fields, seq):
        lines.append('    return 0'); tables.append('\n'.join(lines))
    return source + '\n' + '\n\n'.join(tables)


def standalone_program():
    import ast
    from tools.generate_hia_mcp_canonical import source_program
    parsed = ast.parse(source_program() + '\n' + program())
    functions = {f.name: f for f in parsed.body if isinstance(f, ast.FunctionDef)}
    for name, old, new in [('sdk_value', 'length(s) > 8388608', 'length(s) > 16777215'),
                           ('decimal_convert', 'n > 8388608', 'n > 16777215')]:
        text = ast.unparse(functions[name])
        functions[name] = ast.parse(text.replace(old, new)).body[0]
    text = ast.unparse(functions['sdk_value'])
    text = text.replace('widen(decimal_convert(s, w, at, end - at)) != 8', 'sdk_finite(s, w, at, end - at) == 0')
    functions['sdk_value'] = ast.parse(text).body[0]
    selected = {'sdk_message', 'sdk_id_text'}
    previous = set()
    while selected != previous:
        previous = set(selected)
        for name in previous:
            selected.update(n.func.id for n in ast.walk(functions[name])
                            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                            and n.func.id in functions)
    entry = '''def sdk_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 16777215 or length(w) != 32768:
        return 4294967293
    if length(o) == 8389120:
        return sdk_id_text(s, o, w)
    if length(o) != 160:
        return 4294967293
    return sdk_message(s, o, w)
'''
    return entry + '\n\n'.join(ast.unparse(f) for name, f in functions.items() if name in selected)


def render():
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_worker_config_json import document
    return render_assembly(document(standalone_program(), 'mcp_sdk_request'))
