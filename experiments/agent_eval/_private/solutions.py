"""Trusted oracle bodies for harness qualification, never AI outputs."""

HEPTA = {
    'compact_runs': '''{
    unsafe {
        let mut previous: u32 = 0;
        let mut required: usize = 0;
        for i in 0..n {
            let value = load(input, i);
            if i == 0 || value != previous {
                if required < capacity { store(output, required, value); }
                required = wrapping_add(required, 1);
            }
            previous = value;
        }
        return required;
    }
}''',
    'rolling_sum': '''{
    if window == 0 || window > n { return 0; }
    unsafe {
        let required = n - window + 1;
        let mut sum: i64 = 0;
        for i in 0..window { sum = wrapping_add(sum, load(input, i)); }
        for i in 0..required {
            if i < capacity { store(output, i, sum); }
            if i + window < n {
                sum = wrapping_sub(sum, load(input, i));
                sum = wrapping_add(sum, load(input, i + window));
            }
        }
        return required;
    }
}''',
    'lower_bound': '''{
    let mut lower: usize = 0;
    let mut upper = n;
    unsafe {
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            if load(input, middle) < key { lower = middle + 1; }
            else { upper = middle; }
        }
    }
    return lower;
}''',
    'parse_decimal': '''{
    let maximum: u64 = 18446744073709551615;
    let mut index: usize = 0;
    let mut value: u64 = 0;
    let mut previous_digit = false;
    unsafe {
        if n > 0 { if load(input, 0) == 43 { index = 1; } }
        if index == n { return ParseResult { value: 0, consumed: index, status: 1 }; }
        while index < n {
            let byte = load(input, index);
            if byte == 95 {
                if !previous_digit || index + 1 >= n {
                    return ParseResult { value: 0, consumed: index, status: 1 };
                }
                let next = load(input, index + 1);
                if next < 48 || next > 57 {
                    return ParseResult { value: 0, consumed: index, status: 1 };
                }
                previous_digit = false;
            } else {
                if byte < 48 || byte > 57 {
                    return ParseResult { value: 0, consumed: index, status: 1 };
                }
                let digit = (byte as u64) - 48;
                if value > (maximum - digit) / 10 {
                    return ParseResult { value: 0, consumed: index, status: 2 };
                }
                value = value * 10 + digit;
                previous_digit = true;
            }
            index = index + 1;
        }
    }
    return ParseResult { value: value, consumed: n, status: 0 };
}''',
}

RUST = {
    'compact_runs': '''{
    let mut previous = 0u32;
    let mut required = 0usize;
    for i in 0..n {
        let value = *input.add(i);
        if i == 0 || value != previous {
            if required < capacity { *output.add(required) = value; }
            required += 1;
        }
        previous = value;
    }
    required
}''',
    'rolling_sum': '''{
    if window == 0 || window > n { return 0; }
    let required = n - window + 1;
    let mut sum = 0i64;
    for i in 0..window { sum = sum.wrapping_add(*input.add(i)); }
    for i in 0..required {
        if i < capacity { *output.add(i) = sum; }
        if i + window < n {
            sum = sum.wrapping_sub(*input.add(i));
            sum = sum.wrapping_add(*input.add(i + window));
        }
    }
    required
}''',
    'lower_bound': '''{
    let mut lower = 0usize;
    let mut upper = n;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if *input.add(middle) < key { lower = middle + 1; }
        else { upper = middle; }
    }
    lower
}''',
    'parse_decimal': '''{
    let mut index = if n > 0 && *input == b'+' { 1 } else { 0 };
    let mut value = 0u64;
    let mut previous_digit = false;
    if index == n { return ParseResult { value: 0, consumed: index, status: 1 }; }
    while index < n {
        let byte = *input.add(index);
        if byte == b'_' {
            if !previous_digit || index + 1 >= n || !(*input.add(index + 1)).is_ascii_digit() {
                return ParseResult { value: 0, consumed: index, status: 1 };
            }
            previous_digit = false;
        } else {
            if !byte.is_ascii_digit() { return ParseResult { value: 0, consumed: index, status: 1 }; }
            let digit = (byte - b'0') as u64;
            if value > (u64::MAX - digit) / 10 { return ParseResult { value: 0, consumed: index, status: 2 }; }
            value = value * 10 + digit;
            previous_digit = true;
        }
        index += 1;
    }
    ParseResult { value, consumed: n, status: 0 }
}''',
}
