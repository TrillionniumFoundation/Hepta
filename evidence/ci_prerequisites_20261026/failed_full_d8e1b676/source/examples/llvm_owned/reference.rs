// Independent handwritten Rust baseline. The resource implementation uses
// safe Vec/slice operations; no Hepta-generated Rust is included here.
struct OwnedBytes { data: Vec<u8> }

fn try_bytes(size: usize) -> Result<Vec<u8>, u8> {
    let mut data = Vec::new();
    data.try_reserve_exact(size).map_err(|_| 1u8)?;
    data.resize(size, 0);
    Ok(data)
}

impl OwnedBytes {
    fn new(size: usize, reject: bool) -> Result<Self, u8> {
        let data = try_bytes(size)?;
        if reject { drop(data); Err(2) } else { Ok(Self { data }) }
    }
    fn view(&self) -> &[u8] { &self.data }
}

fn forward<T>(value: T) -> T { value }

#[no_mangle]
pub extern "C" fn full_lifecycle(size: usize, seed: u32) -> u64 {
    let mut owner = match OwnedBytes::new(size, false) {
        Err(code) => return 1000 + u64::from(code), Ok(value) => value,
    };
    for (index, byte) in owner.data.iter_mut().enumerate() {
        *byte = (index as u32).wrapping_add(seed) as u8;
    }
    let moved = forward(owner);
    let checksum = moved.view().iter().map(|&byte| u64::from(byte)).sum();
    drop(moved);
    checksum
}

#[no_mangle]
pub extern "C" fn constructor_error(size: usize, seed: u32) -> u64 {
    match OwnedBytes::new(size, true) {
        Err(code) => 1000 + u64::from(code) + u64::from(seed),
        Ok(unexpected) => { drop(unexpected); 9000 },
    }
}

#[no_mangle]
pub extern "C" fn two_stage(size: usize, seed: u32) -> u64 {
    let mut first = match OwnedBytes::new(size, false) {
        Err(code) => return 1000 + u64::from(code), Ok(value) => value,
    };
    first.data.fill(seed as u8);
    let mut second = match try_bytes(size + 17) {
        Err(code) => { drop(first); return 1000 + u64::from(code); },
        Ok(value) => value,
    };
    for (destination, &source) in second.iter_mut().zip(first.view()) {
        *destination = source ^ 90;
    }
    let checksum = second.iter().map(|&byte| u64::from(byte)).sum();
    drop(second);
    drop(first);
    checksum
}

#[no_mangle]
pub extern "C" fn two_alloc(second: usize, refuse: u32) -> u64 {
    let mut first = match try_bytes(7) {
        Err(code) => return 100 + u64::from(code), Ok(value) => value,
    };
    first[0] = 19;
    let moved = match try_bytes(second) {
        Err(code) => { drop(first); return u64::from(code); }, Ok(value) => forward(value),
    };
    if refuse != 0 { drop(moved); drop(first); return 2; }
    let result = moved.len() as u64 + u64::from(first[0]);
    drop(moved);
    drop(first);
    result
}
