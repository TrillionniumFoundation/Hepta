function fixedGzip(raw, crc32) {
  if (!(raw instanceof Uint8Array) || raw.length > 4 * 1024 * 1024) {
    throw Error("bounded UTF-8 overlay bytes required");
  }
  const output = new Uint8Array(raw.length * 2 + 64);
  let used = 10, accumulator = 0, available = 0;
  output.set([31, 139, 8, 0, 0, 0, 0, 0, 0, 255]);
  function bits(value, count) {
    accumulator |= value << available;
    available += count;
    while (available >= 8) {
      output[used++] = accumulator & 255;
      accumulator >>>= 8;
      available -= 8;
    }
  }
  function reverse(value, count) {
    let result = 0;
    for (let i = 0; i < count; i++) {
      result = (result << 1) | (value & 1);
      value >>>= 1;
    }
    return result;
  }
  const literalCodes = new Uint16Array(288);
  const literalBits = new Uint8Array(288);
  for (let value = 0; value < 288; value++) {
    let code, count;
    if (value < 144) { code = 48 + value; count = 8; }
    else if (value < 256) { code = 400 + value - 144; count = 9; }
    else if (value < 280) { code = value - 256; count = 7; }
    else { code = 192 + value - 280; count = 8; }
    literalCodes[value] = reverse(code, count);
    literalBits[value] = count;
  }
  function symbol(value) { bits(literalCodes[value], literalBits[value]); }
  const lengthBase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
  const lengthExtra = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
  const distanceBase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
  const distanceExtra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
  const heads = new Uint32Array(65536), previous = new Uint32Array(raw.length);
  function hash(at) {
    return ((raw[at] * 251 + raw[at + 1]) * 251 + raw[at + 2]) & 65535;
  }
  function remember(at) {
    if (at + 2 >= raw.length) return;
    const key = hash(at);
    previous[at] = heads[key];
    heads[key] = at + 1;
  }
  // One final fixed-Huffman DEFLATE block. This is a transport writer only.
  bits(3, 3);
  let at = 0;
  while (at < raw.length) {
    let best = 0, distance = 0;
    if (at + 2 < raw.length) {
      let cursor = heads[hash(at)], tried = 0;
      const limit = Math.min(258, raw.length - at);
      while (cursor && tried++ < 64) {
        const candidate = cursor - 1;
        if (at - candidate > 32768) break;
        if (raw[candidate] === raw[at]
            && raw[candidate + best] === raw[at + best]) {
          let length = 0;
          while (length < limit && raw[candidate + length] === raw[at + length]) length++;
          if (length >= 3 && length > best) {
            best = length;
            distance = at - candidate;
            if (length === limit) break;
          }
        }
        cursor = previous[candidate];
      }
    }
    if (best >= 3) {
      let lengthCode = 0, distanceCode = 0;
      while (lengthCode + 1 < lengthBase.length && best >= lengthBase[lengthCode + 1]) lengthCode++;
      while (distanceCode + 1 < distanceBase.length && distance >= distanceBase[distanceCode + 1]) distanceCode++;
      symbol(257 + lengthCode);
      bits(best - lengthBase[lengthCode], lengthExtra[lengthCode]);
      bits(reverse(distanceCode, 5), 5);
      bits(distance - distanceBase[distanceCode], distanceExtra[distanceCode]);
      for (let i = 0; i < best; i++) remember(at + i);
      at += best;
    } else {
      symbol(raw[at]);
      remember(at++);
    }
  }
  symbol(256);
  if (available) output[used++] = accumulator & 255;
  const crc = crc32(raw), size = raw.length >>> 0;
  for (const value of [crc, size]) {
    for (let i = 0; i < 4; i++) output[used++] = (value >>> (8 * i)) & 255;
  }
  return output.slice(0, used);
}
return {fixedGzip};
