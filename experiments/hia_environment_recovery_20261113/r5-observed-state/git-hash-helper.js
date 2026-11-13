return function(){
/* Raw UTF-8 Git object checks for code-mode transport. No network or mutation. */
function utf8(text) {
  const bytes = [];
  for (const character of text) {
    const n = character.codePointAt(0);
    if (n < 128) bytes.push(n);
    else if (n < 2048) bytes.push(192 | (n >> 6), 128 | (n & 63));
    else if (n < 65536) bytes.push(224 | (n >> 12), 128 | ((n >> 6) & 63), 128 | (n & 63));
    else bytes.push(240 | (n >> 18), 128 | ((n >> 12) & 63), 128 | ((n >> 6) & 63), 128 | (n & 63));
  }
  return bytes;
}
function rawSHA1(input) {
  const bytes = input.slice();
  const bitLength = input.length * 8;
  bytes.push(128);
  while (bytes.length % 64 !== 56) bytes.push(0);
  const high = Math.floor(bitLength / 4294967296), low = bitLength >>> 0;
  for (const word of [high, low]) for (let n = 24; n >= 0; n -= 8) bytes.push((word >>> n) & 255);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const rotate = (n, bits) => ((n << bits) | (n >>> (32 - bits))) >>> 0;
  for (let start = 0; start < bytes.length; start += 64) {
    const words = new Array(80);
    for (let n = 0; n < 16; n++) {
      const i = start + n * 4;
      words[n] = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    }
    for (let n = 16; n < 80; n++) words[n] = rotate(words[n - 3] ^ words[n - 8] ^ words[n - 14] ^ words[n - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let n = 0; n < 80; n++) {
      let f, k;
      if (n < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (n < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (n < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temporary = (rotate(a, 5) + (f >>> 0) + e + k + words[n]) >>> 0;
      e = d; d = c; c = rotate(b, 30); b = a; a = temporary;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  return [h0, h1, h2, h3, h4].map(n => n.toString(16).padStart(8, '0')).join('');
}
function gitBytes(type, bytes) { return rawSHA1(utf8(type + ' ' + bytes.length + '\0').concat(bytes)); }
function gitText(text) { const bytes = utf8(text); return {bytes: bytes.length, sha: gitBytes('blob', bytes)}; }
function treeHash(leaves) {
  const root = {entries: new Map()};
  for (const entry of leaves) {
    let node = root;
    const pieces = entry.path.split('/');
    for (const name of pieces.slice(0, -1)) {
      if (!node.entries.has(name)) node.entries.set(name, {entries: new Map()});
      node = node.entries.get(name);
      if (!node.entries) throw Error('file/directory collision');
    }
    if (node.entries.has(pieces.at(-1))) throw Error('duplicate path');
    node.entries.set(pieces.at(-1), entry);
  }
  function compare(left, right) {
    const a = utf8(left[0] + (left[1].entries ? '/' : ''));
    const b = utf8(right[0] + (right[1].entries ? '/' : ''));
    for (let n = 0; n < Math.min(a.length, b.length); n++) if (a[n] !== b[n]) return a[n] - b[n];
    return a.length - b.length;
  }
  function finish(node) {
    let bytes = [];
    for (const [name, value] of [...node.entries].sort(compare)) {
      const mode = value.entries ? '40000' : value.mode;
      const sha = value.entries ? finish(value) : value.sha;
      if (!/^[0-9a-f]{40}$/.test(sha)) throw Error('invalid raw object id');
      bytes = bytes.concat(utf8(mode + ' ' + name + '\0'));
      for (let n = 0; n < 40; n += 2) bytes.push(parseInt(sha.slice(n, n + 2), 16));
    }
    return gitBytes('tree', bytes);
  }
  return finish(root);
}

return {sha1:a=>rawSHA1(Array.from(a)),object:(kind,a)=>gitBytes(kind,Array.from(a)),tree:leaves=>treeHash(leaves)};
};