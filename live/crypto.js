// SHA-256 and HMAC-SHA256 over bytes, synchronous, plus the canonical JSON
// that tracekit hashes: json.dumps(obj, sort_keys=True, separators=(",", ":"))
// with Python's default ASCII escaping, so a ledger written here verifies in Python.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
const enc = new TextEncoder();
export const utf8 = (s) => enc.encode(s);

export function sha256(bytes) {
  const len = bytes.length, blocks = (len + 9 + 63) >> 6;
  const buf = new Uint8Array(blocks * 64);
  buf.set(bytes);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer), bits = len * 8;
  dv.setUint32(buf.length - 4, bits >>> 0);
  dv.setUint32(buf.length - 8, Math.floor(bits / 2 ** 32));
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  const r = (x, n) => (x >>> n) | (x << (32 - n));
  for (let b = 0; b < blocks; b++) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(b * 64 + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = r(w[i - 15], 7) ^ r(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = r(w[i - 2], 17) ^ r(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, bb, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = bb; bb = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += bb; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
  return out;
}
export const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
export const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
export const sha256Hex = (bytes) => hex(sha256(bytes));

export function hmacHex(key, data) {
  let k = key.length > 64 ? sha256(key) : key;
  const kb = new Uint8Array(64);
  kb.set(k);
  const ipad = kb.map((b) => b ^ 0x36), opad = kb.map((b) => b ^ 0x5c);
  const inner = new Uint8Array(64 + data.length);
  inner.set(ipad); inner.set(data, 64);
  const ih = sha256(inner);
  const outer = new Uint8Array(96);
  outer.set(opad); outer.set(ih, 64);
  return hex(sha256(outer));
}

function pyString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c >= 0x20 && c <= 0x7e) out += ch;
    else if (c > 0xffff) {
      const v = c - 0x10000;
      out += `\\u${(0xd800 + (v >> 10)).toString(16).padStart(4, '0')}\\u${(0xdc00 + (v & 0x3ff)).toString(16).padStart(4, '0')}`;
    } else out += `\\u${c.toString(16).padStart(4, '0')}`;
  }
  return out + '"';
}
export function canonical(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') { if (!Number.isInteger(v)) throw new Error('canonical(): only integers are used in ledgers'); return String(v); }
  if (typeof v === 'string') return pyString(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${keys.map((k) => `${pyString(k)}:${canonical(v[k])}`).join(',')}}`;
}
