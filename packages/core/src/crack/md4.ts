/**
 * MD4 puro en JS. OpenSSL moderno deshabilita MD4, pero NTLM lo necesita
 * (NTLM = MD4(UTF-16LE(password))). Implementación compacta sobre bytes.
 */
function rotl(x: number, n: number): number {
  return (x << n) | (x >>> (32 - n));
}

export function md4(bytes: Uint8Array): Buffer {
  const msgLen = bytes.length;
  const bitLen = msgLen * 8;
  // padding: 0x80, luego ceros hasta ≡ 56 mod 64, luego longitud en 64 bits LE.
  const withOne = msgLen + 1;
  const padded = (Math.ceil((withOne + 8) / 64)) * 64;
  const buf = new Uint8Array(padded);
  buf.set(bytes);
  buf[msgLen] = 0x80;
  // longitud (64 bits little-endian); asumimos < 2^32 bits.
  buf[padded - 8] = bitLen & 0xff;
  buf[padded - 7] = (bitLen >>> 8) & 0xff;
  buf[padded - 6] = (bitLen >>> 16) & 0xff;
  buf[padded - 5] = (bitLen >>> 24) & 0xff;

  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  const x = new Int32Array(16);
  for (let off = 0; off < padded; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      x[i] =
        (buf[j]! & 0xff) |
        ((buf[j + 1]! & 0xff) << 8) |
        ((buf[j + 2]! & 0xff) << 16) |
        ((buf[j + 3]! & 0xff) << 24);
    }
    const aa = a, bb = b, cc = c, dd = d;

    const F = (x: number, y: number, z: number) => (x & y) | (~x & z);
    const G = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
    const H = (x: number, y: number, z: number) => x ^ y ^ z;

    // Ronda 1
    const r1 = [3, 7, 11, 19];
    for (let i = 0; i < 16; i++) {
      const k = i;
      const s = r1[i % 4]!;
      const sum = (a + F(b, c, d) + x[k]!) | 0;
      a = d; d = c; c = b; b = rotl(sum, s);
    }
    // Ronda 2
    const r2 = [3, 5, 9, 13];
    const o2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    for (let i = 0; i < 16; i++) {
      const k = o2[i]!;
      const s = r2[i % 4]!;
      const sum = (a + G(b, c, d) + x[k]! + 0x5a827999) | 0;
      a = d; d = c; c = b; b = rotl(sum, s);
    }
    // Ronda 3
    const r3 = [3, 9, 11, 15];
    const o3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let i = 0; i < 16; i++) {
      const k = o3[i]!;
      const s = r3[i % 4]!;
      const sum = (a + H(b, c, d) + x[k]! + 0x6ed9eba1) | 0;
      a = d; d = c; c = b; b = rotl(sum, s);
    }

    a = (a + aa) | 0;
    b = (b + bb) | 0;
    c = (c + cc) | 0;
    d = (d + dd) | 0;
  }

  const out = Buffer.alloc(16);
  out.writeInt32LE(a, 0);
  out.writeInt32LE(b, 4);
  out.writeInt32LE(c, 8);
  out.writeInt32LE(d, 12);
  return out;
}
