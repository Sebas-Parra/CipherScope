import { type Decoder, DecodeError } from "./types.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B32 = /^[A-Z2-7]+=*$/;

function normalize(s: string): string {
  return s.replace(/\s+/g, "").toUpperCase();
}

export const base32Decoder: Decoder = {
  name: "base32",
  label: "Base32 (RFC 4648)",
  category: "encoding",
  canApply(input: string): boolean {
    const t = normalize(input);
    return t.length >= 8 && t.length % 8 === 0 && B32.test(t);
  },
  decode(input: string): string {
    const t = normalize(input).replace(/=+$/, "");
    let bits = 0;
    let value = 0;
    const out: number[] = [];
    for (const ch of t) {
      const idx = ALPHABET.indexOf(ch);
      if (idx === -1) throw new DecodeError(`char base32 inválido: ${ch}`);
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push((value >>> bits) & 0xff);
      }
    }
    return Buffer.from(out).toString("utf8");
  },
};
