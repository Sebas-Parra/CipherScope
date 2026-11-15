import { type Decoder, DecodeError } from "./types.js";

function normalize(s: string): string {
  // Acepta "48656c6c6f", "48 65 6c", "0x48,0x65" …
  return s.replace(/0x/gi, "").replace(/[\s,:;]+/g, "");
}

export const hexDecoder: Decoder = {
  name: "hex",
  label: "Hexadecimal",
  category: "encoding",
  canApply(input: string): boolean {
    const t = normalize(input);
    return t.length >= 2 && t.length % 2 === 0 && /^[0-9a-f]+$/i.test(t);
  },
  decode(input: string): string {
    const t = normalize(input);
    if (t.length % 2 !== 0) throw new DecodeError("hex de longitud impar");
    return Buffer.from(t, "hex").toString("utf8");
  },
};
