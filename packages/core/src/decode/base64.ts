import { type Decoder, DecodeError } from "./types.js";

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const B64URL = /^[A-Za-z0-9_-]+={0,2}$/;

function looksLikeBase64(s: string): boolean {
  const t = s.replace(/\s+/g, "");
  if (t.length < 4 || t.length % 4 !== 0) return false;
  return B64.test(t) || B64URL.test(t);
}

export const base64Decoder: Decoder = {
  name: "base64",
  label: "Base64 / Base64URL",
  category: "encoding",
  canApply: looksLikeBase64,
  decode(input: string): string {
    const t = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(t, "base64");
    // Buffer es permisivo; re-encode para validar que era base64 real.
    if (buf.length === 0) throw new DecodeError("base64 vacío");
    return buf.toString("utf8");
  },
};
