import { type Decoder } from "../types.js";

/** Atbash: A↔Z, B↔Y… Es su propio inverso. */
export function atbash(text: string): string {
  return text.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(base + (25 - (ch.charCodeAt(0) - base)));
  });
}

export const atbashDecoder: Decoder = {
  name: "atbash",
  label: "Atbash",
  category: "classic",
  canApply: (s) => /[a-z]/i.test(s),
  decode: atbash,
};
