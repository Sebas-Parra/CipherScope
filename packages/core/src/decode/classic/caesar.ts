import { type Decoder } from "../types.js";

/** Desplaza letras `shift` posiciones (0-25), preservando mayúsc/minúsc y no-letras. */
export function caesarShift(text: string, shift: number): string {
  const s = ((shift % 26) + 26) % 26;
  return text.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + s) % 26) + base);
  });
}

/** Devuelve los 25 desplazamientos posibles (shift 1..25). */
export function caesarBruteForce(text: string): { shift: number; text: string }[] {
  const out: { shift: number; text: string }[] = [];
  for (let shift = 1; shift < 26; shift++) {
    out.push({ shift, text: caesarShift(text, shift) });
  }
  return out;
}

const isAlpha = (s: string) => /[a-z]/i.test(s);

/** ROT13: César con shift fijo 13 (su propio inverso). */
export const rot13Decoder: Decoder = {
  name: "rot13",
  label: "ROT13 (César shift 13)",
  category: "classic",
  canApply: isAlpha,
  decode: (input) => caesarShift(input, 13),
};
