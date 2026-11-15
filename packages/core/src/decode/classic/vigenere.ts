import { DecodeError } from "../types.js";

/** Descifra Vigenère con la llave dada (solo letras A-Z/a-z en la llave). */
export function vigenereDecode(text: string, key: string): string {
  const k = key.replace(/[^a-z]/gi, "").toLowerCase();
  if (k.length === 0) throw new DecodeError("llave Vigenère vacía");
  let ki = 0;
  return text.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 97;
    ki++;
    return String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base);
  });
}

/** Cifra Vigenère (útil para tests y para la web). */
export function vigenereEncode(text: string, key: string): string {
  const k = key.replace(/[^a-z]/gi, "").toLowerCase();
  if (k.length === 0) throw new DecodeError("llave Vigenère vacía");
  let ki = 0;
  return text.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 97;
    ki++;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}
