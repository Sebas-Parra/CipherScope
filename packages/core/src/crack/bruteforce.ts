/**
 * Fuerza bruta / máscara: genera candidatos por sí mismo, sin wordlist.
 * Produce todas las combinaciones de un charset hasta `maxLen` caracteres.
 *
 * Solo es viable para contraseñas CORTAS y hashes rápidos: el espacio crece
 * exponencialmente (charset^longitud). Para bcrypt/argon2 es inútil.
 */

export const CHARSETS: Record<string, string> = {
  digits: "0123456789",
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "lower+digits": "abcdefghijklmnopqrstuvwxyz0123456789",
  alnum: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "alnum+symbols":
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+",
};

/** Resuelve un nombre de charset preset, o usa la cadena literal como charset. */
export function resolveCharset(nameOrChars: string): string {
  return CHARSETS[nameOrChars] ?? nameOrChars;
}

/** Nº total de combinaciones de `charset` hasta `maxLen` (para estimar tiempo). */
export function keyspace(charsetSize: number, maxLen: number): number {
  let total = 0;
  for (let len = 1; len <= maxLen; len++) total += charsetSize ** len;
  return total;
}

/**
 * Genera candidatos de longitud 1..maxLen sobre `charset` (orden incremental).
 * Es un generador perezoso: el motor `crack` consume lo que necesita y para.
 */
export function* generateCandidates(charset: string, maxLen: number): Generator<string> {
  const chars = [...charset];
  if (chars.length === 0 || maxLen < 1) return;

  for (let len = 1; len <= maxLen; len++) {
    const idx = new Array(len).fill(0);
    while (true) {
      yield idx.map((i) => chars[i]).join("");
      // incrementa como un contador en base chars.length
      let p = len - 1;
      while (p >= 0) {
        idx[p]++;
        if (idx[p] < chars.length) break;
        idx[p] = 0;
        p--;
      }
      if (p < 0) break;
    }
  }
}
