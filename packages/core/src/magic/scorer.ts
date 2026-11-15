/**
 * Puntúa qué tan "legible" es un texto [0-1]. Combina varias señales:
 *  - ratio de caracteres imprimibles / ASCII
 *  - cercanía a la frecuencia de letras del inglés/español
 *  - coincidencia con un diccionario de palabras comunes
 *  - presencia de patrones típicos de flag CTF (flag{...})
 */

const COMMON_WORDS = new Set([
  // inglés
  "the", "and", "you", "that", "for", "with", "this", "flag", "ctf",
  "secret", "password", "hello", "world", "key", "message", "congrats",
  "admin", "user", "login", "token", "access", "granted", "welcome",
  // español
  "que", "los", "las", "con", "por", "para", "una", "clave", "hola",
  "mundo", "secreto", "mensaje", "contrasena", "bandera",
]);

// Frecuencia de letras en inglés (fracción). Suma ~1.
const ENGLISH_FREQ: Record<string, number> = {
  a: 0.082, b: 0.015, c: 0.028, d: 0.043, e: 0.127, f: 0.022, g: 0.02,
  h: 0.061, i: 0.07, j: 0.0015, k: 0.0077, l: 0.04, m: 0.024, n: 0.067,
  o: 0.075, p: 0.019, q: 0.00095, r: 0.06, s: 0.063, t: 0.091, u: 0.028,
  v: 0.0098, w: 0.024, x: 0.0015, y: 0.02, z: 0.00074,
};

function printableRatio(s: string): number {
  if (s.length === 0) return 0;
  let printable = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
  }
  return printable / s.length;
}

/** Distancia a la frecuencia del inglés → similitud [0-1]. */
function freqScore(s: string): number {
  const letters = s.toLowerCase().replace(/[^a-z]/g, "");
  if (letters.length < 4) return 0.3; // poco texto: neutral-bajo
  const counts: Record<string, number> = {};
  for (const ch of letters) counts[ch] = (counts[ch] ?? 0) + 1;
  let chi = 0;
  for (let i = 0; i < 26; i++) {
    const ch = String.fromCharCode(97 + i);
    const expected = (ENGLISH_FREQ[ch] ?? 0) * letters.length;
    const observed = counts[ch] ?? 0;
    if (expected > 0) chi += (observed - expected) ** 2 / expected;
  }
  // chi normalizado: valores bajos = más parecido a inglés.
  return 1 / (1 + chi / letters.length);
}

function wordScore(s: string): number {
  const words = s.toLowerCase().match(/[a-z]{2,}/g);
  if (!words || words.length === 0) return 0;
  const hits = words.filter((w) => COMMON_WORDS.has(w)).length;
  return Math.min(1, hits / words.length + hits * 0.15);
}

export interface Score {
  total: number;
  printable: number;
  freq: number;
  words: number;
  flag: boolean;
}

/** Calcula el score de legibilidad de un texto. */
export function score(s: string): Score {
  const printable = printableRatio(s);
  const freq = freqScore(s);
  const words = wordScore(s);
  const flag = /\b(flag|ctf|key|htb|picoCTF)\{[^}]*\}/i.test(s);

  // Si no es imprimible, nada más importa.
  let total = printable < 0.85 ? printable * 0.5 : 0.3 * printable + 0.3 * freq + 0.4 * words;
  if (flag) total = Math.max(total, 0.95);

  return { total: Math.min(1, total), printable, freq, words, flag };
}
