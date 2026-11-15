import { type Decoder } from "./types.js";
import { base64Decoder } from "./base64.js";
import { base32Decoder } from "./base32.js";
import { hexDecoder } from "./hex.js";
import { urlDecoder } from "./url.js";
import { binaryDecoder } from "./binary.js";
import { morseDecoder } from "./morse.js";
import { rot13Decoder } from "./classic/caesar.js";
import { atbashDecoder } from "./classic/atbash.js";

/**
 * Decoders sin parámetros, aptos para el encadenado automático del motor
 * Magic. César genérico (25 shifts) y Vigenère (requiere llave) viven
 * como funciones aparte: no son deterministas de una sola forma.
 */
export const REGISTRY: Decoder[] = [
  base64Decoder,
  base32Decoder,
  hexDecoder,
  urlDecoder,
  binaryDecoder,
  morseDecoder,
  rot13Decoder,
  atbashDecoder,
];

export function getDecoder(name: string): Decoder | undefined {
  return REGISTRY.find((d) => d.name === name);
}

/** Aplica todos los decoders aplicables a una entrada; descarta los que lanzan. */
export function decodeAll(input: string): { decoder: string; output: string }[] {
  const results: { decoder: string; output: string }[] = [];
  for (const d of REGISTRY) {
    if (!d.canApply(input)) continue;
    try {
      const output = d.decode(input);
      if (output && output !== input) results.push({ decoder: d.name, output });
    } catch {
      /* no aplicable realmente */
    }
  }
  return results;
}
