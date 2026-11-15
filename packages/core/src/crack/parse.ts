import { identify } from "../identify/identify.js";

export interface ParsedTarget {
  /** Usuario, si venía en formato user:hash. */
  user?: string;
  /** El hash en sí. */
  hash: string;
  /** Salt, si venía en formato hash:salt. */
  salt?: string;
  raw: string;
}

const looksHash = (s: string) => identify(s).candidates.length > 0;

/**
 * Interpreta una línea que puede ser "hash", "user:hash" o "hash:salt".
 * Heurística: si el primer campo parece hash → "hash:salt"; si el segundo
 * parece hash → "user:hash"; si ambos/ninguno, se asume "hash:salt".
 */
export function parseTarget(line: string): ParsedTarget {
  const raw = line.trim();
  const idx = raw.indexOf(":");
  if (idx === -1) return { hash: raw, raw };

  const left = raw.slice(0, idx);
  const right = raw.slice(idx + 1);

  const leftIsHash = looksHash(left);
  const rightIsHash = looksHash(right);

  if (!leftIsHash && rightIsHash) {
    return { user: left, hash: right, raw };
  }
  // left es hash (o ambos): tratamos el resto como salt.
  return { hash: left, salt: right, raw };
}
