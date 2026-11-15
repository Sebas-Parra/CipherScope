import type { HashKind } from "../identify/signatures.js";
import { HASHERS, type SaltMode } from "./hashers.js";
import { VERIFIERS } from "./verifiers.js";

export interface CrackOptions {
  kind: HashKind;
  /** Salt conocido (para hashes crudos salteados). */
  salt?: string;
  /** Posición del salt. Si hay salt y no se indica, se prueban prefix y suffix. */
  saltMode?: SaltMode;
  /** Límite de intentos (0 = sin límite). */
  maxAttempts?: number;
}

export interface CrackResult {
  found: boolean;
  password?: string;
  /** Modo de salt con el que acertó. */
  saltMode?: SaltMode;
  attempts: number;
}

/**
 * Crackea un hash por diccionario: hashea cada candidato y compara.
 * Es puro: recibe un iterable de contraseñas (la CLI lee el archivo).
 */
export function crack(
  targetHash: string,
  candidates: Iterable<string>,
  opts: CrackOptions
): CrackResult {
  const verifier = VERIFIERS[opts.kind];
  const hasher = HASHERS[opts.kind];
  if (!verifier && !hasher) {
    throw new Error(`Tipo no crackeable localmente: ${opts.kind}`);
  }

  const maxAttempts = opts.maxAttempts ?? 0;

  // Camino 1: hashes con salt embebido (bcrypt…) → se verifican con compare,
  // sin salt externo ni modos.
  if (verifier) {
    let attempts = 0;
    for (const candidate of candidates) {
      attempts++;
      if (verifier(candidate, targetHash)) {
        return { found: true, password: candidate, attempts };
      }
      if (maxAttempts && attempts >= maxAttempts) {
        return { found: false, attempts };
      }
    }
    return { found: false, attempts };
  }

  // Camino 2: hashes "crudos" → hashear candidato y comparar.
  const hash = hasher!;
  const target = normalize(opts.kind, targetHash);

  // Qué modos de salt probar.
  let modes: { salt?: string; saltMode: SaltMode }[];
  if (!opts.salt) {
    modes = [{ saltMode: "none" }];
  } else if (opts.saltMode) {
    modes = [{ salt: opts.salt, saltMode: opts.saltMode }];
  } else {
    modes = [
      { salt: opts.salt, saltMode: "suffix" },
      { salt: opts.salt, saltMode: "prefix" },
    ];
  }

  let attempts = 0;
  for (const candidate of candidates) {
    for (const m of modes) {
      const digest = normalize(opts.kind, hash(candidate, m));
      attempts++;
      if (digest === target) {
        return { found: true, password: candidate, saltMode: m.saltMode, attempts };
      }
      if (maxAttempts && attempts >= maxAttempts) {
        return { found: false, attempts };
      }
    }
  }
  return { found: false, attempts };
}

/** MySQL41 lleva '*' y mayúsculas; el resto se compara en hex minúsculas. */
function normalize(kind: HashKind, h: string): string {
  if (kind === "mysql41") return h.toUpperCase();
  return h.toLowerCase();
}

/** ¿Podemos crackear este tipo en local (por hasher o por verificador)? */
export function isCrackable(kind: HashKind): boolean {
  return kind in HASHERS || kind in VERIFIERS;
}
