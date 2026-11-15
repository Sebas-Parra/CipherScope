import bcrypt from "bcryptjs";
import type { HashKind } from "../identify/signatures.js";

/**
 * Verificadores para hashes con salt embebido: no se "recalculan" a partir
 * de la contraseña (el salt vive dentro del hash), se comprueban con compare.
 * Son LENTOS por diseño → solo aptos para wordlists pequeñas.
 */
export type Verifier = (password: string, targetHash: string) => boolean;

export const VERIFIERS: Partial<Record<HashKind, Verifier>> = {
  bcrypt: (password, targetHash) => {
    try {
      return bcrypt.compareSync(password, targetHash);
    } catch {
      return false;
    }
  },
};

export function hasVerifier(kind: HashKind): boolean {
  return kind in VERIFIERS;
}

/** ¿Es un hash lento (salt/iteraciones)? Útil para avisar y limitar intentos. */
export function isSlowHash(kind: HashKind): boolean {
  return hasVerifier(kind);
}
