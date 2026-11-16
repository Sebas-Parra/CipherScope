import { type HashKind } from "../identify/signatures.js";

/**
 * Una "construcción" es una forma concreta de combinar contraseña y salt que
 * produce el mismo hash de aspecto idéntico. Un SHA-1 de 40 hex puede ser el
 * hash plano, sha1(pass.salt), sha1(salt.pass), o un HMAC-SHA1 — todos se ven
 * igual, pero cada uno exige un modo distinto de hashcat.
 *
 * Cuando el reto entrega el salt por separado (no embebido como en $6$/bcrypt),
 * hay que probar estas construcciones una por una.
 */
export interface Construction {
  /** Descripción legible de la combinación. */
  label: string;
  /** Fórmula compacta, p.ej. "sha1($salt.$pass)". */
  formula: string;
  /** Modo de hashcat (-m). */
  mode: number;
}

/** Plantilla por "velocidad" de familia: plano + 2 salteados + 2 HMAC. */
function build(
  name: string,
  plain: number,
  passSalt: number,
  saltPass: number,
  hmacPass: number,
  hmacSalt: number
): Construction[] {
  return [
    { label: `${name} plano (sin salt)`, formula: `${name.toLowerCase()}($pass)`, mode: plain },
    { label: `${name} + salt al final`, formula: `${name.toLowerCase()}($pass.$salt)`, mode: passSalt },
    { label: `${name} + salt al inicio`, formula: `${name.toLowerCase()}($salt.$pass)`, mode: saltPass },
    { label: `HMAC-${name} (key = contraseña)`, formula: `HMAC-${name}($salt, key=$pass)`, mode: hmacPass },
    { label: `HMAC-${name} (key = salt)`, formula: `HMAC-${name}($pass, key=$salt)`, mode: hmacSalt },
  ];
}

/**
 * Construcciones (con salt/HMAC) a probar para un hash de aspecto ambiguo.
 * Devuelve [] para familias sin variantes estándar (bcrypt, $6$, etc.).
 *
 * Modos de hashcat verificados:
 *  - MD5:    0 plano · 10 pass.salt · 20 salt.pass · 50 HMAC(key=pass) · 60 HMAC(key=salt)
 *  - SHA-1:  100 · 110 · 120 · 150 · 160
 *  - SHA-256:1400 · 1410 · 1420 · 1450 · 1460
 *  - SHA-512:1700 · 1710 · 1720 · 1750 · 1760
 */
export function constructions(kind: HashKind): Construction[] {
  switch (kind) {
    case "md5":
      return build("MD5", 0, 10, 20, 50, 60);
    case "sha1":
      return build("SHA1", 100, 110, 120, 150, 160);
    case "sha256":
      return build("SHA256", 1400, 1410, 1420, 1450, 1460);
    case "sha512":
      return build("SHA512", 1700, 1710, 1720, 1750, 1760);
    default:
      return [];
  }
}
