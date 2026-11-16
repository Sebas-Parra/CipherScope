import { type HashKind } from "./signatures.js";

/**
 * Aviso de formato: el input se *parece* a un hash conocido por su prefijo,
 * pero tiene un problema estructural (longitud o charset del digest) que hará
 * que hashcat/john lo rechacen con "Token length exception".
 *
 * `identify` solo devuelve candidatos cuando una firma calza EXACTAMENTE, así
 * que un hash al que le falta o le sobra un carácter queda sin candidatos. Este
 * diagnóstico cubre justo ese hueco y explica qué revisar.
 */
export interface FormatWarning {
  kind: HashKind;
  label: string;
  /** Longitud esperada del digest. */
  expected: number;
  /** Longitud encontrada. */
  actual: number;
  /** Mensaje accionable para el usuario. */
  message: string;
}

/** Charset válido del digest en hashes crypt/bcrypt (base64 estilo crypt). */
const CRYPT_CHARSET = /^[./A-Za-z0-9]*$/;

/** id de crypt → tipo, etiqueta y longitud exacta del digest. */
const CRYPT: Record<string, { kind: HashKind; label: string; len: number }> = {
  "6": { kind: "sha512crypt", label: "sha512crypt ($6$)", len: 86 },
  "5": { kind: "sha256crypt", label: "sha256crypt ($5$)", len: 43 },
  "1": { kind: "md5crypt", label: "md5crypt ($1$)", len: 22 },
};

function badChar(digest: string): string | undefined {
  for (const ch of digest) {
    if (!CRYPT_CHARSET.test(ch)) return ch;
  }
  return undefined;
}

/**
 * Revisa si el input parece un hash crypt/bcrypt malformado y, si es así,
 * devuelve un aviso explicando el problema. Devuelve `undefined` cuando el
 * input no tiene pinta de crypt/bcrypt o cuando está bien formado.
 */
export function diagnose(raw: string): FormatWarning | undefined {
  const s = raw.trim();

  // --- Familias crypt: $id$[rounds=N$]salt$digest ---
  const crypt = /^\$([651])\$/.exec(s);
  if (crypt) {
    const spec = CRYPT[crypt[1]!]!;
    const parts = s.split("$"); // ["", id, (rounds=?,) salt, digest]
    // Necesitamos al menos id + salt + digest para evaluar el digest.
    if (parts.length >= 4) {
      const digest = parts[parts.length - 1] ?? "";

      const bad = badChar(digest);
      if (bad) {
        return {
          kind: spec.kind,
          label: spec.label,
          expected: spec.len,
          actual: digest.length,
          message: `Parece ${spec.label} pero el digest contiene un carácter inválido (${JSON.stringify(
            bad
          )}). Solo se permiten letras, dígitos, "." y "/". Revisa que no se haya colado puntuación o un espacio al copiarlo.`,
        };
      }

      if (digest.length !== spec.len) {
        const diff = spec.len - digest.length;
        return {
          kind: spec.kind,
          label: spec.label,
          expected: spec.len,
          actual: digest.length,
          message:
            diff > 0
              ? `Parece ${spec.label} pero el digest tiene ${digest.length} caracteres (faltan ${diff}). Debe tener ${spec.len}. Seguramente se perdió o se cortó algún carácter al copiarlo — vuelve a copiarlo completo desde el origen.`
              : `Parece ${spec.label} pero el digest tiene ${digest.length} caracteres (sobran ${-diff}). Debe tener ${spec.len}. Revisa que no haya caracteres de más al final (un punto de puntuación, un espacio, un salto de línea).`,
        };
      }
    }
    return undefined;
  }

  // --- bcrypt: $2[abxy]$NN$<22 salt + 31 hash = 53> ---
  const bcrypt = /^\$2[abxy]\$\d{2}\$(.*)$/.exec(s);
  if (bcrypt) {
    const body = bcrypt[1] ?? "";
    const bad = badChar(body);
    if (bad) {
      return {
        kind: "bcrypt",
        label: "bcrypt",
        expected: 53,
        actual: body.length,
        message: `Parece bcrypt pero contiene un carácter inválido (${JSON.stringify(
          bad
        )}) tras el coste. Solo letras, dígitos, "." y "/".`,
      };
    }
    if (body.length !== 53) {
      const diff = 53 - body.length;
      return {
        kind: "bcrypt",
        label: "bcrypt",
        expected: 53,
        actual: body.length,
        message:
          diff > 0
            ? `Parece bcrypt pero tras el coste hay ${body.length} caracteres (faltan ${diff}). Deben ser 53 (22 de salt + 31 de hash). Vuelve a copiar el hash completo.`
            : `Parece bcrypt pero tras el coste hay ${body.length} caracteres (sobran ${-diff}). Deben ser 53 (22 de salt + 31 de hash). Revisa caracteres de más al final.`,
      };
    }
  }

  return undefined;
}
