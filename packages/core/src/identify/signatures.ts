/**
 * Tabla de firmas: cada entrada describe cómo reconocer un tipo de hash
 * o codificación por su forma (longitud, charset, prefijo).
 *
 * `score` base (0-1) refleja qué tan distintiva es la firma; `identify`
 * lo ajusta con señales adicionales. Un patrón muy genérico (p.ej. "32 hex"
 * encaja con MD5, NTLM, MD4…) tiene score moderado y varios candidatos.
 */

export type HashKind =
  | "md5"
  | "ntlm"
  | "md4"
  | "sha1"
  | "sha224"
  | "sha256"
  | "sha384"
  | "sha512"
  | "sha3-256"
  | "ripemd160"
  | "crc32"
  | "mysql323"
  | "mysql41"
  | "bcrypt"
  | "sha256crypt"
  | "sha512crypt"
  | "md5crypt"
  | "argon2"
  | "base64"
  | "base32"
  | "hex"
  | "jwt"
  | "uuid";

export interface Signature {
  kind: HashKind;
  /** Nombre legible para el usuario. */
  label: string;
  /** "hash" | "encoding" | "token" */
  family: "hash" | "encoding" | "token";
  /** ¿Reversible sin secreto? (encodings sí, hashes no). */
  reversible: boolean;
  /** Patrón que debe calzar exactamente (se ancla con ^...$). */
  pattern: RegExp;
  /** Confianza base [0-1] cuando el patrón calza. */
  baseScore: number;
  /** Nota corta para el usuario. */
  note?: string;
}

const hex = (n: number) => new RegExp(`^[a-f0-9]{${n}}$`, "i");

export const SIGNATURES: Signature[] = [
  // --- Prefijados: muy distintivos, score alto ---
  {
    kind: "bcrypt",
    label: "bcrypt",
    family: "hash",
    reversible: false,
    pattern: /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/,
    baseScore: 0.99,
    note: "Hash lento con salt embebido. Crackear solo con diccionario pequeño.",
  },
  {
    kind: "sha512crypt",
    label: "sha512crypt ($6$)",
    family: "hash",
    reversible: false,
    pattern: /^\$6\$[^$]{1,16}\$[./A-Za-z0-9]{86}$/,
    baseScore: 0.98,
    note: "Formato típico de /etc/shadow en Linux.",
  },
  {
    kind: "sha256crypt",
    label: "sha256crypt ($5$)",
    family: "hash",
    reversible: false,
    pattern: /^\$5\$[^$]{1,16}\$[./A-Za-z0-9]{43}$/,
    baseScore: 0.98,
  },
  {
    kind: "md5crypt",
    label: "md5crypt ($1$)",
    family: "hash",
    reversible: false,
    pattern: /^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$/,
    baseScore: 0.98,
  },
  {
    kind: "argon2",
    label: "Argon2",
    family: "hash",
    reversible: false,
    pattern: /^\$argon2(id|i|d)\$.+/,
    baseScore: 0.99,
  },
  {
    kind: "jwt",
    label: "JWT (JSON Web Token)",
    family: "token",
    reversible: true,
    pattern: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/,
    baseScore: 0.95,
    note: "Header y payload son Base64URL decodificables; la firma no.",
  },
  {
    kind: "uuid",
    label: "UUID",
    family: "token",
    reversible: false,
    pattern: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,
    baseScore: 0.95,
  },

  // --- Longitudes hex específicas ---
  {
    kind: "crc32",
    label: "CRC-32",
    family: "hash",
    reversible: false,
    pattern: hex(8),
    baseScore: 0.4,
  },
  {
    kind: "mysql323",
    label: "MySQL 3.23",
    family: "hash",
    reversible: false,
    pattern: hex(16),
    baseScore: 0.45,
  },
  {
    kind: "md5",
    label: "MD5",
    family: "hash",
    reversible: false,
    pattern: hex(32),
    baseScore: 0.6,
    note: "32 hex también calza NTLM/MD4. Probar todos con hashcat.",
  },
  {
    kind: "ntlm",
    label: "NTLM",
    family: "hash",
    reversible: false,
    pattern: hex(32),
    baseScore: 0.45,
    note: "Indistinguible de MD5 por forma; contexto (Windows) decide.",
  },
  {
    kind: "md4",
    label: "MD4",
    family: "hash",
    reversible: false,
    pattern: hex(32),
    baseScore: 0.2,
  },
  {
    kind: "sha1",
    label: "SHA-1",
    family: "hash",
    reversible: false,
    pattern: hex(40),
    baseScore: 0.6,
    note: "40 hex también calza RIPEMD-160.",
  },
  {
    kind: "ripemd160",
    label: "RIPEMD-160",
    family: "hash",
    reversible: false,
    pattern: hex(40),
    baseScore: 0.2,
  },
  {
    kind: "mysql41",
    label: "MySQL 4.1+ (SHA-1 doble)",
    family: "hash",
    reversible: false,
    pattern: /^\*[A-F0-9]{40}$/i,
    baseScore: 0.9,
    note: "SHA-1 con prefijo '*'.",
  },
  {
    kind: "sha224",
    label: "SHA-224",
    family: "hash",
    reversible: false,
    pattern: hex(56),
    baseScore: 0.6,
  },
  {
    kind: "sha256",
    label: "SHA-256",
    family: "hash",
    reversible: false,
    pattern: hex(64),
    baseScore: 0.65,
    note: "64 hex también calza SHA3-256.",
  },
  {
    kind: "sha3-256",
    label: "SHA3-256",
    family: "hash",
    reversible: false,
    pattern: hex(64),
    baseScore: 0.2,
  },
  {
    kind: "sha384",
    label: "SHA-384",
    family: "hash",
    reversible: false,
    pattern: hex(96),
    baseScore: 0.7,
  },
  {
    kind: "sha512",
    label: "SHA-512",
    family: "hash",
    reversible: false,
    pattern: hex(128),
    baseScore: 0.75,
  },
];
