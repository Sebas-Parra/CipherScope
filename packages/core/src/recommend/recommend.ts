import { type HashKind } from "../identify/signatures.js";

export interface Recommendation {
  kind: HashKind;
  /** Modo de hashcat (-m). undefined si no aplica. */
  hashcatMode?: number;
  /** Formato de john (--format=). */
  johnFormat?: string;
  /** Estrategia recomendada en lenguaje humano. */
  strategy: string;
  /** Comandos listos para copiar (placeholders: HASH, WORDLIST). */
  commands: string[];
}

const WL = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt";

const TABLE: Partial<Record<HashKind, Omit<Recommendation, "kind">>> = {
  md5: {
    hashcatMode: 0,
    johnFormat: "raw-md5",
    strategy: "Rápido de crackear. Diccionario primero, luego reglas (best64) y máscara.",
    commands: [
      `hashcat -m 0 -a 0 HASH ${WL}`,
      `hashcat -m 0 -a 0 HASH ${WL} -r /usr/share/hashcat/rules/best64.rule`,
      `john --format=raw-md5 --wordlist=${WL} HASH`,
    ],
  },
  ntlm: {
    hashcatMode: 1000,
    johnFormat: "nt",
    strategy: "Hash de contraseñas Windows. Sin salt → muy rápido. Diccionario + reglas.",
    commands: [`hashcat -m 1000 -a 0 HASH ${WL}`, `john --format=nt --wordlist=${WL} HASH`],
  },
  sha1: {
    hashcatMode: 100,
    johnFormat: "raw-sha1",
    strategy: "Rápido. Diccionario + reglas; máscara para patrones conocidos.",
    commands: [`hashcat -m 100 -a 0 HASH ${WL}`, `john --format=raw-sha1 --wordlist=${WL} HASH`],
  },
  sha256: {
    hashcatMode: 1400,
    johnFormat: "raw-sha256",
    strategy: "Diccionario + reglas. Sigue siendo rápido en GPU.",
    commands: [`hashcat -m 1400 -a 0 HASH ${WL}`, `john --format=raw-sha256 --wordlist=${WL} HASH`],
  },
  sha512: {
    hashcatMode: 1700,
    johnFormat: "raw-sha512",
    strategy: "Diccionario + reglas.",
    commands: [`hashcat -m 1700 -a 0 HASH ${WL}`, `john --format=raw-sha512 --wordlist=${WL} HASH`],
  },
  sha224: {
    hashcatMode: 1300,
    strategy: "Diccionario + reglas.",
    commands: [`hashcat -m 1300 -a 0 HASH ${WL}`],
  },
  sha384: {
    hashcatMode: 10800,
    strategy: "Diccionario + reglas.",
    commands: [`hashcat -m 10800 -a 0 HASH ${WL}`],
  },
  bcrypt: {
    hashcatMode: 3200,
    johnFormat: "bcrypt",
    strategy: "LENTO por diseño. Olvida la fuerza bruta: solo diccionarios pequeños y dirigidos.",
    commands: [`hashcat -m 3200 -a 0 HASH ${WL}`, `john --format=bcrypt --wordlist=${WL} HASH`],
  },
  sha512crypt: {
    hashcatMode: 1800,
    johnFormat: "sha512crypt",
    strategy: "Lento (salt + iteraciones). Diccionario dirigido. Típico de /etc/shadow.",
    commands: [`hashcat -m 1800 -a 0 HASH ${WL}`, `john --format=sha512crypt --wordlist=${WL} HASH`],
  },
  sha256crypt: {
    hashcatMode: 7400,
    johnFormat: "sha256crypt",
    strategy: "Lento. Diccionario dirigido.",
    commands: [`hashcat -m 7400 -a 0 HASH ${WL}`, `john --format=sha256crypt --wordlist=${WL} HASH`],
  },
  md5crypt: {
    hashcatMode: 500,
    johnFormat: "md5crypt",
    strategy: "Lento-moderado. Diccionario + reglas.",
    commands: [`hashcat -m 500 -a 0 HASH ${WL}`, `john --format=md5crypt --wordlist=${WL} HASH`],
  },
  argon2: {
    strategy: "Muy lento y resistente a GPU. Solo contraseñas débiles con diccionario mínimo.",
    commands: [`john --wordlist=${WL} HASH`],
  },
  mysql41: {
    hashcatMode: 300,
    johnFormat: "mysql-sha1",
    strategy: "SHA-1 doble de MySQL. Diccionario + reglas.",
    commands: [`hashcat -m 300 -a 0 HASH ${WL}`],
  },
  mysql323: {
    hashcatMode: 200,
    strategy: "Hash antiguo y débil de MySQL.",
    commands: [`hashcat -m 200 -a 0 HASH ${WL}`],
  },
  crc32: {
    hashcatMode: 11500,
    strategy: "No es criptográfico: checksum de 32 bits. Útil para integridad, no para secretos.",
    commands: [`hashcat -m 11500 -a 0 HASH ${WL}`],
  },
};

/** Devuelve la recomendación de ataque para un tipo de hash, si se conoce. */
export function recommend(kind: HashKind): Recommendation | undefined {
  const entry = TABLE[kind];
  if (!entry) return undefined;
  return { kind, ...entry };
}
