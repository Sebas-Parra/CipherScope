import { createHash } from "node:crypto";
import { md4 } from "./md4.js";
import type { HashKind } from "../identify/signatures.js";

/** Dónde va el salt respecto a la contraseña, para hashes "crudos". */
export type SaltMode = "none" | "prefix" | "suffix";

export interface HashOptions {
  salt?: string;
  saltMode?: SaltMode;
}

function raw(algo: string) {
  return (password: string, opts: HashOptions = {}): string => {
    const { salt = "", saltMode = "none" } = opts;
    let data = password;
    if (saltMode === "prefix") data = salt + password;
    else if (saltMode === "suffix") data = password + salt;
    return createHash(algo).update(data, "utf8").digest("hex");
  };
}

/** NTLM = MD4(UTF-16LE(password)), sin salt. */
function ntlm(password: string): string {
  return md4(Buffer.from(password, "utf16le")).toString("hex");
}

/** MySQL 4.1+: '*' + UPPER(SHA1(SHA1_raw(password))). */
function mysql41(password: string): string {
  const once = createHash("sha1").update(password, "utf8").digest();
  const twice = createHash("sha1").update(once).digest("hex");
  return "*" + twice.toUpperCase();
}

/** MySQL 3.23 (OLD_PASSWORD): hash propietario de 16 hex. */
function mysql323(password: string): string {
  let nr = 1345345333;
  let add = 7;
  let nr2 = 0x12345671;
  for (const ch of password) {
    const c = ch.charCodeAt(0);
    if (ch === " " || ch === "\t") continue;
    nr ^= ((((nr & 63) + add) * c + (nr << 8)) >>> 0);
    nr2 = (nr2 + ((nr2 << 8) ^ nr)) >>> 0;
    add += c;
  }
  const r1 = (nr & 0x7fffffff) >>> 0;
  const r2 = (nr2 & 0x7fffffff) >>> 0;
  return r1.toString(16).padStart(8, "0") + r2.toString(16).padStart(8, "0");
}

/** CRC-32 (IEEE), 8 hex. No criptográfico. */
function crc32(password: string): string {
  let crc = 0xffffffff;
  const bytes = Buffer.from(password, "utf8");
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

export type Hasher = (password: string, opts?: HashOptions) => string;

/** Tabla de funciones de hash por tipo. Solo los crackeables localmente. */
export const HASHERS: Partial<Record<HashKind, Hasher>> = {
  md5: raw("md5"),
  sha1: raw("sha1"),
  sha224: raw("sha224"),
  sha256: raw("sha256"),
  sha384: raw("sha384"),
  sha512: raw("sha512"),
  "sha3-256": raw("sha3-256"),
  ripemd160: raw("ripemd160"),
  ntlm,
  md4: (p) => md4(Buffer.from(p, "utf8")).toString("hex"),
  mysql41,
  mysql323,
  crc32,
};
