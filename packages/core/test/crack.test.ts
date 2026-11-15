import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import bcrypt from "bcryptjs";
import { crack, isCrackable } from "../src/crack/crack.js";
import { HASHERS } from "../src/crack/hashers.js";
import { md4 } from "../src/crack/md4.js";
import { parseTarget } from "../src/crack/parse.js";

const WL = ["123456", "password", "hello", "letmein", "dragon"];

describe("md4 / NTLM", () => {
  it("MD4 de cadena vacía es el vector conocido", () => {
    expect(md4(Buffer.from("", "utf8")).toString("hex")).toBe(
      "31d6cfe0d16ae931b73c59d7e0c089c0"
    );
  });

  it("MD4('abc') es el vector conocido", () => {
    expect(md4(Buffer.from("abc", "utf8")).toString("hex")).toBe(
      "a448017aaf21d8525fc10ae87aa6729d"
    );
  });

  it("NTLM('password') coincide con el valor conocido", () => {
    expect(HASHERS.ntlm!("password")).toBe("8846f7eaee8fb117ad06bdd830b7586c");
  });
});

describe("crack por diccionario", () => {
  it("encuentra MD5 en la wordlist", () => {
    const target = createHash("md5").update("password").digest("hex");
    const r = crack(target, WL, { kind: "md5" });
    expect(r.found).toBe(true);
    expect(r.password).toBe("password");
  });

  it("falla si no está en la wordlist", () => {
    const target = createHash("sha256").update("nope-not-here").digest("hex");
    const r = crack(target, WL, { kind: "sha256" });
    expect(r.found).toBe(false);
    expect(r.attempts).toBe(WL.length);
  });

  it("crackea NTLM", () => {
    const r = crack("8846f7eaee8fb117ad06bdd830b7586c", WL, { kind: "ntlm" });
    expect(r.password).toBe("password");
  });

  it("soporta salt como sufijo probando ambos modos", () => {
    const target = createHash("md5").update("hello" + "s4lt").digest("hex");
    const r = crack(target, WL, { kind: "md5", salt: "s4lt" });
    expect(r.found).toBe(true);
    expect(r.password).toBe("hello");
    expect(r.saltMode).toBe("suffix");
  });

  it("respeta maxAttempts", () => {
    const target = createHash("md5").update("dragon").digest("hex");
    const r = crack(target, WL, { kind: "md5", maxAttempts: 2 });
    expect(r.found).toBe(false);
    expect(r.attempts).toBe(2);
  });
});

describe("bcrypt (verificador)", () => {
  it("bcrypt es crackeable en local", () => {
    expect(isCrackable("bcrypt")).toBe(true);
  });

  it("crackea un bcrypt por diccionario", () => {
    // coste bajo (6) para que el test sea rápido.
    const target = bcrypt.hashSync("dragon", 6);
    const r = crack(target, WL, { kind: "bcrypt" });
    expect(r.found).toBe(true);
    expect(r.password).toBe("dragon");
  });

  it("no acierta si la contraseña no está", () => {
    const target = bcrypt.hashSync("zzz-nope", 6);
    const r = crack(target, WL, { kind: "bcrypt" });
    expect(r.found).toBe(false);
  });
});

describe("fuerza bruta", () => {
  it("genera el keyspace correcto", async () => {
    const { generateCandidates, keyspace } = await import("../src/crack/bruteforce.js");
    const all = [...generateCandidates("ab", 2)];
    expect(all).toEqual(["a", "b", "aa", "ab", "ba", "bb"]);
    expect(keyspace(2, 2)).toBe(6);
  });

  it("crackea un MD5 corto por fuerza bruta (sin wordlist)", async () => {
    const { generateCandidates, resolveCharset } = await import("../src/crack/bruteforce.js");
    const target = createHash("md5").update("ab12").digest("hex");
    const r = crack(target, generateCandidates(resolveCharset("lower+digits"), 4), {
      kind: "md5",
    });
    expect(r.found).toBe(true);
    expect(r.password).toBe("ab12");
  });
});

describe("parseTarget", () => {
  it("detecta user:hash", () => {
    const md5 = createHash("md5").update("x").digest("hex");
    const p = parseTarget(`admin:${md5}`);
    expect(p.user).toBe("admin");
    expect(p.hash).toBe(md5);
  });

  it("detecta hash:salt", () => {
    const md5 = createHash("md5").update("x").digest("hex");
    const p = parseTarget(`${md5}:somesalt`);
    expect(p.hash).toBe(md5);
    expect(p.salt).toBe("somesalt");
  });

  it("hash solo", () => {
    const md5 = createHash("md5").update("x").digest("hex");
    expect(parseTarget(md5).hash).toBe(md5);
  });
});
