import { describe, it, expect } from "vitest";
import { diagnose } from "../src/identify/diagnose.js";
import { identify } from "../src/identify/identify.js";

// El hash real del reto al que le faltaba el "." final (85 en vez de 86).
const SHORT =
  "$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02";
const FULL = SHORT + ".";

describe("diagnose", () => {
  it("avisa cuando a un $6$ le falta un carácter (85/86)", () => {
    const w = diagnose(SHORT);
    expect(w).toBeDefined();
    expect(w!.kind).toBe("sha512crypt");
    expect(w!.expected).toBe(86);
    expect(w!.actual).toBe(85);
    expect(w!.message).toMatch(/faltan 1/);
  });

  it("no avisa cuando el $6$ está completo (86)", () => {
    expect(diagnose(FULL)).toBeUndefined();
  });

  it("detecta sobrantes en el digest", () => {
    const w = diagnose(FULL + "XX");
    expect(w).toBeDefined();
    expect(w!.actual).toBe(88);
    expect(w!.message).toMatch(/sobran 2/);
  });

  it("detecta carácter inválido en el digest", () => {
    const bad = SHORT.slice(0, -1) + "!"; // mismo largo (85) pero con '!'
    const w = diagnose(bad);
    expect(w).toBeDefined();
    expect(w!.message).toMatch(/inválido/);
  });

  it("avisa de bcrypt con longitud incorrecta", () => {
    const w = diagnose("$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRo"); // falta 1
    expect(w).toBeDefined();
    expect(w!.kind).toBe("bcrypt");
    expect(w!.expected).toBe(53);
  });

  it("no avisa para hashes que no son crypt/bcrypt", () => {
    expect(diagnose("279412f945939ba78ce0758d3fd83daa")).toBeUndefined();
    expect(diagnose("hola mundo")).toBeUndefined();
  });

  it("identify adjunta el warning cuando no hay candidatos", () => {
    const r = identify(SHORT);
    expect(r.candidates).toHaveLength(0);
    expect(r.warning).toBeDefined();
    expect(r.warning!.actual).toBe(85);
  });

  it("identify no pone warning cuando el hash es válido", () => {
    const r = identify(FULL);
    expect(r.candidates.length).toBeGreaterThan(0);
    expect(r.warning).toBeUndefined();
  });
});
