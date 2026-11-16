import { describe, it, expect } from "vitest";
import { constructions } from "../src/recommend/constructions.js";

describe("constructions", () => {
  it("SHA-1 incluye el modo HMAC key=salt (-m 160), el del reto tryhackme", () => {
    const c = constructions("sha1");
    const modes = c.map((x) => x.mode);
    expect(modes).toEqual([100, 110, 120, 150, 160]);
    expect(c.find((x) => x.mode === 160)!.label).toMatch(/key = salt/);
  });

  it("MD5 cubre plano + salteados + HMAC", () => {
    expect(constructions("md5").map((x) => x.mode)).toEqual([0, 10, 20, 50, 60]);
  });

  it("SHA-256 y SHA-512 tienen sus modos salteados", () => {
    expect(constructions("sha256").map((x) => x.mode)).toEqual([1400, 1410, 1420, 1450, 1460]);
    expect(constructions("sha512").map((x) => x.mode)).toEqual([1700, 1710, 1720, 1750, 1760]);
  });

  it("no ofrece construcciones para hashes sin variantes estándar", () => {
    expect(constructions("bcrypt")).toEqual([]);
    expect(constructions("sha512crypt")).toEqual([]);
    expect(constructions("ntlm")).toEqual([]);
  });
});
