import { describe, it, expect } from "vitest";
import { recommend } from "../src/recommend/recommend.js";

describe("recommend", () => {
  it("MD5 → modo hashcat 0", () => {
    const r = recommend("md5");
    expect(r?.hashcatMode).toBe(0);
    expect(r?.commands.some((c) => c.includes("-m 0"))).toBe(true);
  });

  it("bcrypt → modo 3200 y advierte de lentitud", () => {
    const r = recommend("bcrypt");
    expect(r?.hashcatMode).toBe(3200);
    expect(r?.strategy.toLowerCase()).toContain("lento");
  });

  it("tipo sin recomendación devuelve undefined", () => {
    expect(recommend("uuid")).toBeUndefined();
  });
});
