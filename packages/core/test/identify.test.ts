import { describe, it, expect } from "vitest";
import { identify } from "../src/identify/identify.js";

describe("identify", () => {
  it("reconoce MD5 (32 hex) con MD5 como top", () => {
    const r = identify("5f4dcc3b5aa765d61d8327deb882cf99");
    expect(r.candidates[0]?.kind).toBe("md5");
    expect(r.candidates.map((c) => c.kind)).toContain("ntlm");
  });

  it("reconoce SHA-256 (64 hex)", () => {
    const r = identify("a".repeat(64));
    expect(r.candidates[0]?.kind).toBe("sha256");
  });

  it("reconoce bcrypt por prefijo con alta confianza", () => {
    const r = identify("$2b$12$" + "a".repeat(53));
    expect(r.candidates[0]?.kind).toBe("bcrypt");
    expect(r.candidates[0]?.confidence).toBeGreaterThan(0.9);
    expect(r.candidates[0]?.reversible).toBe(false);
  });

  it("reconoce JWT", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123";
    const r = identify(jwt);
    expect(r.candidates.some((c) => c.kind === "jwt")).toBe(true);
  });

  it("devuelve lista vacía para basura", () => {
    const r = identify("no soy un hash!!!");
    expect(r.candidates).toHaveLength(0);
  });
});
