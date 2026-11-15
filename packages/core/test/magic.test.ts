import { describe, it, expect } from "vitest";
import { magic } from "../src/magic/magic.js";
import { score } from "../src/magic/scorer.js";

describe("scorer", () => {
  it("texto en inglés puntúa más alto que ruido binario", () => {
    const good = score("the secret password is hello world");
    const bad = score("\x00\x01\x02\x03\xff\xfe");
    expect(good.total).toBeGreaterThan(bad.total);
  });

  it("detecta patrón de flag", () => {
    expect(score("flag{this_is_the_flag}").flag).toBe(true);
  });
});

describe("magic chaining", () => {
  it("resuelve Base64 simple", () => {
    // "the flag is here" -> base64
    const b64 = Buffer.from("the flag is here").toString("base64");
    const results = magic(b64, { includeCaesar: false });
    expect(results[0]?.output).toBe("the flag is here");
  });

  it("resuelve cadena Base64 -> ROT13", () => {
    const plain = "the secret message";
    const rotted = plain.replace(/[a-z]/gi, (ch) => {
      const base = ch <= "Z" ? 65 : 97;
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
    });
    const encoded = Buffer.from(rotted).toString("base64");
    const results = magic(encoded, { maxDepth: 3 });
    const found = results.find((r) => r.output === plain);
    expect(found).toBeDefined();
  });

  it("resuelve César por fuerza bruta", () => {
    const shifted = "wkh vhfuhw"; // "the secret" shift +3
    const results = magic(shifted, { maxDepth: 1 });
    const found = results.find((r) => r.output.includes("the secret"));
    expect(found).toBeDefined();
  });
});
