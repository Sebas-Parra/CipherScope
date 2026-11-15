import { describe, it, expect } from "vitest";
import { base64Decoder } from "../src/decode/base64.js";
import { base32Decoder } from "../src/decode/base32.js";
import { hexDecoder } from "../src/decode/hex.js";
import { urlDecoder } from "../src/decode/url.js";
import { binaryDecoder } from "../src/decode/binary.js";
import { morseDecoder } from "../src/decode/morse.js";
import { caesarShift, caesarBruteForce } from "../src/decode/classic/caesar.js";
import { atbash } from "../src/decode/classic/atbash.js";
import { vigenereDecode, vigenereEncode } from "../src/decode/classic/vigenere.js";

describe("encodings", () => {
  it("base64", () => {
    expect(base64Decoder.canApply("SGVsbG8=")).toBe(true);
    expect(base64Decoder.decode("SGVsbG8=")).toBe("Hello");
  });

  it("base32", () => {
    expect(base32Decoder.decode("JBSWY3DP")).toBe("Hello");
  });

  it("hex con separadores", () => {
    expect(hexDecoder.decode("48 65 6c 6c 6f")).toBe("Hello");
    expect(hexDecoder.decode("0x48,0x69")).toBe("Hi");
  });

  it("url", () => {
    expect(urlDecoder.decode("a%20b%2Bc")).toBe("a b+c");
  });

  it("binario", () => {
    expect(binaryDecoder.decode("01001000 01101001")).toBe("Hi");
  });

  it("morse", () => {
    expect(morseDecoder.decode(".... . .-.. .-.. ---")).toBe("HELLO");
  });
});

describe("cifrados clásicos", () => {
  it("césar ida y vuelta", () => {
    expect(caesarShift("Hello", 3)).toBe("Khoor");
    expect(caesarShift("Khoor", -3)).toBe("Hello");
  });

  it("césar brute force produce 25 candidatos", () => {
    expect(caesarBruteForce("abc")).toHaveLength(25);
  });

  it("rot13 es su inverso", () => {
    expect(caesarShift(caesarShift("Secret", 13), 13)).toBe("Secret");
  });

  it("atbash es su inverso", () => {
    expect(atbash(atbash("Hello World"))).toBe("Hello World");
    expect(atbash("abc")).toBe("zyx");
  });

  it("vigenère ida y vuelta", () => {
    const enc = vigenereEncode("attackatdawn", "lemon");
    expect(vigenereDecode(enc, "lemon")).toBe("attackatdawn");
  });
});
