// identify
export { identify } from "./identify/identify.js";
export type { Candidate, IdentifyResult } from "./identify/identify.js";
export { diagnose } from "./identify/diagnose.js";
export type { FormatWarning } from "./identify/diagnose.js";
export { SIGNATURES } from "./identify/signatures.js";
export type { HashKind, Signature } from "./identify/signatures.js";

// decode
export type { Decoder } from "./decode/types.js";
export { DecodeError } from "./decode/types.js";
export { REGISTRY, getDecoder, decodeAll } from "./decode/registry.js";
export { base64Decoder } from "./decode/base64.js";
export { base32Decoder } from "./decode/base32.js";
export { hexDecoder } from "./decode/hex.js";
export { urlDecoder } from "./decode/url.js";
export { binaryDecoder } from "./decode/binary.js";
export { morseDecoder } from "./decode/morse.js";
export { caesarShift, caesarBruteForce, rot13Decoder } from "./decode/classic/caesar.js";
export { atbash, atbashDecoder } from "./decode/classic/atbash.js";
export { vigenereDecode, vigenereEncode } from "./decode/classic/vigenere.js";

// magic
export { magic } from "./magic/magic.js";
export type { MagicResult, MagicStep, MagicOptions } from "./magic/magic.js";
export { score } from "./magic/scorer.js";
export type { Score } from "./magic/scorer.js";

// recommend
export { recommend } from "./recommend/recommend.js";
export type { Recommendation } from "./recommend/recommend.js";
export { constructions } from "./recommend/constructions.js";
export type { Construction } from "./recommend/constructions.js";

// crack (v3)
export { crack, isCrackable } from "./crack/crack.js";
export type { CrackOptions, CrackResult } from "./crack/crack.js";
export { HASHERS } from "./crack/hashers.js";
export type { Hasher, SaltMode, HashOptions } from "./crack/hashers.js";
export { VERIFIERS, hasVerifier, isSlowHash } from "./crack/verifiers.js";
export type { Verifier } from "./crack/verifiers.js";
export { CHARSETS, resolveCharset, keyspace, generateCandidates } from "./crack/bruteforce.js";
export { parseTarget } from "./crack/parse.js";
export type { ParsedTarget } from "./crack/parse.js";
export { md4 } from "./crack/md4.js";
