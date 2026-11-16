import { SIGNATURES, type HashKind, type Signature } from "./signatures.js";
import { diagnose, type FormatWarning } from "./diagnose.js";

export interface Candidate {
  kind: HashKind;
  label: string;
  family: Signature["family"];
  reversible: boolean;
  /** Confianza final [0-1]. */
  confidence: number;
  note?: string;
}

export interface IdentifyResult {
  input: string;
  length: number;
  candidates: Candidate[];
  /** Aviso de formato si el input parece un hash crypt/bcrypt malformado. */
  warning?: FormatWarning;
}

/**
 * Identifica el tipo de un hash/token/encoding por su forma.
 * Devuelve candidatos ordenados por confianza descendente.
 *
 * El ranking parte del `baseScore` de la firma y aplica un pequeño
 * desempate determinista para que el orden sea estable.
 */
export function identify(raw: string): IdentifyResult {
  const input = raw.trim();
  const matches: Candidate[] = [];

  for (const sig of SIGNATURES) {
    if (sig.pattern.test(input)) {
      matches.push({
        kind: sig.kind,
        label: sig.label,
        family: sig.family,
        reversible: sig.reversible,
        confidence: sig.baseScore,
        note: sig.note,
      });
    }
  }

  matches.sort((a, b) => b.confidence - a.confidence || a.label.localeCompare(b.label));

  // Si ninguna firma crypt/bcrypt calzó, revisa si es por un hash malformado.
  const warning = matches.length === 0 ? diagnose(input) : undefined;

  return { input, length: input.length, candidates: matches, warning };
}
