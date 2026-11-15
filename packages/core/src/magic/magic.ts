import { REGISTRY } from "../decode/registry.js";
import { caesarBruteForce } from "../decode/classic/caesar.js";
import { score, type Score } from "./scorer.js";

export interface MagicStep {
  /** Nombre del decoder aplicado, p.ej. "base64" o "caesar(+3)". */
  decoder: string;
  /** Salida tras aplicar este paso. */
  output: string;
}

export interface MagicResult {
  /** Cadena de transformaciones desde la entrada original. */
  steps: MagicStep[];
  /** Texto final. */
  output: string;
  /** Legibilidad del texto final. */
  score: Score;
}

export interface MagicOptions {
  /** Profundidad máxima de encadenado. */
  maxDepth?: number;
  /** Nº de resultados a devolver. */
  limit?: number;
  /** Incluir fuerza bruta de César (25 shifts) en cada nivel. */
  includeCaesar?: boolean;
}

/**
 * Motor Magic: explora (BFS) transformaciones encadenadas y rankea los
 * resultados por legibilidad. Equivalente conceptual al "Magic" de
 * CyberChef, pero acotado y determinista.
 */
export function magic(input: string, opts: MagicOptions = {}): MagicResult[] {
  const maxDepth = opts.maxDepth ?? 3;
  const limit = opts.limit ?? 5;
  const includeCaesar = opts.includeCaesar ?? true;

  const results: MagicResult[] = [];
  const seen = new Set<string>([input]);

  interface Node {
    text: string;
    steps: MagicStep[];
  }

  let frontier: Node[] = [{ text: input, steps: [] }];

  for (let depth = 0; depth < maxDepth; depth++) {
    const next: Node[] = [];
    for (const node of frontier) {
      const expansions = expand(node.text, includeCaesar);
      for (const { decoder, output } of expansions) {
        if (seen.has(output)) continue;
        seen.add(output);
        const steps = [...node.steps, { decoder, output }];
        const sc = score(output);
        results.push({ steps, output, score: sc });
        next.push({ text: output, steps });
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }

  results.sort((a, b) => b.score.total - a.score.total || a.steps.length - b.steps.length);
  return results.slice(0, limit);
}

/** Genera todas las salidas posibles de un paso desde `text`. */
function expand(text: string, includeCaesar: boolean): { decoder: string; output: string }[] {
  const out: { decoder: string; output: string }[] = [];

  for (const d of REGISTRY) {
    if (!d.canApply(text)) continue;
    try {
      const output = d.decode(text);
      if (output && output !== text) out.push({ decoder: d.name, output });
    } catch {
      /* descartado */
    }
  }

  if (includeCaesar && /[a-z]/i.test(text)) {
    for (const { shift, text: output } of caesarBruteForce(text)) {
      if (shift === 13) continue; // ya cubierto por rot13 del registry
      out.push({ decoder: `caesar(+${shift})`, output });
    }
  }

  return out;
}
