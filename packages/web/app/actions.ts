"use server";

import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import {
  identify,
  decodeAll,
  magic,
  recommend,
  caesarBruteForce,
  crack,
  isCrackable,
  isSlowHash,
  parseTarget,
  resolveCharset,
  generateCandidates,
  keyspace,
  score,
  type Candidate,
  type HashKind,
  type SaltMode,
} from "@cipherscope/core";

/** Tope de intentos por defecto para hashes lentos (bcrypt): son carísimos. */
const SLOW_HASH_CAP = 5000;
/** Presupuesto de tiempo para hashes lentos: la web no puede colgarse minutos. */
const SLOW_TIME_BUDGET_MS = 20_000;

/** Decoders "clásicos" (rot13/atbash): son conjeturas, no decodificación directa. */
const CLASSIC_DECODERS = new Set(["rot13", "atbash"]);

/** Wordlist por defecto (SecLists / rockyou). Editable desde la UI. */
const DEFAULT_WORDLIST =
  "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt";

/** Hashes lentos con salt: no hay atajo (ni online, ni fuerza bruta). Solo hashcat/john. */
const NO_SHORTCUT: ReadonlySet<HashKind> = new Set<HashKind>([
  "bcrypt",
  "argon2",
  "sha512crypt",
  "sha256crypt",
  "md5crypt",
]);

export interface AnalyzeResponse {
  input: string;
  candidates: (Candidate & {
    command?: string;
    /** Modo de hashcat (-m). */
    mode?: number;
    /** No tiene atajo: salt + coste → solo hashcat/john con diccionario. */
    noShortcut?: boolean;
  })[];
  decodings: { decoder: string; output: string }[];
  magic: { chain: string; output: string; score: number }[];
  caesar: { shift: number; text: string }[];
}

/**
 * Server Action: ejecuta el core en el servidor (usa Buffer/crypto de Node)
 * y devuelve un resultado serializable para la UI.
 */
export async function analyze(raw: string): Promise<AnalyzeResponse> {
  const input = raw.trim();
  if (!input) {
    return { input, candidates: [], decodings: [], magic: [], caesar: [] };
  }

  const id = identify(input);
  const candidates = id.candidates.map((c) => {
    const rec = !c.reversible ? recommend(c.kind) : undefined;
    return {
      ...c,
      command: rec?.commands[0],
      mode: rec?.hashcatMode,
      noShortcut: NO_SHORTCUT.has(c.kind),
    };
  });

  // Solo decodificaciones reales: encodings (no conjeturas clásicas) cuyo
  // resultado sea mayormente texto imprimible. Así un hash no genera ruido.
  const decodings = decodeAll(input)
    .filter((d) => !CLASSIC_DECODERS.has(d.decoder))
    .filter((d) => score(d.output).printable > 0.9)
    .slice(0, 8);

  // Si es un hash reconocido con confianza, NO es texto codificado: nada de
  // Magic/César (un hash largo alcanza ~40% de "legibilidad" solo por tener
  // muchas letras, pero no significa nada).
  const looksLikeHash = id.candidates.some((c) => c.family === "hash" && c.confidence >= 0.6);

  // Magic: solo si no es un hash, y solo resultados con legibilidad ≥40%.
  const magicResults = looksLikeHash
    ? []
    : magic(input, { limit: 5 })
        .map((r) => ({
          chain: r.steps.map((s) => s.decoder).join(" → "),
          output: r.output.slice(0, 300),
          score: Math.round(r.score.total * 100),
        }))
        .filter((m) => m.score >= 40);

  // César solo tiene sentido en texto alfabético que NO parece un hash.
  const caesar =
    /[a-z]/i.test(input) && input.length < 400 && !looksLikeHash ? caesarBruteForce(input) : [];

  return { input, candidates, decodings, magic: magicResults, caesar };
}

export interface CrackResponse {
  found: boolean;
  password?: string;
  user?: string;
  kind?: string;
  saltMode?: string;
  attempts: number;
  seconds: number;
  error?: string;
  /** El tipo es un hash lento (bcrypt…): solo apto para wordlists pequeñas. */
  slow?: boolean;
  /** Se alcanzó el tope de intentos antes de terminar la wordlist. */
  capped?: boolean;
  /** Tope aplicado, si lo hubo. */
  limit?: number;
  /** Estrategia en lenguaje humano para atacarlo con hashcat/john. */
  strategy?: string;
  /** Pasos concretos (comandos listos) para crackearlo con rockyou. */
  plan?: { n: number; title: string; cmd: string }[];
  /** Origen del resultado (p.ej. "fuerza bruta", "online: gromweb"). */
  source?: string;
  /** Fuerza bruta: se agotó todo el espacio de búsqueda sin encontrarla. */
  exhausted?: boolean;
}

/** Construye los pasos de ataque con hashcat/john para un tipo y wordlist dados. */
function buildPlan(kind: HashKind, hash: string, wordlist: string): CrackResponse["plan"] {
  const rec = recommend(kind);
  const steps: { n: number; title: string; cmd: string }[] = [
    { n: 1, title: "Guarda el hash en un archivo", cmd: `echo '${hash}' > hash.txt` },
  ];
  if (rec?.hashcatMode !== undefined) {
    const m = rec.hashcatMode;
    steps.push({
      n: steps.length + 1,
      title: "Ataque por diccionario (rockyou)",
      cmd: `hashcat -m ${m} -a 0 hash.txt ${wordlist}`,
    });
    steps.push({
      n: steps.length + 1,
      title: "Diccionario + reglas (más combinaciones)",
      cmd: `hashcat -m ${m} -a 0 hash.txt ${wordlist} -r /usr/share/hashcat/rules/best66.rule`,
    });
  }
  if (rec?.johnFormat) {
    steps.push({
      n: steps.length + 1,
      title: "Alternativa con John the Ripper",
      cmd: `john --format=${rec.johnFormat} --wordlist=${wordlist} hash.txt`,
    });
  }
  if (rec?.hashcatMode !== undefined) {
    steps.push({
      n: steps.length + 1,
      title: "Ver la contraseña encontrada",
      cmd: `hashcat -m ${rec.hashcatMode} hash.txt --show`,
    });
  }
  return steps;
}

export interface CrackInput {
  hash: string;
  /** Tipo forzado (md5, sha256, ntlm…). Vacío = autodetectar. */
  type?: string;
  /** Salt conocido. */
  salt?: string;
  /** Ruta de la wordlist en el servidor. */
  wordlist?: string;
  /** Tope de intentos (0/undefined = sin tope). */
  maxAttempts?: number;
}

/**
 * Server Action: crackea un hash por diccionario leyendo la wordlist del
 * servidor en streaming por lotes (apto para rockyou sin agotar memoria).
 */
export async function crackHash(opts: CrackInput): Promise<CrackResponse> {
  const started = Date.now();
  const wordlist = opts.wordlist?.trim() || DEFAULT_WORDLIST;

  if (!opts.hash?.trim()) {
    return { found: false, attempts: 0, seconds: 0, error: "Falta el hash." };
  }
  if (!existsSync(wordlist)) {
    return { found: false, attempts: 0, seconds: 0, error: `No existe la wordlist: ${wordlist}` };
  }

  const parsed = parseTarget(opts.hash.trim());
  const salt = opts.salt?.trim() || parsed.salt;

  const candidates = identify(parsed.hash).candidates;
  const forced = (opts.type?.trim() || undefined) as HashKind | undefined;
  // Tipo para CRACKEAR: el forzado, o el primer candidato crackeable.
  let kind = forced ?? candidates.find((c) => isCrackable(c.kind))?.kind;
  // Tipo para el PLAN/recomendación: el forzado, o el candidato más probable.
  const planKind = forced ?? kind ?? candidates[0]?.kind;

  if (!kind || !isCrackable(kind)) {
    const strat = planKind ? recommend(planKind) : undefined;
    return {
      found: false,
      attempts: 0,
      seconds: 0,
      kind: planKind,
      error:
        "No se puede crackear en local (bcrypt a coste alto, *crypt, argon2…). Sigue estos pasos con hashcat/john:",
      strategy: strat?.strategy,
      plan: planKind ? buildPlan(planKind, parsed.hash, wordlist) : undefined,
    };
  }

  // Los hashes lentos (bcrypt) se topan por defecto: cada intento cuesta
  // ~cientos de ms, así que rockyou entera tardaría horas/semanas.
  const slow = isSlowHash(kind);
  const cap =
    opts.maxAttempts && opts.maxAttempts > 0 ? opts.maxAttempts : slow ? SLOW_HASH_CAP : 0;

  const rl = createInterface({
    input: createReadStream(wordlist, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });

  const BATCH = slow ? 20 : 100_000;
  let batch: string[] = [];
  let totalAttempts = 0;

  const flush = () => {
    if (batch.length === 0) return undefined;
    const remaining = cap ? cap - totalAttempts : 0;
    const r = crack(parsed.hash, batch, {
      kind: kind!,
      salt,
      saltMode: undefined as SaltMode | undefined,
      maxAttempts: remaining > 0 ? remaining : undefined,
    });
    totalAttempts += r.attempts;
    batch = [];
    return r;
  };

  let capped = false;
  try {
    for await (const line of rl) {
      if (!line) continue;
      batch.push(line);
      if (batch.length >= BATCH) {
        const r = flush();
        if (r?.found) {
          rl.close();
          return done(true, r, parsed, kind, salt, totalAttempts, started, slow);
        }
        // Tope por intentos o por tiempo (hashes lentos no cuelgan la web).
        if (cap && totalAttempts >= cap) {
          capped = true;
          break;
        }
        if (slow && Date.now() - started > SLOW_TIME_BUDGET_MS) {
          capped = true;
          break;
        }
      }
    }
    if (!capped) {
      const last = flush();
      if (last?.found) return done(true, last, parsed, kind, salt, totalAttempts, started, slow);
    }
  } finally {
    rl.close();
  }

  return {
    found: false,
    kind,
    attempts: totalAttempts,
    seconds: (Date.now() - started) / 1000,
    slow,
    capped,
    limit: capped ? cap : undefined,
    // Si no salió por diccionario local, ofrece el plan con hashcat/john.
    strategy: recommend(kind)?.strategy,
    plan: buildPlan(kind, parsed.hash, wordlist),
  };
}

function done(
  found: boolean,
  r: ReturnType<typeof crack>,
  parsed: ReturnType<typeof parseTarget>,
  kind: HashKind,
  salt: string | undefined,
  attempts: number,
  started: number,
  slow: boolean
): CrackResponse {
  return {
    found,
    password: r.password,
    user: parsed.user,
    kind,
    saltMode: salt ? r.saltMode : undefined,
    attempts,
    seconds: (Date.now() - started) / 1000,
    slow,
  };
}

// ──────────────────────────────────────────────────────────────────────────
//  Modo "sin wordlist" 1: FUERZA BRUTA / MÁSCARA (local)
// ──────────────────────────────────────────────────────────────────────────

export interface BruteForceInput {
  hash: string;
  type?: string;
  /** Charset preset o literal: digits | lower | lower+digits | alnum | … */
  charset?: string;
  /** Longitud máxima a probar. */
  maxLen?: number;
}

/** Presupuesto de tiempo para fuerza bruta: nunca cuelga la web. */
const BRUTE_TIME_BUDGET_MS = 15_000;

export async function bruteForceHash(opts: BruteForceInput): Promise<CrackResponse> {
  const started = Date.now();
  if (!opts.hash?.trim()) {
    return { found: false, attempts: 0, seconds: 0, error: "Falta el hash." };
  }

  const parsed = parseTarget(opts.hash.trim());
  const candidates = identify(parsed.hash).candidates;
  const forced = (opts.type?.trim() || undefined) as HashKind | undefined;
  const kind = forced ?? candidates.find((c) => isCrackable(c.kind))?.kind;

  if (!kind || !isCrackable(kind)) {
    return {
      found: false,
      attempts: 0,
      seconds: 0,
      kind: forced ?? candidates[0]?.kind,
      error: "No reconozco el tipo o no es crackeable en local. Indica el tipo (md5, sha256, ntlm…).",
    };
  }
  if (isSlowHash(kind)) {
    return {
      found: false,
      attempts: 0,
      seconds: 0,
      kind,
      error: `${kind} es un hash lento: la fuerza bruta es inviable. Usa diccionario + hashcat.`,
      strategy: recommend(kind)?.strategy,
      plan: buildPlan(kind, parsed.hash, DEFAULT_WORDLIST),
    };
  }

  const charset = resolveCharset(opts.charset?.trim() || "lower+digits");
  const maxLen = Math.min(Math.max(opts.maxLen ?? 5, 1), 8);

  // Procesa el generador en lotes con tope de tiempo.
  const gen = generateCandidates(charset, maxLen);
  const BATCH = 200_000;
  let batch: string[] = [];
  let totalAttempts = 0;
  let capped = false;

  const flush = () => {
    if (batch.length === 0) return undefined;
    const r = crack(parsed.hash, batch, { kind });
    totalAttempts += r.attempts;
    batch = [];
    return r;
  };

  for (const candidate of gen) {
    batch.push(candidate);
    if (batch.length >= BATCH) {
      const r = flush();
      if (r?.found) {
        return {
          found: true,
          password: r.password,
          kind,
          attempts: totalAttempts,
          seconds: (Date.now() - started) / 1000,
          source: `fuerza bruta (${opts.charset || "lower+digits"}, ≤${maxLen})`,
        };
      }
      if (Date.now() - started > BRUTE_TIME_BUDGET_MS) {
        capped = true;
        break;
      }
    }
  }
  if (!capped) {
    const last = flush();
    if (last?.found) {
      return {
        found: true,
        password: last.password,
        kind,
        attempts: totalAttempts,
        seconds: (Date.now() - started) / 1000,
        source: `fuerza bruta (${opts.charset || "lower+digits"}, ≤${maxLen})`,
      };
    }
  }

  return {
    found: false,
    kind,
    attempts: totalAttempts,
    seconds: (Date.now() - started) / 1000,
    capped,
    exhausted: !capped,
    source: `fuerza bruta (${opts.charset || "lower+digits"}, ≤${maxLen})`,
    strategy: recommend(kind)?.strategy,
    plan: buildPlan(kind, parsed.hash, DEFAULT_WORDLIST),
  };
}

// ──────────────────────────────────────────────────────────────────────────
//  Modo "sin wordlist" 2: LOOKUP ONLINE (bases públicas de hashes)
// ──────────────────────────────────────────────────────────────────────────

/**
 * Consulta un servicio público de reverse-lookup. AVISO: envía el hash a un
 * tercero por internet. Soporta MD5 (gromweb). El salt de bcrypt lo hace
 * inútil para hashes lentos.
 */
export async function lookupOnline(opts: { hash: string; type?: string }): Promise<CrackResponse> {
  const started = Date.now();
  if (!opts.hash?.trim()) {
    return { found: false, attempts: 0, seconds: 0, error: "Falta el hash." };
  }

  const parsed = parseTarget(opts.hash.trim());
  const candidates = identify(parsed.hash).candidates;
  const forced = (opts.type?.trim() || undefined) as HashKind | undefined;
  const kind = forced ?? candidates[0]?.kind;

  if (kind !== "md5") {
    return {
      found: false,
      attempts: 0,
      seconds: 0,
      kind,
      error: "El lookup online soporta MD5 por ahora. Para otros tipos usa fuerza bruta o hashcat.",
    };
  }

  const hash = parsed.hash.toLowerCase();
  try {
    const res = await fetch(`https://md5.gromweb.com/?md5=${hash}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(12_000),
    });
    const html = await res.text();
    const m = html
      .replace(/<style[\s\S]*?<\/style>/g, "")
      .replace(/<script[\s\S]*?<\/script>/g, "")
      .match(/reversed into the string\s*<[^>]*>([^<]+)</i);
    if (m && m[1]) {
      return {
        found: true,
        password: m[1].trim(),
        kind: "md5",
        attempts: 1,
        seconds: (Date.now() - started) / 1000,
        source: "online: gromweb",
      };
    }
  } catch {
    return {
      found: false,
      attempts: 0,
      seconds: (Date.now() - started) / 1000,
      kind: "md5",
      error: "No se pudo consultar el servicio online (sin red o caído).",
    };
  }

  return {
    found: false,
    kind: "md5",
    attempts: 1,
    seconds: (Date.now() - started) / 1000,
    source: "online: gromweb",
    strategy: recommend("md5")?.strategy,
    plan: buildPlan("md5", parsed.hash, DEFAULT_WORDLIST),
  };
}
