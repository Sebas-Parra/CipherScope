#!/usr/bin/env node
import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { Command } from "commander";
import pc from "picocolors";
import {
  identify,
  decodeAll,
  magic,
  recommend,
  caesarBruteForce,
  vigenereDecode,
  score,
  crack,
  isCrackable,
  parseTarget,
  type HashKind,
  type SaltMode,
} from "@cipherscope/core";

/** Itera las líneas de una wordlist de forma perezosa (apto para rockyou). */
async function* wordlistLines(path: string): AsyncGenerator<string> {
  const rl = createInterface({
    input: createReadStream(path, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    if (line.length > 0) yield line;
  }
}

const program = new Command();

program
  .name("cipherscope")
  .description("Navaja suiza de criptoanálisis para CTF")
  .version("0.1.0");

function bar(v: number, width = 20): string {
  const filled = Math.round(v * width);
  return pc.green("█".repeat(filled)) + pc.dim("░".repeat(width - filled));
}

// --- identify ---
program
  .command("identify")
  .alias("id")
  .argument("<input>", "hash o token a identificar")
  .description("Identifica el tipo por su forma y rankea candidatos")
  .action((input: string) => {
    const r = identify(input);
    if (r.candidates.length === 0) {
      console.log(pc.yellow("No coincide con ninguna firma conocida."));
      console.log(pc.dim(`(longitud ${r.length}) ¿Será un encoding? Prueba: cipherscope decode`));
      return;
    }
    console.log(pc.bold(`\nCandidatos para `) + pc.cyan(r.input.slice(0, 40)) + pc.dim(` (len ${r.length})\n`));
    for (const c of r.candidates) {
      const rev = c.reversible ? pc.green("reversible") : pc.red("una sola vía");
      console.log(
        `  ${bar(c.confidence)} ${pc.bold(c.label.padEnd(22))} ${rev}`
      );
      if (c.note) console.log(pc.dim(`    └ ${c.note}`));
    }
    console.log();
  });

// --- decode ---
program
  .command("decode")
  .alias("dec")
  .argument("<input>", "texto codificado")
  .description("Aplica todos los decoders reversibles aplicables")
  .action((input: string) => {
    const results = decodeAll(input);
    if (results.length === 0) {
      console.log(pc.yellow("Ningún decoder directo aplica. Prueba: cipherscope magic"));
      return;
    }
    console.log(pc.bold("\nDecodificaciones directas:\n"));
    for (const { decoder, output } of results) {
      console.log(`  ${pc.cyan(decoder.padEnd(10))} → ${output}`);
    }
    console.log();
  });

// --- magic ---
program
  .command("magic")
  .argument("<input>", "texto a resolver")
  .option("-d, --depth <n>", "profundidad máxima de encadenado", "3")
  .option("-n, --limit <n>", "número de resultados", "5")
  .option("--no-caesar", "no probar fuerza bruta de César")
  .description("Detecta transformaciones encadenadas y rankea por legibilidad")
  .action((input: string, opts: { depth: string; limit: string; caesar: boolean }) => {
    const results = magic(input, {
      maxDepth: Number(opts.depth),
      limit: Number(opts.limit),
      includeCaesar: opts.caesar,
    });
    if (results.length === 0) {
      console.log(pc.yellow("Sin resultados. ¿Seguro que hay algo codificado?"));
      return;
    }
    console.log(pc.bold("\nMejores candidatos (por legibilidad):\n"));
    results.forEach((r, i) => {
      const chain = r.steps.map((s) => s.decoder).join(pc.dim(" → "));
      console.log(
        `${pc.bold(`#${i + 1}`)} ${bar(r.score.total)} ${pc.dim(`[${chain}]`)}`
      );
      console.log(`    ${pc.green(r.output.slice(0, 200))}\n`);
    });
  });

// --- caesar ---
program
  .command("caesar")
  .argument("<input>", "texto cifrado con César")
  .description("Muestra los 25 desplazamientos posibles")
  .action((input: string) => {
    console.log(pc.bold("\nFuerza bruta César:\n"));
    for (const { shift, text } of caesarBruteForce(input)) {
      console.log(`  ${pc.cyan(`+${String(shift).padStart(2)}`)}  ${text}`);
    }
    console.log();
  });

// --- vigenere ---
program
  .command("vigenere")
  .argument("<input>", "texto cifrado")
  .requiredOption("-k, --key <key>", "llave")
  .description("Descifra Vigenère con una llave conocida")
  .action((input: string, opts: { key: string }) => {
    console.log("\n  " + pc.green(vigenereDecode(input, opts.key)) + "\n");
  });

// --- recommend ---
program
  .command("recommend")
  .alias("rec")
  .argument("<type>", "tipo de hash (md5, sha256, bcrypt…)")
  .description("Comando de hashcat/john y estrategia para un tipo de hash")
  .action((type: string) => {
    const r = recommend(type as HashKind);
    if (!r) {
      console.log(pc.yellow(`Sin recomendación para "${type}". Tipos: md5, sha1, sha256, bcrypt…`));
      return;
    }
    console.log(pc.bold(`\nEstrategia para ${pc.cyan(r.kind)}:\n`));
    console.log("  " + r.strategy + "\n");
    console.log(pc.bold("  Comandos (reemplaza HASH por tu hash o archivo):\n"));
    for (const cmd of r.commands) console.log("  " + pc.green("$ ") + cmd);
    console.log();
  });

// --- crack ---
program
  .command("crack")
  .argument("<target>", "hash, o formato user:hash / hash:salt")
  .requiredOption("-w, --wordlist <path>", "ruta a la wordlist (p.ej. rockyou.txt)")
  .option("-t, --type <kind>", "forzar tipo de hash (md5, sha256, ntlm…)")
  .option("-s, --salt <salt>", "salt conocido (prueba prefix y suffix)")
  .option("--salt-mode <mode>", "prefix | suffix (por defecto prueba ambos)")
  .description("Cracking local por diccionario: hashea candidatos y compara")
  .action(
    async (
      target: string,
      opts: { wordlist: string; type?: string; salt?: string; saltMode?: string }
    ) => {
      if (!existsSync(opts.wordlist)) {
        console.log(pc.red(`No existe la wordlist: ${opts.wordlist}`));
        process.exitCode = 1;
        return;
      }

      const parsed = parseTarget(target);
      if (parsed.user) console.log(pc.dim(`Usuario: ${parsed.user}`));
      const salt = opts.salt ?? parsed.salt;

      // Determinar el tipo: explícito, o el mejor candidato crackeable.
      let kind = opts.type as HashKind | undefined;
      if (!kind) {
        const cand = identify(parsed.hash).candidates.find((c) => isCrackable(c.kind));
        kind = cand?.kind;
      }
      if (!kind || !isCrackable(kind)) {
        console.log(
          pc.yellow(
            `No sé crackear este hash localmente. Usa -t <tipo> o prueba con hashcat/john (cipherscope recommend).`
          )
        );
        return;
      }

      console.log(
        pc.bold(`\nCrackeando `) +
          pc.cyan(kind) +
          (salt ? pc.dim(` (salt: ${salt})`) : "") +
          pc.dim(`  wordlist: ${opts.wordlist}\n`)
      );

      const start = Date.now();
      let totalAttempts = 0;
      const BATCH = 50_000;
      let batch: string[] = [];

      const flush = (): ReturnType<typeof crack> | undefined => {
        if (batch.length === 0) return undefined;
        const r = crack(parsed.hash, batch, {
          kind: kind!,
          salt,
          saltMode: opts.saltMode as SaltMode | undefined,
        });
        totalAttempts += r.attempts;
        batch = [];
        return r;
      };

      for await (const word of wordlistLines(opts.wordlist)) {
        batch.push(word);
        if (batch.length >= BATCH) {
          const r = flush();
          if (r?.found) return printCrack(r, parsed, kind, salt, totalAttempts, start);
        }
      }
      const last = flush();
      if (last?.found) return printCrack(last, parsed, kind, salt, totalAttempts, start);

      const secs = ((Date.now() - start) / 1000).toFixed(1);
      console.log(
        pc.red(`✗ No encontrada.`) +
          pc.dim(` ${totalAttempts.toLocaleString()} intentos en ${secs}s\n`)
      );
    }
  );

function printCrack(
  r: ReturnType<typeof crack>,
  parsed: ReturnType<typeof parseTarget>,
  kind: HashKind,
  salt: string | undefined,
  attempts: number,
  start: number
): void {
  const secs = ((Date.now() - start) / 1000).toFixed(2);
  console.log(pc.green(pc.bold(`\n✓ ¡Contraseña encontrada!\n`)));
  if (parsed.user) console.log(`  usuario:    ${pc.cyan(parsed.user)}`);
  console.log(`  contraseña: ${pc.green(pc.bold(r.password ?? ""))}`);
  console.log(pc.dim(`  tipo: ${kind}${salt ? `  salt(${r.saltMode}): ${salt}` : ""}`));
  console.log(pc.dim(`  ${attempts.toLocaleString()} intentos en ${secs}s\n`));
}

// --- analyze (default) ---
program
  .command("analyze", { isDefault: true })
  .argument("[input]", "cualquier cosa: hash, encoding o texto cifrado")
  .description("Todo-en-uno: identifica, decodifica y sugiere el ataque")
  .action((input?: string) => {
    if (!input) {
      program.help();
      return;
    }
    console.log(pc.bold(pc.magenta("\n═══ CipherScope ═══\n")));

    const id = identify(input);
    if (id.candidates.length > 0) {
      console.log(pc.bold("● Identificación:"));
      for (const c of id.candidates.slice(0, 3)) {
        console.log(`  ${bar(c.confidence)} ${c.label}`);
        if (!c.reversible) {
          const rec = recommend(c.kind);
          if (rec) console.log(pc.dim(`    → ${rec.commands[0]}`));
        }
      }
      console.log();
    }

    // Solo mostramos decodificaciones directas cuyo resultado parezca texto
    // real; excluimos rot13/atbash (son conjeturas, no decodificación directa)
    // para que un hash que "también es hex válido" no ensucie la salida.
    const classic = new Set(["rot13", "atbash"]);
    const dec = decodeAll(input).filter(
      ({ decoder, output }) => !classic.has(decoder) && score(output).printable > 0.9
    );
    if (dec.length > 0) {
      console.log(pc.bold("● Decodificación directa:"));
      for (const { decoder, output } of dec) {
        console.log(`  ${pc.cyan(decoder)}: ${pc.green(output.slice(0, 120))}`);
      }
      console.log();
    }

    const mg = magic(input, { limit: 3 });
    if (mg.length > 0 && mg[0] && mg[0].score.total > 0.4) {
      console.log(pc.bold("● Magic (encadenado):"));
      mg.slice(0, 3).forEach((r) => {
        const chain = r.steps.map((s) => s.decoder).join(" → ");
        console.log(`  ${bar(r.score.total)} ${pc.dim(`[${chain}]`)} ${pc.green(r.output.slice(0, 80))}`);
      });
      console.log();
    }

    if (id.candidates.length === 0 && dec.length === 0 && mg.length === 0) {
      console.log(pc.yellow("No encontré nada reconocible. ¿Texto plano ya?\n"));
    }
  });

program.parseAsync(process.argv);
