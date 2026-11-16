"use client";

import { useEffect, useState, useTransition } from "react";
import {
  analyze,
  crackHash,
  bruteForceHash,
  lookupOnline,
  type AnalyzeResponse,
  type CrackResponse,
} from "./actions";

const HISTORY_KEY = "cipherscope.history";
const DEFAULT_WORDLIST = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt";

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [pending, startTransition] = useTransition();

  // --- estado del panel de cracking ---
  const [crackForm, setCrackForm] = useState({
    hash: "",
    type: "",
    salt: "",
    wordlist: DEFAULT_WORDLIST,
  });
  const [crackResult, setCrackResult] = useState<CrackResponse | null>(null);
  const [cracking, startCrack] = useTransition();
  const [bruteCfg, setBruteCfg] = useState({ charset: "lower+digits", maxLen: 5 });

  function runCrack() {
    if (!crackForm.hash.trim()) return;
    setCrackResult(null);
    startCrack(async () => {
      const res = await crackHash({
        hash: crackForm.hash,
        type: crackForm.type || undefined,
        salt: crackForm.salt || undefined,
        wordlist: crackForm.wordlist || undefined,
      });
      setCrackResult(res);
    });
  }

  function runBrute() {
    if (!crackForm.hash.trim()) return;
    setCrackResult(null);
    startCrack(async () => {
      const res = await bruteForceHash({
        hash: crackForm.hash,
        type: crackForm.type || undefined,
        charset: bruteCfg.charset,
        maxLen: bruteCfg.maxLen,
      });
      setCrackResult(res);
    });
  }

  function runLookup() {
    if (!crackForm.hash.trim()) return;
    setCrackResult(null);
    startCrack(async () => {
      const res = await lookupOnline({
        hash: crackForm.hash,
        type: crackForm.type || undefined,
      });
      setCrackResult(res);
    });
  }

  useEffect(() => {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch {
      /* localStorage no disponible */
    }
  }, []);

  function pushHistory(value: string) {
    setHistory((prev) => {
      const next = [value, ...prev.filter((h) => h !== value)].slice(0, 12);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  function run(value: string) {
    const v = value.trim();
    if (!v) return;
    startTransition(async () => {
      const res = await analyze(v);
      setResult(res);
      pushHistory(v);
    });
  }

  function clearHistory() {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch {
      /* ignore */
    }
  }

  const hasResults =
    result &&
    (result.candidates.length ||
      result.decodings.length ||
      result.magic.length ||
      result.caesar.length ||
      result.warning);

  return (
    <div className="wrap">
      <header>
        <h1>
          Cipher<span className="scope">Scope</span>
        </h1>
        <p>Pega un hash, un encoding o un texto cifrado. Te digo qué es y cómo resolverlo.</p>
      </header>

      <textarea
        className="mono"
        placeholder="p.ej. 5f4dcc3b5aa765d61d8327deb882cf99  ·  SGVsbG8=  ·  Khoor Zruog"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(input);
        }}
      />
      <div className="row">
        <button onClick={() => run(input)} disabled={pending || !input.trim()}>
          {pending ? "Analizando…" : "Analizar  (⌘/Ctrl+↵)"}
        </button>
        <button
          className="ghost"
          onClick={() => {
            setInput("");
            setResult(null);
          }}
        >
          Limpiar
        </button>
      </div>

      {result && !hasResults && (
        <div className="card">
          <span className="muted">
            No encontré nada reconocible. ¿Quizá ya es texto plano?
          </span>
        </div>
      )}

      {result?.warning && (
        <div className="card">
          <h2>⚠ Hash malformado</h2>
          <div className="badhash">
            <strong>{result.warning.label}</strong> — digest de{" "}
            <strong>{result.warning.actual}</strong> caracteres (se esperan{" "}
            <strong>{result.warning.expected}</strong>).
          </div>
          <div className="muted" style={{ fontSize: "0.9rem", marginTop: 6 }}>
            {result.warning.message}
          </div>
          <div className="muted" style={{ fontSize: "0.82rem", marginTop: 6 }}>
            hashcat/john lo rechazarían con <span className="mono">Token length exception</span>.
          </div>
        </div>
      )}

      {result?.candidates.length ? (
        <div className="card">
          <h2>Identificación</h2>
          {result.candidates.map((c) => (
            <div key={c.kind}>
              <div className="candidate">
                <div className="bar">
                  <span style={{ width: `${Math.round(c.confidence * 100)}%` }} />
                </div>
                <strong>{c.label}</strong>
                <span className={`tag ${c.reversible ? "rev" : "oneway"}`}>
                  {c.reversible ? "reversible" : "una sola vía"}
                </span>
              </div>
              {c.note && <div className="muted" style={{ fontSize: "0.85rem" }}>{c.note}</div>}
              {c.noShortcut && (
                <div className="noshortcut">
                  🔒 Este hash <strong>no se puede crackear online ni por fuerza bruta</strong> (salt
                  + coste alto, por diseño). La vía es hashcat
                  {c.mode !== undefined ? ` con modo -m ${c.mode}` : ""} + diccionario:
                </div>
              )}
              {c.command && <div className="cmd mono">$ {c.command}</div>}
              {c.constructions && (
                <details className="ctor">
                  <summary>
                    ¿Te dieron un <strong>salt</strong> aparte? Prueba estas construcciones →
                  </summary>
                  <table className="ctor-table mono">
                    <thead>
                      <tr>
                        <th>-m</th>
                        <th>construcción</th>
                      </tr>
                    </thead>
                    <tbody>
                      {c.constructions.map((x) => {
                        const salt = crackForm.salt.trim() || "SALT";
                        const needsSalt = x.mode !== c.constructions![0].mode; // el plano no lleva salt
                        const target = needsSalt ? `${result.input}:${salt}` : result.input;
                        const cmd = `echo '${target}' > h.txt; hashcat -m ${x.mode} -a 0 h.txt ${DEFAULT_WORDLIST}`;
                        return (
                          <tr key={x.mode}>
                            <td className="ctor-mode">{x.mode}</td>
                            <td>
                              <div>
                                {x.formula}
                                <span className="ctor-label"> — {x.label}</span>
                              </div>
                              <div className="cmd mono ctor-cmd">$ {cmd}</div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  <div className="muted" style={{ fontSize: "0.78rem", marginTop: 6 }}>
                    Los modos con salt usan el formato <span className="mono">hash:salt</span> (el
                    plano no lleva salt). Escribe tu salt en el campo del panel de abajo y los
                    comandos se actualizan solos. Pruébalas en orden hasta que una recupere la
                    contraseña; si todas dan <span className="mono">Exhausted</span>, repite con{" "}
                    <span className="mono">-r /usr/share/hashcat/rules/best66.rule</span>.
                  </div>
                </details>
              )}
            </div>
          ))}
        </div>
      ) : null}

      {result?.decodings.length ? (
        <div className="card">
          <h2>Decodificación directa</h2>
          <div className="kv">
            {result.decodings.map((d, i) => (
              <div key={i} style={{ display: "contents" }}>
                <span className="k mono">{d.decoder}</span>
                <span className="out mono">{d.output}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {result?.magic.length ? (
        <div className="card">
          <h2>Magic · encadenado</h2>
          <ul>
            {result.magic.map((m, i) => (
              <li key={i} style={{ padding: "6px 0" }}>
                <div className="candidate">
                  <div className="bar">
                    <span style={{ width: `${m.score}%` }} />
                  </div>
                  <span className="muted mono" style={{ fontSize: "0.8rem" }}>
                    [{m.chain}]
                  </span>
                </div>
                <div className="out mono">{m.output}</div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {result?.caesar.length ? (
        <details className="card">
          <summary style={{ cursor: "pointer", color: "var(--muted)" }}>
            César · 25 desplazamientos
          </summary>
          <div className="grid2 mono" style={{ marginTop: 12, fontSize: "0.85rem" }}>
            {result.caesar.map((r) => (
              <div key={r.shift}>
                <span className="muted">+{r.shift}</span> {r.text.slice(0, 60)}
              </div>
            ))}
          </div>
        </details>
      ) : null}

      <div className="card">
        <h2>Crack · diccionario (rockyou)</h2>
        <input
          className="mono field"
          placeholder="hash  ·  user:hash  ·  hash:salt"
          value={crackForm.hash}
          onChange={(e) => setCrackForm({ ...crackForm, hash: e.target.value })}
        />
        <div className="row3">
          <input
            className="mono field"
            placeholder="tipo (auto): md5, sha256, ntlm…"
            value={crackForm.type}
            onChange={(e) => setCrackForm({ ...crackForm, type: e.target.value })}
          />
          <input
            className="mono field"
            placeholder="salt (opcional)"
            value={crackForm.salt}
            onChange={(e) => setCrackForm({ ...crackForm, salt: e.target.value })}
          />
        </div>
        <input
          className="mono field"
          value={crackForm.wordlist}
          onChange={(e) => setCrackForm({ ...crackForm, wordlist: e.target.value })}
          title="Ruta de la wordlist en el servidor"
        />
        {/^\$2[abxy]?\$/.test(crackForm.hash.trim()) ||
        /^(bcrypt|argon2)/i.test(crackForm.type.trim()) ? (
          <div className="cmd mono" style={{ color: "var(--yellow)" }}>
            ⚠ bcrypt es lento por diseño: usa una wordlist pequeña (p.ej.
            <br />
            /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt). Tope: 5.000 intentos.
          </div>
        ) : null}
        <div className="row">
          <button onClick={runCrack} disabled={cracking || !crackForm.hash.trim()}>
            {cracking ? "Trabajando…" : "Crackear (diccionario)"}
          </button>
          <button className="ghost" onClick={runBrute} disabled={cracking || !crackForm.hash.trim()}>
            ⚡ Fuerza bruta
          </button>
          <button className="ghost" onClick={runLookup} disabled={cracking || !crackForm.hash.trim()}>
            🌐 Buscar online
          </button>
        </div>

        <div className="row3" style={{ marginTop: 8 }}>
          <label className="mono" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
            charset fuerza bruta
            <select
              className="field"
              value={bruteCfg.charset}
              onChange={(e) => setBruteCfg({ ...bruteCfg, charset: e.target.value })}
            >
              <option value="digits">solo dígitos (0-9)</option>
              <option value="lower">minúsculas (a-z)</option>
              <option value="lower+digits">minúsculas + dígitos</option>
              <option value="alnum">alfanumérico (a-z A-Z 0-9)</option>
              <option value="alnum+symbols">alfanumérico + símbolos</option>
            </select>
          </label>
          <label className="mono" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
            longitud máx. ({bruteCfg.maxLen})
            <input
              className="field"
              type="range"
              min={1}
              max={7}
              value={bruteCfg.maxLen}
              onChange={(e) => setBruteCfg({ ...bruteCfg, maxLen: Number(e.target.value) })}
            />
          </label>
        </div>
        <div className="muted mono" style={{ fontSize: "0.72rem", marginTop: 4 }}>
          ⚡ fuerza bruta: sin wordlist, solo contraseñas cortas (tope 15s) ·
          🌐 online: envía el hash a un servicio público (MD5)
        </div>

        {crackResult?.error && (
          <div className="mono" style={{ color: "var(--yellow)", marginTop: 12 }}>
            {crackResult.error}
          </div>
        )}

        {crackResult?.found && (
          <div style={{ marginTop: 14 }} className="kv">
            <span className="k">resultado</span>
            <span className="out mono" style={{ fontWeight: 700 }}>
              ✓ {crackResult.password}
            </span>
            {crackResult.user && (
              <>
                <span className="k">usuario</span>
                <span className="mono">{crackResult.user}</span>
              </>
            )}
            <span className="k">tipo</span>
            <span className="mono muted">
              {crackResult.kind}
              {crackResult.saltMode ? ` · salt(${crackResult.saltMode})` : ""}
            </span>
            <span className="k">intentos</span>
            <span className="mono muted">
              {crackResult.attempts.toLocaleString()} en {crackResult.seconds.toFixed(2)}s
            </span>
            {crackResult.source && (
              <>
                <span className="k">método</span>
                <span className="mono muted">{crackResult.source}</span>
              </>
            )}
          </div>
        )}

        {crackResult && !crackResult.found && !crackResult.error && (
          <div className="muted mono" style={{ marginTop: 14 }}>
            ✗ No encontrada · {crackResult.attempts.toLocaleString()} intentos en{" "}
            {crackResult.seconds.toFixed(1)}s
            {crackResult.capped && (
              <span style={{ color: "var(--yellow)" }}>
                {" "}
                (detenido por tiempo{crackResult.source ? ` · ${crackResult.source}` : ""})
              </span>
            )}
            {crackResult.exhausted && (
              <span style={{ color: "var(--yellow)" }}>
                {" "}
                (probé TODO el espacio{crackResult.source ? ` · ${crackResult.source}` : ""} → la
                contraseña es más larga o usa otros caracteres)
              </span>
            )}
          </div>
        )}

        {/* Plan de ataque: aparece cuando NO se crackeó en local */}
        {crackResult && !crackResult.found && crackResult.plan?.length ? (
          <div style={{ marginTop: 16, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
            <h2 style={{ marginBottom: 8 }}>Pasos para crackearlo con rockyou</h2>
            {crackResult.strategy && (
              <div className="muted" style={{ fontSize: "0.85rem", marginBottom: 12 }}>
                {crackResult.strategy}
              </div>
            )}
            <ol className="plan">
              {crackResult.plan.map((p) => (
                <li key={p.n}>
                  <div className="muted" style={{ fontSize: "0.8rem" }}>
                    {p.n}. {p.title}
                  </div>
                  <div className="cmd mono">$ {p.cmd}</div>
                </li>
              ))}
            </ol>
          </div>
        ) : null}
      </div>

      {history.length > 0 && (
        <div className="card">
          <h2>
            Historial de sesión
            <button
              className="ghost"
              onClick={clearHistory}
              style={{ float: "right", padding: "2px 10px", fontSize: "0.75rem" }}
            >
              borrar
            </button>
          </h2>
          <ul className="history mono">
            {history.map((h, i) => (
              <li
                key={i}
                onClick={() => {
                  setInput(h);
                  run(h);
                }}
              >
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {h}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
