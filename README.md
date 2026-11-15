# CipherScope

> Navaja suiza de criptoanálisis para CTF: detecta automáticamente hashes y codificaciones, encadena transformaciones y te guía (o ejecuta) el ataque.

**Estado:** 🚧 En desarrollo · **Autor:** Sebastian Parra

---

## ¿Qué es?

CipherScope recibe cualquier texto "cifrado" o un hash y responde dos preguntas:

1. **¿Qué es esto?** — identifica el tipo (MD5, SHA-256, bcrypt, Base64, Hex, César, Vigenère…).
2. **¿Cómo lo resuelvo?** — decodifica lo reversible al instante, o te entrega los pasos/comando exacto para crackear lo que es de una sola vía.

La idea no es "romper toda la criptografía" (imposible por diseño), sino **automatizar la parte aburrida**: reconocer el formato y saber qué atacar primero. Justo lo que se repite en cada reto de CTF.

---

## Conceptos clave (y por qué importan)

CipherScope distingue tres mundos que la gente suele confundir:

| Categoría | Ejemplos | ¿Reversible? | Qué hace CipherScope |
|---|---|---|---|
| **Encoding** | Base64, Base32, Hex, URL, binario, Morse | Sí, sin llave | Decodifica directo |
| **Cifrado clásico** | César/ROT13, Atbash, Vigenère, sustitución | Sí, con llave o análisis | Decodifica / ataca por frecuencia |
| **Hash** | MD5, SHA-1/256/512, NTLM, bcrypt | No (una sola vía) | Identifica + guía/ejecuta cracking |

> Un hash **no se descifra**: solo se intenta adivinar la entrada por diccionario o fuerza bruta. CipherScope lo deja claro en vez de prometer magia.

---

## Funcionalidades

### v1 — Núcleo
- [x] **Identificador de hashes** por patrón (longitud, charset, prefijo) con lista de candidatos rankeada por probabilidad.
- [x] **Decodificador de encodings** (Base64/32, Hex, URL, binario, Morse).
- [x] **Tabla de recomendaciones**: por cada tipo, el modo de `hashcat`/`john`, la estrategia y el comando listo para copiar.

### v2 — Magic (el diferenciador)
- [x] **Auto-detección en cadena**: prueba transformaciones encadenadas (ej. Base64 → Hex → ROT13) y rankea por "legibilidad" del resultado.
- [x] **Scoring de legibilidad**: ratio de caracteres imprimibles + coincidencia con diccionario de palabras comunes.
- [x] **Cifrados clásicos**: César (fuerza bruta de 25 shifts), Atbash, Vigenère (con llave), análisis de frecuencia.

### v3 — Ataque integrado
- [ ] **Cracking local por diccionario** (rockyou y wordlists propias): hashea candidatos y compara.
- [ ] Soporte de **salts** y formatos `user:hash`.
- [ ] Interfaz web en Next.js con historial de la sesión.

---

## Uso (CLI)

```bash
pnpm install
pnpm --filter @cipherscope/core build
pnpm --filter @cipherscope/cli build

# Todo-en-uno: identifica, decodifica y sugiere ataque
node packages/cli/dist/index.js "<entrada>"

# Comandos específicos
cipherscope identify 5f4dcc3b5aa765d61d8327deb882cf99   # → MD5 / NTLM / MD4
cipherscope decode SGVsbG8=                              # → Hello
cipherscope magic <texto>                                # encadenado Base64→ROT13→…
cipherscope caesar "Khoor Zruog"                         # 25 shifts
cipherscope vigenere <texto> -k lemon                    # descifra con llave
cipherscope recommend bcrypt                             # comando hashcat/john
```

> Durante el desarrollo usa `node packages/cli/dist/index.js <cmd>`. Tras
> `pnpm link --global` (o `npm i -g`) tendrás el binario `cipherscope`.

## Arquitectura

Monorepo con un **core agnóstico** reutilizado por la CLI y la web.

```
cipherscope/
├── packages/
│   ├── core/                 # Lógica pura, sin I/O. Testeable al 100%.
│   │   ├── identify/         # Detección de hashes
│   │   │   ├── signatures.ts # Tabla: regex + metadatos por tipo
│   │   │   └── identify.ts   # Devuelve candidatos rankeados
│   │   ├── decode/           # Decoders reversibles
│   │   │   ├── registry.ts   # Cada decoder es un "plugin"
│   │   │   ├── base64.ts
│   │   │   ├── hex.ts
│   │   │   ├── morse.ts
│   │   │   └── classic/      # César, Vigenère, Atbash…
│   │   ├── magic/            # Motor de detección en cadena
│   │   │   ├── scorer.ts     # Puntúa legibilidad
│   │   │   └── magic.ts      # BFS/DFS sobre transformaciones
│   │   ├── crack/            # Ataques de diccionario (v3)
│   │   └── recommend/        # tipo de hash → comando + estrategia
│   │
│   ├── cli/                  # Interfaz de terminal (commander)
│   └── web/                  # Next.js — portafolio + uso real
│
├── wordlists/                # Diccionarios (no versionar los grandes)
└── package.json              # pnpm workspaces
```

### Principio de diseño: cada decoder es un plugin

Un decoder cumple un contrato simple, así agregar uno nuevo no toca el motor:

```ts
interface Decoder {
  name: string;                      // "base64"
  canApply(input: string): boolean;  // ¿el charset/formato encaja?
  decode(input: string): string;     // la transformación
}
```

El motor **Magic** solo recorre el `registry`, aplica los decoders aplicables y puntúa. Desacoplado y extensible.

---

## Stack

- **Lenguaje:** TypeScript (core compartido entre CLI y web)
- **CLI:** Node.js + commander
- **Web:** Next.js + React
- **Tests:** Vitest sobre `core` (es lógica pura → fácil de cubrir)
- **Monorepo:** pnpm workspaces

---

## Roadmap

1. `core/identify` + tabla de firmas → CLI mínima que diga "esto es X".
2. `core/decode` con 3-4 encodings → integrar a la CLI.
3. `core/magic` + scorer → la función estrella.
4. Web en Next.js reusando el core.
5. `core/crack` con diccionario local.

---

## Aviso

Herramienta educativa y para CTF. Úsala solo sobre datos propios o en entornos autorizados.