import { type Decoder, DecodeError } from "./types.js";

const MAP: Record<string, string> = {
  ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
  "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
  "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
  ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
  "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
  "--..": "Z",
  "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
  ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
  ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/", "-....-": "-",
};

export const morseDecoder: Decoder = {
  name: "morse",
  label: "Código Morse",
  category: "encoding",
  canApply(input: string): boolean {
    const t = input.trim();
    return t.length > 0 && /^[.\-/\s]+$/.test(t) && /[.\-]/.test(t);
  },
  decode(input: string): string {
    // Palabras separadas por "/" o por doble espacio; letras por espacio.
    const words = input.trim().split(/\s*\/\s*|\s{2,}/);
    const decoded = words.map((word) =>
      word
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map((sym) => {
          const ch = MAP[sym];
          if (ch === undefined) throw new DecodeError(`símbolo morse desconocido: ${sym}`);
          return ch;
        })
        .join("")
    );
    return decoded.join(" ");
  },
};
