import { type Decoder, DecodeError } from "./types.js";

export const urlDecoder: Decoder = {
  name: "url",
  label: "URL / percent-encoding",
  category: "encoding",
  canApply(input: string): boolean {
    return /%[0-9a-f]{2}/i.test(input) || input.includes("+");
  },
  decode(input: string): string {
    try {
      return decodeURIComponent(input.replace(/\+/g, " "));
    } catch {
      throw new DecodeError("percent-encoding inválido");
    }
  },
};
