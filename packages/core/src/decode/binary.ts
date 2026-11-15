import { type Decoder, DecodeError } from "./types.js";

export const binaryDecoder: Decoder = {
  name: "binary",
  label: "Binario (8 bits)",
  category: "encoding",
  canApply(input: string): boolean {
    const groups = input.trim().split(/\s+/);
    return groups.length > 0 && groups.every((g) => /^[01]{8}$/.test(g));
  },
  decode(input: string): string {
    const groups = input.trim().split(/\s+/);
    const bytes = groups.map((g) => {
      if (!/^[01]{8}$/.test(g)) throw new DecodeError(`grupo binario inválido: ${g}`);
      return parseInt(g, 2);
    });
    return Buffer.from(bytes).toString("utf8");
  },
};
