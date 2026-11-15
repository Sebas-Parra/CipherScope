/**
 * Contrato de plugin. Cada decoder es autocontenido: sabe si puede
 * aplicarse a una entrada y cómo transformarla. El motor Magic solo
 * recorre el registry sin conocer los detalles de cada uno.
 */
export interface Decoder {
  /** Identificador único, p.ej. "base64". */
  name: string;
  /** Descripción corta para el usuario. */
  label: string;
  /** Categoría para la UI/ranking. */
  category: "encoding" | "classic";
  /** ¿El charset/formato de la entrada encaja? Barato, sin decodificar. */
  canApply(input: string): boolean;
  /**
   * Aplica la transformación. Si `canApply` fue true pero la entrada es
   * inválida igualmente, debe lanzar para que el motor lo descarte.
   */
  decode(input: string): string;
}

export class DecodeError extends Error {}
