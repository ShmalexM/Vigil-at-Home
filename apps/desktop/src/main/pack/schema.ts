// Tools offered to a dog are described by JSON Schema (MCP's format), but
// @vigil/ai's tools take a zod shape. This turns the common parts of a JSON
// Schema object into one: primitive types, enums, arrays and nested objects,
// with descriptions. Anything it doesn't know becomes "any value" and is left
// for the tool's own server to check.

import { z } from 'zod';

type Json = Record<string, unknown>;

export function shapeFromJsonSchema(schema: unknown): z.ZodRawShape {
  const s = (schema ?? {}) as Json;
  const props = (s['properties'] ?? {}) as Record<string, Json>;
  const required = new Set(Array.isArray(s['required']) ? (s['required'] as string[]) : []);
  const shape: Record<string, z.ZodType> = {};
  for (const [name, prop] of Object.entries(props).slice(0, 64)) {
    const t = toZod(prop, 0);
    shape[name] = required.has(name) ? t : t.optional();
  }
  return shape;
}

function toZod(p: Json, depth: number): z.ZodType {
  const described = (t: z.ZodType) =>
    typeof p['description'] === 'string'
      ? t.describe((p['description'] as string).slice(0, 500))
      : t;
  if (depth > 4) return described(z.any());
  if (
    Array.isArray(p['enum']) &&
    p['enum'].every((v) => typeof v === 'string') &&
    p['enum'].length > 0
  )
    return described(z.enum(p['enum'] as [string, ...string[]]));
  const type = Array.isArray(p['type'])
    ? (p['type'] as string[]).find((t) => t !== 'null')
    : p['type'];
  switch (type) {
    case 'string':
      return described(z.string());
    case 'integer':
      return described(z.number().int());
    case 'number':
      return described(z.number());
    case 'boolean':
      return described(z.boolean());
    case 'array':
      return described(z.array(p['items'] ? toZod(p['items'] as Json, depth + 1) : z.any()));
    case 'object':
      return described(z.object(shapeFromJsonSchema(p)).passthrough());
    default:
      return described(z.any());
  }
}
