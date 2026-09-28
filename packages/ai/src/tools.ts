import { z } from 'zod';
import type { ReadTool } from './types.js';

/** Define a read-only tool with a typed input. */
export function readTool<Shape extends z.ZodRawShape>(tool: ReadTool<Shape>): ReadTool {
  return tool as unknown as ReadTool;
}

export function toolJsonSchema(tool: ReadTool): Record<string, unknown> {
  const schema = z.toJSONSchema(z.object(tool.input)) as Record<string, unknown>;
  delete schema.$schema;
  return schema;
}

/** Validate arguments from the model before running a tool. Returns text for the model. */
export async function callTool(
  tool: ReadTool,
  rawArgs: unknown,
): Promise<{ ok: boolean; text: string }> {
  const parsed = z.object(tool.input).safeParse(rawArgs ?? {});
  if (!parsed.success) return { ok: false, text: `Invalid arguments: ${parsed.error.message}` };
  try {
    return { ok: true, text: JSON.stringify(await tool.run(parsed.data)) };
  } catch (error) {
    return {
      ok: false,
      text: `Tool failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
