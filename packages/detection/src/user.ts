/**
 * Entry point for the app's UI layer only. Do not import this from anything
 * the AI agent can reach (MCP tool handlers, subscription adapters).
 */
export { mintUserOrigin as userOrigin, type UserOrigin } from "./origin.js";
