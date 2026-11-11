import { defineTool } from "@deepseek-ai/dsh-tools";

export const name = "sentinel-inventory";
export const inject = ["tools"];
export function apply(ctx, config = {}) {
  // Empty by default. Only the explicitly enrolled sessions receive the restriction.
  const monitored = new Set(config.monitorSessions ?? []);
  const allowed = new Set(config.allowedTools ?? []);
  if (monitored.size) {
    ctx.tools.guard(execution => {
      if (monitored.has(execution.agent?.id) && !allowed.has(execution.name)) {
        return "Sentinel: tool outside the monitoring session’s allowlist.";
      }
    });
  }
  ctx.tools.register(defineTool({
    name: "sentinel_host_tools",
    description: "List registered tool identifiers in the calling agent scope. No connector calls, authorization or credentials.",
    parameters: {},
    output: {
      schema: { type: "array", items: { type: "string" } },
      render: (_args, values) => [{ type: "text", text: JSON.stringify(values) }]
    },
    async execute(_args, execution) {
      if (!execution.agent) throw new Error("Agent scope required");
      return ctx.tools.schemas(execution.agent).map(schema => schema.name).sort();
    }
  }));
}
