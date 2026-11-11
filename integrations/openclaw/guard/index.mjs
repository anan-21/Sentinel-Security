import {registerScanners} from "./scanners.mjs";
// Optional enforcement for explicitly named monitoring agents.
// An exact allowlist avoids trusting tool annotations or matching on descriptions.
export default {
  id: "sentinel-readonly-guard",
  name: "Sentinel read-only tool guard",
  register(api) {
    if (api.pluginConfig?.scannerCommand) registerScanners(api,api.pluginConfig.scannerCommand);
    const agentIds = new Set(api.pluginConfig?.agentIds ?? []);
    const allowed = new Set(api.pluginConfig?.allowedTools ?? []);
    api.on("before_tool_call", (event, context) => {
      if (agentIds.has(context.agentId) && !allowed.has(event.toolName)) {
        return { block: true, blockReason: "Sentinel: tool outside this monitoring agent’s allowlist." };
      }
    });
  }
};
