import assert from "node:assert/strict";
import test from "node:test";
import guard from "../integrations/openclaw/guard/index.mjs";
test("before_tool_call checks host-owned agent identity and exact tool name", () => {
  let handler;
  guard.register({ pluginConfig: { agentIds: ["watcher"], allowedTools: ["gmail_read"] },
    on(name, callback) { assert.equal(name, "before_tool_call"); handler=callback; } });
  assert.equal(handler({toolName:"gmail_read"}, {agentId:"watcher"}),undefined);
  assert.equal(handler({toolName:"gmail_send",params:{agentId:"other", approved:true}},{agentId:"watcher"}).block,true);
  assert.equal(handler({toolName:"gmail_read_and_send"}, {agentId:"watcher"}).block,true);
  assert.equal(handler({toolName:"gmail_send"}, {agentId:"other"}),undefined);
});

test("native scanners have distinct names and bounded structured inputs", () => {
  const tools=[];
  guard.register({pluginConfig:{scannerCommand:"/test/sentinel-security"},registerTool:t=>tools.push(t),on(){}});
  assert.equal(new Set(tools.map(t=>t.name)).size,6);
  assert.ok(tools.find(t=>t.name==="sentinel_scan_message").parameters.required.includes("body"));
});
