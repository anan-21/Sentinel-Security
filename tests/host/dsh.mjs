// Run from a temporary directory containing the installed DSH modules and inventory.mjs.
// Uses synthetic connectors so neither host credentials nor message content are needed.
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import { createScope } from '@deepseek-ai/dsh-scope';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import ToolRuntime, {defineTool} from '@deepseek-ai/dsh-tools';
import {FileSystemSkillProvider} from '@deepseek-ai/dsh-skill-filesystem';
import * as inventory from './inventory.mjs';

const ctx = new Context();
await ctx.plugin(SystemPrompt, {});
await ctx.plugin(ToolRuntime);
await ctx.plugin(inventory,{monitorSessions:["test-a"],allowedTools:["sentinel_host_tools"]});
const signal = new AbortController().signal;
const agents = [{id:'test-a'}, {id:'test-b'}];
for (const [i, agent] of agents.entries()) {
  await ctx.plugin(Object.assign(inner => {
    const scope = createScope(inner, agent);
    scope.ctx.tools.register(defineTool({
      name:i===0?'gmail_read':'slack_read',
      description:'Synthetic read-only connector', parameters:{},
      output:{schema:{type:'string'},render:(_args,value)=>[{type:'text',text:value}]},
      async execute(){throw Error('Discovery attempted a connector read');}
    }));
  },{inject:['tools','systemPrompt']}));
}
for (const [i,agent] of agents.entries()) {
  const result=await ctx.tools.execute({callId:'test'+i, name:'sentinel_host_tools',arguments:{},agent,signal});
  assert.equal(result.isError,false,JSON.stringify(result));
  const names=JSON.parse(result.content[0].text);
  assert.ok(names.includes(i===0?'gmail_read':'slack_read'));
  assert.ok(!names.includes(i===0?'slack_read':'gmail_read'));
}
const denied = await ctx.tools.execute({callId:"deny",name:"gmail_read",arguments:{},agent:agents[0],signal});
assert.equal(denied.isError,true);
assert.ok(denied.content[0].text.includes("outside the monitoring session"));
const provider = new FileSystemSkillProvider(ctx,{signal,invalidate(){}},{includeDefaultRoots:false,customSkillDirs:[process.cwd()+'/skills'],watch:false});
const list = await provider.list({});
const candidate=(list.candidates??list).find(x=>x.name==='sentinel-security');
assert.ok(candidate);
assert.ok((await provider.get(candidate,{signal})).content.includes('sentinel_scan_prompt'));
await provider.dispose();
console.log('DSH filesystem skill and scoped tool dispatch: passed');
