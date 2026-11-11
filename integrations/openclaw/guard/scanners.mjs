// Each call starts the administrator-selected local CLI. Arguments and stdin
// are independent, and untrusted message text never becomes a shell program.
import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";

const string = { type: "string", maxLength: 100000 };
const url = { type: "string", maxLength: 4096 };
const operations = ["read","search","navigate","send","write","delete","execute","change_permissions","transfer","disclose_secret","unknown"];
const operation = {type:"string",enum:operations};
const definitions = [
  ["sentinel_scan_prompt","prompt","Scan untrusted text for instructions and deception.",{text:string},["text"]],
  ["sentinel_scan_message","message","Scan an authorized message with local rules.",{
    source:string, sender:string, subject:string, body:string, links:{type:"array",maxItems:50,items:url}
  },["source","sender","subject","body"]],
  ["sentinel_scan_webpage","webpage","Scan supplied webpage text and URL without browsing.",{url,text:string},["url","text"]],
  ["sentinel_scan_url","url","Check a URL without making a network request.",{url},["url"]],
  ["sentinel_scan_action","action","Review a proposed operation and its user goal.",{action:string,user_goal:string},["action"]],
  ["sentinel_review_tool_call","tool-call","Review origin and task scope; does not grant authority.",{
    origin:{type:"string",enum:["user","host_task","external_content","unknown"]},operation,
    allowed_operations:{type:"array",maxItems:16,items:operation}
  },["origin","operation","allowed_operations"]]
];

export function localScan(command, kind, args, signal) {
  if (!isAbsolute(command)) throw Error("Configure an absolute sentinel-security executable path.");
  const payload = Buffer.from(JSON.stringify(args));
  if (payload.length > 262144) throw Error("Sentinel: input too large.");
  return new Promise((resolve,reject) => {
    const child = spawn(command, ["scan",kind], {
      shell:false, stdio:["pipe","pipe","ignore"], signal, timeout:15000, killSignal:"SIGKILL"
    });
    const chunks=[];
    let bytes=0;
    child.once("error",()=>reject(Error("Sentinel: scanner unavailable.")));
    child.stdin.on("error",()=>reject(Error("Sentinel: input rejected.")));
    child.stdout.on("data",chunk=>{
      bytes+=chunk.length;
      if (bytes>1048576) { child.kill("SIGKILL"); return; }
      chunks.push(chunk);
    });
    child.once("close",code=>{
      if (code!==0 || bytes>1048576) return reject(Error("Sentinel: local scan failed."));
      try {
        const value=JSON.parse(Buffer.concat(chunks).toString("utf8"));
        resolve({content:[{type:"text",text:JSON.stringify(value)}],details:value});
      } catch { reject(Error("Sentinel: invalid scanner response.")); }
    });
    child.stdin.end(payload);
  });
}

export function registerScanners(api, command) {
  if (!isAbsolute(command)) throw Error("Sentinel: scannerCommand must be absolute.");
  for (const [name, kind, description, properties, required] of definitions) {
    api.registerTool({name, description, parameters:{type:"object",properties,required,additionalProperties:false},
      execute:(_callId, args, signal) => localScan(command,kind,args,signal)});
  }
}
