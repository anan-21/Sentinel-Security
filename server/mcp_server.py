import logging
from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.transport_security import TransportSecuritySettings
from security.engine import scan,report,url_findings,finding
from server.schemas import Report
from server.auth import Guard
import os
Text=Annotated[str,Field(max_length=100000)]
URL=Annotated[str,Field(max_length=4096)]
mcp=FastMCP('Sentinel Security',stateless_http=True,json_response=True,transport_security=TransportSecuritySettings(allowed_hosts=os.environ.get('SENTINEL_ALLOWED_HOSTS','127.0.0.1:*,localhost:*').split(',')))
a=ToolAnnotations(readOnlyHint=True,destructiveHint=False,openWorldHint=False)
@mcp.tool(annotations=a)
def sentinel_scan_message(source: str,sender: Text,subject: Text,body: Text,links: Annotated[list[URL],Field(max_length=50)]=[]) -> Report:
    """Analyze untrusted message content without fetching URLs or saving content."""
    return scan({'sender':sender,'subject':subject,'body':body},links)
@mcp.tool(annotations=a)
def sentinel_scan_url(url: URL) -> Report:
    """Static URL analysis only. No DNS, network requests or threat intelligence."""
    return report(url_findings(url))
@mcp.tool(annotations=a)
def sentinel_scan_webpage(url: URL,text: Text) -> Report:
    """Analyze supplied page text; does not browse or execute content."""
    return scan({'text':text},[url])
@mcp.tool(annotations=a)
def sentinel_scan_action(action: Text,user_goal: Text='') -> Report:
    """Advisory action review, never grants permission or executes actions."""
    r=scan({'action':action})
    import re
    for m in re.finditer(r'transfer|send email|change permissions|转账|发送邮件|修改权限|grant access',action,re.I):
        r.findings.append(finding('sensitive_action','需要 Muse 原生审批；不能据描述认定已获授权','action',action,m.start(),m.end()))
    result=report(r.findings)
    result.uncertainty.append('无法可靠判断操作与用户目标的语义一致性；由 Muse 核对。')
    return result
@mcp.tool(annotations=a)
def sentinel_get_status() -> dict:
    """Service capabilities, not Muse connector discovery or monitoring status."""
    return {'version':'0.1.0','healthy':True,'modules':['message','url','webpage','action'],'network_fetch':False,'content_storage':False,'monitoring':'host-managed; unverified','threat_intelligence':False}
def create_app(): return Guard(mcp.streamable_http_app())
if __name__=='__main__':
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(),host='0.0.0.0',port=8000,access_log=False)
