# WorkBuddy 接入

1. 安装 Python 包和 Skill：`uv tool install .`，然后 `sentinel-security install workbuddy`。在客户端重新打开会话，要求“使用 Sentinel，先查询我安装了哪些连接器”。按 WorkBuddy 实际返回的状态区分绑定、启用、授权和可调用。切换账号时重做发现。
2. 如有当前档案的本地 ID，可用 `sentinel-security discover workbuddy --workbuddy-profile <档案ID>`，或在安装时传同一选项。适配 WorkBuddy 5.5.6 的 v4 状态格式，只投影所选档案的服务名及 bound、enabled 标记。无法识别格式则回到会话查询。不要把整个状态文件提供给模型或远程服务。内置商店的可安装服务不能计入自己的连接。
3. 本地 stdio 配置使用上一步安装的可执行文件绝对路径，参数为 `["mcp"]`。在允许设置 MCP 的入口中使用下列结构。普通 WorkBuddy 客户端与它附带的 CodeBuddy CLI 的配置作用域可能不同。

```json
{"mcpServers":{"sentinel-security":{"command":"/absolute/path/to/sentinel-security","args":["mcp"]}}}
```

若使用自己的 HTTPS 服务，仓库的 [connector/](connector/) 是 WorkBuddy Connector Platform 格式的连接器包。填自己的 HTTPS 服务根地址和 Sentinel 专用令牌。已准备提交材料，未上架 WorkBuddy 市场。不要将 GitHub 仓库 URL 填入服务地址。

仅在 **CodeBuddy CLI 专用监控项目** 中，可用 `PreToolUse` 增加[只读工具限制](readonly_hook.py)。以下是 settings 的 hooks 片段；换成真实脚本路径及经过审查的只读工具名。处理器仅在要求拦截时返回 deny；其他调用继续走宿主审批。WorkBuddy 图形客户端是否加载相同设置需按客户端验证。

```json
{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python3 '/absolute/path/to/readonly_hook.py' mcp__sentinel-security__sentinel_scan_prompt mcp__gmail__get_message"}]}]}}
```

[WorkBuddy 连接器规范](https://open.workbuddy.cn/en/docs/connector) · [客户端查询已安装连接器](https://www.workbuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/Connector) · [CodeBuddy CLI Hook 规范](https://www.codebuddy.ai/docs/cli/hooks)
