# WorkBuddy 接入

1. 安装 Python 包和 Skill：`uv tool install .`，然后 `sentinel-security install workbuddy`。在客户端重新打开会话，要求“使用 Sentinel，先查询我安装了哪些连接器”。按 WorkBuddy 实际返回的状态区分绑定、启用、授权和可调用。切换账号时重做发现。
2. 如有当前档案的本地 ID，可用 `sentinel-security discover workbuddy --workbuddy-profile <档案ID>`，或在安装时传同一选项。适配 WorkBuddy 5.5.6 的 v4 状态格式，只投影所选档案的服务名及 bound、enabled 标记。无法识别格式则回到会话查询。不要把整个状态文件提供给模型或远程服务。内置商店的可安装服务不能计入自己的连接。
3. 本地 stdio 配置使用上一步安装的可执行文件绝对路径，参数为 `["mcp"]`。在允许设置 MCP 的入口中使用下列结构。普通 WorkBuddy 客户端与它附带的 CodeBuddy CLI 的配置作用域可能不同。

## 首次邮箱配置

`sentinel-security bootstrap workbuddy` 只读检查本机网易邮箱元数据，不查钥匙串，不输出邮箱地址、授权码或邮件。也随安装器提供独立脚本 `scripts/workbuddy_bootstrap.py`，在没有 Sentinel CLI 的宿主里可直接用 Python 运行。

| 情况 | 初始化行为 |
|---|---|
| 本机有「163邮箱助手」账户 | 返回 `reuse_existing`，保留现有账户；验证信息只是上次保存的缓存 |
| 宿主有其他邮箱证据 | `--host-mail-state present` 返回 `verify_existing`，核对原连接，不另建账号 |
| 当前范围未知、文件不可读或格式不识别 | 查询宿主或检查元数据；不把未知当作未连接 |
| 明确无邮箱但没有指定服务商 | 返回 `choose_provider`，由用户选择 |
| 明确无邮箱，用户选择网易 | 加 `--provider netease --configure` 启动本机配置页 |
| 邮件助手未安装 | 返回 `install_mail163`，由当前 Agent 通过 WorkBuddy 原生市场安装，再继续 |
| 已发起配置但尚未保存 | 返回 `setup_pending`，不重复弹窗；明确重试才加 `--retry` |

```sh
sentinel-security bootstrap workbuddy
# 当前宿主已经成功查询，并确认范围内无邮箱；用户已选择网易：
sentinel-security bootstrap workbuddy --host-mail-state none --provider netease --configure
```

本机适配对应 WorkBuddy 市场「163邮箱助手」mail163 1.5.2，自动运行前校验审核过的脚本 SHA-256；不下载、不分发第三方助手代码。助手升级或被修改后，`review_helper` 要求先审核；现有账户不会被覆盖。配置记录读取自当前操作系统用户的 `~/.wb-163-mail/config.json`，与该助手的账户范围一致，不承诺按 WorkBuddy 登录档案隔离这些账户。

Sentinel 在独立 Python 进程里运行该助手，并强制 IMAP TLS 校验证书及主机名。没有修改第三方助手原文件；直接绕过 Sentinel 运行上游脚本时，其行为仍由上游版本决定。

用户在本机页面输入授权码并确认保存。Sentinel 只记录“向导已发起”的本地去重状态，不保存凭据或邮箱地址；清空/取消后明确重试使用 `--retry`。`setup_started` 只证明已启动助手进程，页面可用与真实登录仍需核对。已有本机配置没有有效授权时，应处理原连接，不能用新账户绕过撤权。

Skill 被激活执行才会初始化，宿主仅索引 SKILL.md 时不会启动脚本。仅安装 Skill 不等于有后台监控。远程 MCP 服务无法检查用户电脑的这些文件，也不会在服务端打开用户的浏览器。

## MCP 配置

```json
{"mcpServers":{"sentinel-security":{"command":"/absolute/path/to/sentinel-security","args":["mcp"]}}}
```

若使用自己的 HTTPS 服务，仓库的 [connector/](connector/) 是 WorkBuddy Connector Platform 格式的连接器包。填自己的 HTTPS 服务根地址和 Sentinel 专用令牌。已准备提交材料，未上架 WorkBuddy 市场。不要将 GitHub 仓库 URL 填入服务地址。

仅在 **CodeBuddy CLI 专用监控项目** 中，可用 `PreToolUse` 增加[只读工具限制](readonly_hook.py)。以下是 settings 的 hooks 片段；换成真实脚本路径及经过审查的只读工具名。处理器仅在要求拦截时返回 deny；其他调用继续走宿主审批。WorkBuddy 图形客户端是否加载相同设置需按客户端验证。

```json
{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"python3 '/absolute/path/to/readonly_hook.py' mcp__sentinel-security__sentinel_scan_prompt mcp__gmail__get_message"}]}]}}
```

[WorkBuddy 连接器规范](https://open.workbuddy.cn/en/docs/connector) · [客户端查询已安装连接器](https://www.workbuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/Connector) · [CodeBuddy CLI Hook 规范](https://www.codebuddy.ai/docs/cli/hooks)
