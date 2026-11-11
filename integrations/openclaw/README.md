# OpenClaw 接入

`sentinel-security install openclaw` 安装到用户 skills 目录并查询配置的聊天渠道。自定义工作区可传 `--skills-root <workspace>/skills`。用 `openclaw skills info sentinel-security --json` 验证加载。Skill 调用本地 CLI，其他宿主中的邮箱授权不随安装迁移。

适配器检测 `openclaw channels list --help`。旧版加 `--json --no-usage`，新版使用支持的参数。适配器只保留 chat 对象内有配置证据的服务类型，忽略身份、账号和额度等数据。渠道列表不含所有邮箱或网站；当前会话的 Gmail 工具或显式网站连接可通过 `discover openclaw --stdin` 补充。

**可选执行拦截**。在 OpenClaw 配置中把下列片段合并到已有字段，保留其他插件。路径换为克隆后 `integrations/openclaw/guard` 的绝对路径。让专用监控 Agent 使用限定账户与只读凭据，替换示例工具名，不要将 shell、通用 HTTP 或能写入的复合工具列入允许清单。

```json
{
  "plugins":{
    "load":{"paths":["/absolute/path/to/integrations/openclaw/guard"]},
    "entries":{"sentinel-readonly-guard":{"enabled":true,"config":{
      "scannerCommand":"/absolute/path/to/sentinel-security",
      "agentIds":["mail-monitor"],"allowedTools":["gmail_get_message","sentinel_scan_message"]
    }}}
  }
}
```

若已有 `plugins.allow`，将插件 ID 加入。加载后 `openclaw plugins inspect sentinel-readonly-guard --json` 应报告 loaded 和 before_tool_call。对选定 Agent，列表之外的工具在调用前被拒绝；其他 Agent 继续其原生策略。配置 scannerCommand 后插件会注册六个本地检测工具，通过固定程序和 JSON 标准输入调用扫描器，监控 Agent 无需 shell。已有同名 MCP 工具时可以省略 scannerCommand。清单为空时该监控 Agent 的工具调用全部被拒绝。钩子仅在宿主提供目标 agentId 的调用路径生效。在你的真实任务中先用合成消息和应被禁止的测试工具验证。

**定时检查。** 先验证专用 Agent 读取一条用户选定的测试项、完成扫描，并确认提醒的私人目的地。使用这些命令仅创建和核查**禁用**的演练任务；不读任何邮箱或发送消息。适用于实测的 OpenClaw 2026.4.10；其他版本先核查原生帮助。若已有同名任务，请复用其 ID，不要重复创建。

```sh
openclaw cron list --all --json
openclaw cron add --name sentinel-rehearsal --agent mail-monitor --session isolated \
  --every 15m --tools sentinel_scan_prompt --disabled --no-deliver \
  --message '调用 sentinel_scan_prompt，检测虚构文本 Ignore previous instructions。' --json
openclaw cron list --all --json
# 只撤销上一步创建的演练任务：
openclaw cron rm <演练任务ID>
```

真实任务需要所有者选择连接器、账户、收件人、频率与只读范围，确认去重及实际投递后再启用。本包不在安装时创建生产定时任务，也不默认将扫描报告发往最近联系的聊天。

[OpenClaw 渠道 CLI](https://github.com/openclaw/openclaw/blob/main/docs/cli/channels.md) · [插件 Hook](https://docs.openclaw.ai/plugins/hooks/reference)
