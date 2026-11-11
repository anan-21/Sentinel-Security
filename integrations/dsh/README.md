# DeepSeek Harness 接入

`sentinel-security install dsh` 写入 `$DSH_HOME/skills`（默认 ~/.dsh/skills）。项目级安装使用 `--skills-root /path/to/project/.dsh/skills`。使用受限制的 preset 时，需要在 preset 允许的 skill 目录中安装。直接在 DSH 中要求“加载 sentinel-security，先检查我的通讯连接”。

**MCP**。在自己的目标 profile/preset 挂载以下配置行，把 command 换为安装后的绝对路径。DSH 原生桥为工具加上 `mcp__sentinel__` 前缀。检查当前版本的 profile 分层规则；切勿打印可能含有凭据的整份配置。

```yaml
- id: sentinel-scanner
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: sentinel
    transport: stdio
    command: /absolute/path/to/sentinel-security
    args: [mcp]
```

**原生发现**。可选安装仓库中 [inventory/](inventory/) 本地 npm 包到目标 DSH profile，然后将 `dsh-sentinel-inventory` 挂载为 Cordis 插件。本机 CLI 的形式是 `dsh plugin --profile web add /absolute/path/to/integrations/dsh/inventory`。确认该 profile 使用与宿主相同的 dsh-tools 版本。插件注册 `sentinel_host_tools`，执行时传入真实调用者作用域；没有作用域即报错。仅输出注册名，条件工具还要在当前会话确认可调用。未安装插件时，可直接按当前会话的工具名初始化。

```yaml
- id: sentinel-inventory
  name: dsh-sentinel-inventory
  config: {}
```

**受限会话**。如要对专用监控会话强制限制工具，在该插件的 config 设置 `monitorSessions: ["实际会话ID"]` 及 `allowedTools: ["sentinel_host_tools", "实际只读工具名"]`。使用宿主的单向拒绝 guard；原有审批仍然有效。会话 ID 改变要重新指定。默认不修改其他会话。测试命令 `.venv/bin/python tests/host/run_dsh.py` 使用本机 npm 安装的 DSH 模块、临时配置和合成渠道，验证实际工具执行路径及两会话隔离。

[DSH Skill 加载规则](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/skills.md) · [作用域及执行保护](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md)
