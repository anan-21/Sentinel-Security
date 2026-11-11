# 适配依据（2026-11-11）

| 一手来源 | 使用方式 |
|---|---|
| [TencentCloudBase/skills](https://github.com/TencentCloudBase/skills) | 参考可独立分发的 SKILL.md 包布局，Sentinel 的流程和规则自行编写 |
| [WorkBuddy Connector 规范](https://open.workbuddy.cn/en/docs/connector) | 独立连接器包、HTTPS Streamable HTTP、token-schema 和本地 stdio |
| [WorkBuddy 已安装连接器查询](https://www.workbuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/Connector) | 使用个人 Agent 当前可见清单；市场可安装项不能当成当前连接 |
| [OpenClaw 渠道命令源代码](https://github.com/openclaw/openclaw/blob/main/src/commands/channels/list.ts) | 从 JSON 的 chat 字段提取配置证据。实测旧版返回账号列表，新版源代码区分 configured/available/installable |
| [OpenClaw 工具钩子](https://github.com/openclaw/openclaw/blob/main/src/plugins/hooks.ts) | before_tool_call 使用宿主提供的 agentId 决定是否执行监控清单 |
| [DeepSeek Harness 工具注册表](https://github.com/deepseek-ai/deepseek-harness/tree/master/packages/core/tools) | 为当前 Agent 取 schemas(scope)，注册原生工具并用 guard 拒绝选定会话中的越界操作 |
| [DSH 技能子系统](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/skills.md) | 复用宿主文件系统 provider 和 preset 作用域 |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | 借鉴把正常任务、工具返回中夹带的攻击和后续动作分别验证的思路。本项目使用自定义合成样本，未声称通过该基准 |
| [ProtectAI LLM Guard](https://github.com/protectai/llm-guard) | 考察输入分类器；首版保持本地静态规则，无需下载模型或发送邮件给模型 |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) | 实际使用官方 SDK 的 stdio 与 Streamable HTTP 传输 |
| [Meta Muse 安全架构](https://muse.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse) | 由 Muse 自己掌管账号、后台运行及审批，外部服务只做风险分析 |

官网指南之外，本机 WorkBuddy 5.5.6 的安装包显示 v4 连接器记录保存 bound/enabled；适配器只对显式选定的档案投影这两个布尔值。v4 不保证有完整的解绑历史，旧版镜像也不作为当前状态依据。服务端没有权限枚举其他 MCP 服务器。
