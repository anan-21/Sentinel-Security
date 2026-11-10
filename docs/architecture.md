# 架构与调研（2026-11-10）
Muse 授权连接器 → Muse 最小化内容 → HTTPS/Bearer → 官方 MCP SDK → 无网络静态检测 → 结构化证据 → Muse 原生通知。

官方安全文章明确 VM 支持自定义技能与 crons；这纠正早期调研中缺乏证据的部分，但没有提供所有后台 API 的调用契约。官方帮助明确允许请求 Custom Connector、邮件搜索、部分连接器主动事件。没有据此证明 Gmail 后台读取、WhatsApp 全量消息、用户自定义 SKILL.md 永久安装或全工具枚举。

来源：
- https://muse.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse
- https://platform.muse.ai/docs
- https://platform.muse.ai/terms
- https://www.meta.com/help/superintelligence/1687253048996149/
- https://ai.meta.com/muse/ （本轮页面未返回可读正文）

内部 Sentinel 是 Meta 的执行权限控制层，本项目只是外部风险建议。正式目录上架另需遵循提交审核；个人 Custom Connector 的帮助文档注明不由 Meta 审核。

复用官方 MCP Python SDK 1.30.0；不自造协议。LLM Guard 模型依赖较重，首版不纳入；无可靠情报数据源，绝不声称已知恶意命中。
