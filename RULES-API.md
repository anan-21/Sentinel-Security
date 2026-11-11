# API

八个只读 MCP 工具同时支持本地 stdio 与 /mcp Streamable HTTP。HTTP 使用 Bearer 认证，/healthz 公开。扫描结果沿用 Report 结构；发现及动作决策使用各自的结构化结果。宿主元数据或模型判断不授予连接器权限。
