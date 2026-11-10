# 未完成与限制
- 公网 HTTPS、Muse Custom Connector、真实 Gmail读取与后台提醒均未实测；缺少部署目标及用户授权。
- Docker daemon 当前不可用，Dockerfile/compose 已准备，构建未验证。
- 未实现 OAuth、第三方情报、附件扫描、重定向展开、强制工具拦截或多租户账户系统。
- 静态词法规则覆盖有限；引用攻击话术会误报，同义改写可能漏报。LOW 不是安全证明。
- 不验证 SPF/DKIM/DMARC；域名品牌列表仅包含少数示例，不保证同形字或拼写变体完整识别。
- CRITICAL 结构可表示，但当前无可信恶意情报或实际执行证据，不生成该等级。
- user_goal 接收但不声称能够自动可靠判断语义不一致；报告明确要求 Muse 核对。
- Python 3.11本地验证；requirements.lock 锁定当前环境（含测试依赖）。
