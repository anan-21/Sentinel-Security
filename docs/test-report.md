# 0.2.0 验证记录

测试使用合成文本、私人目录中的临时配置和回环网络。公开仓库不包含本机真实连接清单、账户标识或邮件。

| 环境 | 实际操作与结果 |
|---|---|
| WorkBuddy 5.5.6（macOS） | 随附 CodeBuddy CLI 在临时项目添加 Sentinel stdio 服务，查询单个服务器返回 Connected。单独验证 v4 绑定标志投影、禁用状态、跨档案路径拒绝。未访问真实邮件或代表用户认证。 |
| OpenClaw 2026.4.10 | CLI 渠道枚举返回本机配置的渠道类型。在临时 workspace 加载 Skill，隔离网关加载插件及 before_tool_call。通过真实 /tools/invoke 路径调用本地扫描器，伪造指令得到 HIGH，监控清单外的工具在执行前被拦截。通过原生 cron 创建禁用的隔离任务、重读并核对任务所属 Agent、工具清单和关闭投递的状态，再撤销；没有触发模型或消息发送。 |
| DSH 0.1.5-rc.2 | 实际文件系统 Skill provider 读取 SKILL.md。在真实 Cordis/DSH 工具执行流水线上创建两个合成 Agent 作用域，分别获得自己的连接器名。专用监控会话的 guard 拒绝越界调用。 |
| MCP 和打包 | 通过 SDK 客户端启动 stdio 子进程并执行发现及动作评估；验证 HTTP 协议调用、错误请求、鉴权、来源拒绝与大小限制。在独立 uv 工具环境安装 wheel，并为三种宿主安装 Skill、运行本地扫描。 |
| Muse | 保留初始化说明和原有五个工具。尚未做真实账户、Gmail 后台任务和通知验收。 |

本地自动化检查为 90 项 Python 测试、2 项 Node 测试。Python 测试客户端有一条弃用提示。原有 20 条合成样本中，正常邮件 5/5 为 LOW，诈骗 5/5、可疑 URL 5/5、注入 5/5 均命中。新用例覆盖全角字、零宽字符、HTML 实体、单层显式 base64、目标冲突、假授权与记忆写入。引用攻击指令的培训材料会误报；将通信内容“镜像到其他保险库”的迂回措辞仍可能漏报。样本是回归测试，没有独立生产准确率结论。

## 持续运行

开发期间每分钟运行当时的 Python 回归套件，历时 3,001 秒、51 轮；套件随实现增加，末轮 90 项全部通过。另在仅包含待发布文件的干净副本重装锁定依赖，90 项 Python、2 项 Node 测试均通过，wheel 在仓库外可安装。

同一个本地 HTTP MCP 进程连续运行 1,600.05 秒（26 分 40 秒）。108 轮共发送 756 个请求，覆盖协议初始化、工具枚举、良性邮件、注入文本、发现、越权动作评估及无效凭据；进程正常结束，检查日志未出现所用测试令牌或合成正文。该测试未使用真实邮箱。

## 复现

从仓库根目录运行。tests/host/ 中测试仅在本地使用合成数据和临时工作区。运行宿主测试须已安装对应 CLI。

```sh
.venv/bin/python -m pytest -q
node --test tests/test_guard.mjs
.venv/bin/python tests/host/workbuddy.py
.venv/bin/python tests/host/run_dsh.py
.venv/bin/python tests/host/openclaw_gateway.py
.venv/bin/python tests/host/soak.py --seconds 3000 --interval 15
```

Docker 本机 daemon 在开发时未运行。仓库提供容器构建与认证健康检查 CI。以 GitHub Actions 当前运行结果为准。
