# Sentinel Security 0.1.0 — Muse 专用外部安全检测器
本地可运行 MVP，非 Meta 官方产品。5个只读 MCP 工具；规则检测，无模型或外部情报依赖。尚未完成真实 Muse / Gmail 联调或公网部署。

## 本地运行
```sh
uv venv --python 3.11
uv pip install --python .venv/bin/python -r requirements.lock
cp .env.example .env
# 用密码管理器生成至少32字符随机 token，保存在 .env；不要提交或贴入聊天
set -a
. ./.env
set +a
.venv/bin/python -m server.mcp_server
```
本地地址 http://127.0.0.1:8000/mcp；无认证健康检查 /healthz。MCP 请求必须 Authorization: Bearer <token>。测试：`.venv/bin/python -m pytest -q`。

## Docker
启动 Docker Desktop 后执行 `docker compose up --build -d`，`docker compose ps` 检查健康。当前交付环境 Docker daemon 未启动，镜像构建尚未实测。compose 只绑定回环地址。

## 接入 Muse
详见 integrations/muse/connector_guide.md。将 integrations/muse/setup_prompt.md 的域名替换为实际 HTTPS 地址后发给 Muse，同时提供 MUSE_SETUP.md。不要用 localhost 连接云端 Muse，不要把密钥写入指令。

服务不访问邮箱、不发现其他连接器、不创建任务、不保存内容；这些由 Muse 按实际能力完成。查看 docs/test-report.md 和 docs/limitations.md，区分本地验证与真实端到端验收。
