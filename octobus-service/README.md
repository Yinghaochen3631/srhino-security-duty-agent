# OctoBus 服务包

本目录包含课题使用的 Srhino 专用 OctoBus 服务包。将 `srhino-security/`
作为一个完整服务目录导入 OctoBus，即可复现 Agent 所依赖的四个能力：

- `ListSrhinoAlerts`：按日报日期读取告警元数据；
- `GetSrhinoAlertEvidence`：读取人工点击 AI 研判样本的原始请求和回包；
- `CreateAlertReviewTask`：创建待人工确认的研判跟进任务；
- `SendSrhinoDutyReport`：保存 Markdown 值守日报并返回报告 ID。

## 文件说明

| 文件 | 用途 |
| --- | --- |
| `service.json` | OctoBus 服务清单、服务名和 proto 入口 |
| `proto/srhino_security.proto` | 四个 RPC 方法及请求/响应结构 |
| `bin/srhino-security-service.js` | 服务入口和四个方法的实现 |
| `config.schema.json` | 服务配置校验规则 |
| `config.example.json` | 可复制后按部署路径修改的配置模板 |
| `secret.schema.json` | 可选操作员标识的密钥字段定义 |
| `package.json` | Node.js 模块与 OctoBus SDK 依赖 |

## 导入前配置

复制 `config.example.json` 为 OctoBus 实例配置。`dataFile` 指向 Agent 工作区中的
Srhino JSONL 告警文件，`reportDir` 指向日报落盘目录。示例使用服务器上的默认路径，
本地复现时改为对应的绝对路径即可。配置中不包含 API Key、SMTP 授权码或服务器密码。

```bash
cp octobus-service/srhino-security/config.example.json /path/to/instance-config.json
# 按实际挂载路径修改 dataFile 和 reportDir
```

服务包导入后，在 OctoBus 中创建同名服务实例，并在能力集里逐项选择上述四个方法；
Agent 的 `agent-compose.yml` 使用 `internal/srhino-security` 引用该能力集。

## 本地静态检查

不需要连接 OctoBus 即可检查清单、proto、配置模板和入口文件是否齐全：

```bash
test -f octobus-service/srhino-security/service.json
test -f octobus-service/srhino-security/proto/srhino_security.proto
node --check octobus-service/srhino-security/bin/srhino-security-service.js
```

