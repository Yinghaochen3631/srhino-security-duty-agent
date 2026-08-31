# Srhino平台安全值守日报（2026-08-28）

> 数据范围：前一日 Srhino 告警；设备动作、运营闭环和 AI 研判分别统计。
> 值守边界：模型只提供研判和建议，不自动封禁 IP、不修改规则或生产配置。

## 一、告警概览

| 指标 | 数量 | 说明 |
| --- | ---: | --- |
| 告警总数 | 240 | 统计窗口内全部事件 |
| 高危 | 40 | 优先人工确认处置 |
| 中危 | 80 | 持续观察并核查资产 |
| 低危 | 120 | 聚合降噪后跟踪趋势 |
| 拦截 | 116 | 请求被 Srhino 直接阻断 |
| 人机校验 | 44 | 要求验证码/MFA 等二次验证 |
| 放行观察 | 80 | 返回业务响应但保留告警 |

## 二、处置闭环

| 指标 | 数量 | 说明 |
| --- | ---: | --- |
| 已拦截 | 116 | 设备已完成阻断 |
| 已下发风险预警 | 26 | 已通知责任单位跟进并登记责任单位 |
| 已完成观察 | 35 | 低危告警完成观察登记并纳入趋势跟踪 |
| 待人工复核 | 63 | 需要值守人员确认 |
| 已闭环 | 176 | 处置结果已确认 |
| 待复核 | 64 | 尚未完成闭环 |
| 闭环率 | 73.3% | 已闭环 / 告警总数 |
| 风险预警已下发 | 142 | 接收单位统计合计 142 条 |

## 三、风险类别 Top

| 排名 | 风险类别 | 数量 |
| ---: | --- | ---: |
| 1 | 扫描探测 | 120 |
| 2 | 跨站脚本（XSS） | 42 |
| 3 | API滥用 | 37 |
| 4 | 路径穿越 | 12 |
| 5 | 暴力破解 | 10 |
| 6 | SQL注入 | 10 |
| 7 | 数据暴露 | 9 |

## 四、重点资产

| 排名 | 资产 | 告警数 |
| ---: | --- | ---: |
| 1 | web-prod-02 | 51 |
| 2 | web-prod-01 | 50 |
| 3 | api-prod-01 | 47 |
| 4 | api-prod-02 | 47 |
| 5 | oa-prod-01 | 45 |

## 五、小时趋势

| 时段 | 告警数 |
| --- | ---: |
| 00:00 | 9 |
| 01:00 | 2 |
| 02:00 | 1 |
| 07:00 | 7 |
| 08:00 | 6 |
| 09:00 | 21 |
| 10:00 | 32 |
| 11:00 | 38 |
| 12:00 | 22 |
| 14:00 | 9 |
| 16:00 | 5 |
| 18:00 | 10 |
| 20:00 | 12 |
| 22:00 | 40 |
| 23:00 | 26 |
<!-- SRHINO_HOURLY_CHART:00:9,01:2,02:1,07:7,08:6,09:21,10:32,11:38,12:22,14:9,16:5,18:10,20:12,22:40,23:26 -->

## 六、待人工复核

共 124 条事件处置动作为放行/挑战/待处置，建议优先处理高危且未拦截事件；模型不得据此自动封禁或修改生产配置。

本次人工点击AI研判样本：5 条，模型可读取其脱敏请求/响应原文并输出‘真实攻击/疑似误报/无法判断’及依据。

## 七、AI原始包研判

本次对 5 条人工点击样本读取 raw_request/raw_response，逐条输出研判结论、证据、置信度、下一步处置建议和人工动作。以下内容是日报正文的一部分，不是仅存在于 Agent 运行日志中的摘要。

### SRHINO-20260828-R001｜SQL注入攻击（high，规则 SQLI-942100）
- 资产链路：203.0.113.10 → api-prod-01；设备动作：拦截
- AI研判结论：**真实攻击**；置信度：高
- 证据分析：请求体包含 admin' OR '1'='1 恒真条件，命中 SQL 注入规则；响应为 403 且设备动作是拦截。
- 确定性规则预判：**真实攻击尝试**（SRH-SQLI-001）；命中强 SQL 注入结构且设备阻断或返回阻断状态
- 原始请求：
```http
POST /api/auth/login HTTP/1.1
Host: api-prod-01.example.test
Content-Type: application/x-www-form-urlencoded
User-Agent: demo-client/1.0

username=admin%27+OR+%271%27%3D%271&password=demo
```
- 原始回包：
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Srhino-Action: block

{"code":403,"message":"request blocked"}
```
- 下一步处置建议：保持拦截；核查同源 IP 的登录失败记录和账号是否需要重置密码。
- 人工动作：无需额外确认，保持现有设备处置

### SRHINO-20260828-R002｜路径穿越攻击（high，规则 LFI-930110）
- 资产链路：198.51.100.20 → web-prod-02；设备动作：拦截
- AI研判结论：**真实攻击**；置信度：高
- 证据分析：请求参数包含 ../../../../etc/passwd 路径穿越序列，User-Agent 呈扫描器特征；响应为 403 并被设备阻断。
- 确定性规则预判：**真实攻击尝试**（SRH-PATH-001）；多层路径穿越指向系统敏感文件且被阻断
- 原始请求：
```http
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: web-prod-02.example.test
Accept: */*
User-Agent: security-scanner/2.1


```
- 原始回包：
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain
X-Srhino-Action: block

blocked by security policy
```
- 下一步处置建议：保持拦截；核查下载接口路径规范化和目标主机文件访问日志。
- 人工动作：无需额外确认，保持现有设备处置

### SRHINO-20260828-R003｜暴力破解登录（high，规则 BRUTE-913100）
- 资产链路：192.0.2.50 → oa-prod-01；设备动作：人机校验
- AI研判结论：**真实攻击（尝试）**；置信度：高
- 证据分析：admin 账号配合序号化口令猜测，命中暴力破解规则；响应 429 且人机校验未通过，尚未证明登录成功。
- 确定性规则预判：**真实攻击（尝试）**（SRH-BRUTE-001）；发现序列化口令并触发限速/人机校验，单条证据不能证明登录成功
- 原始请求：
```http
POST /admin/login HTTP/1.1
Host: oa-prod-01.example.test
Content-Type: application/json
X-Forwarded-For: 192.0.2.50

{"username":"admin","password":"guess-017"}
```
- 原始回包：
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 60
X-Srhino-Action: challenge

{"error":"verification_required"}
```
- 下一步处置建议：值守人员确认后可将人机校验升级为临时拦截，并核查管理员账号、源 IP 和 MFA 记录。
- 人工动作：需要值守人员确认

### SRHINO-20260828-R004｜跨站脚本攻击（medium，规则 XSS-941100）
- 资产链路：203.0.113.11 → web-prod-01；设备动作：放行观察
- AI研判结论：**疑似误报**；置信度：高
- 证据分析：请求包含 XSS 测试载荷，但响应已将 script 标签 HTML 实体编码，业务正常返回且未观察到脚本执行。
- 确定性规则预判：**疑似误报**（SRH-XSS-001）；脚本标签已转义，且业务响应为 2xx
- 原始请求：
```http
GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
Host: web-prod-01.example.test
User-Agent: Mozilla/5.0 (compatible; demo-browser)


```
- 原始回包：
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Srhino-Action: allow

<html><body>Search results for &lt;script&gt;alert(1)&lt;/script&gt;</body></html>
```
- 下一步处置建议：暂不封禁；通知 Web 应用责任单位确认统一输出编码并观察同类请求。
- 人工动作：需要值守人员确认

### SRHINO-20260828-R005｜SQL注入攻击（medium，规则 SQLI-942100）
- 资产链路：198.51.100.21 → api-prod-02；设备动作：放行观察
- AI研判结论：**疑似误报**；置信度：高
- 证据分析：SQL 关键字出现在合法商品搜索词 select shoes 中，没有引号闭合、UNION 或注释结构；响应为正常业务 JSON。
- 确定性规则预判：**疑似误报**（SRH-SQLI-001）；仅命中业务关键词，响应正常且未发现注入结构
- 原始请求：
```http
POST /api/order/search HTTP/1.1
Host: api-prod-02.example.test
Content-Type: application/json
X-Request-Id: demo-r005

{"keyword":"select shoes","sort":"price asc"}
```
- 原始回包：
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Srhino-Action: allow

{"total":2,"items":[{"name":"select shoes","price":199}]}
```
- 下一步处置建议：暂不封禁；通知 API平台主管单位核对参数化查询和业务关键词白名单。
- 人工动作：需要值守人员确认

## 八、值守结论

本日共接收 Srhino 告警 **240** 条，其中高危 40 条；设备已拦截 116 条，向责任单位下发风险预警 142 条，完成闭环 176 条，闭环率 **73.3%**，仍有 64 条待复核。
告警以 **扫描探测** 为主（120 条），重点资产为 **web-prod-02**（51 条）。高危告警已完成拦截或风险预警登记；中危放行/挑战事件及人工点击 AI 研判样本仍需值守人员确认，不能仅凭模型结果自动变更设备策略。
AI 已对 5 条带完整请求/回包证据的样本完成研判。建议下一班优先核查待复核队列中的高危事件，跟进风险预警接收单位的整改反馈，并对放行观察类告警持续观察同源 IP、访问频率和应用日志。
闭环口径：设备拦截、高危风险预警完成登记、低危观察登记计入已闭环；中危放行/挑战和人工研判待确认事件计入待复核。
