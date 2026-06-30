# 设计：发送 VPN 配置与 OTP 到用户邮箱

**日期**: 2026-06-30
**仓库**: `openvpn-ui` (Go + Beego v2)
**关联**: 配置生成脚本在 `openvpn-server` 仓库的 `bin/genclient.sh`

## 目标

在 OpenVPN-UI 的证书列表中，管理员可一键将某用户的 VPN 客户端配置（`.ovpn`）以及 2FA OTP 二维码与文本密钥，通过服务端 SMTP 发送到该用户的注册邮箱。可重复发送（补发）。

## 背景与现状

- 证书列表 `views/certificates.html` 每行有一个详情弹窗，弹窗里已有一个 **"Send Email"** 按钮（line 184）。
- 该按钮当前仅由 JS 拼接 `mailto:` 链接打开本地邮件客户端，**无法携带附件**（`.ovpn` / QR 图片）。
- 创建用户流程：`CertificatesController.Post()` → `lib.CreateCertificate()` → 在 UI 容器内 `exec` 调用 `/opt/scripts/genclient.sh`。脚本产物：
  - `<OVConfigPath>/clients/<name>.ovpn`
  - `<OVConfigPath>/clients/<name>.png`（OTP 二维码，仅当启用 2FA）
  - 向 `<OVConfigPath>/clients/oath.secrets` 追加一行 `<tfaname>:<userhash>`
- 现成可复用：`CertificatesController.saveClientConfig(keysPath, name)` 会用模板重新生成并写出 `<name>.ovpn`，返回路径。
- 容器内已具备 `oathtool`（创建证书即依赖它），可据 `userhash` 重算 Base32 密钥。
- 项目已 vendored（存在 `vendor/`）。Go 1.23.4。

## 范围

本功能完全在 `openvpn-ui` 仓库实现。`openvpn-server` 仓库仅做文档化改动（compose 环境变量、README 说明）。

## 决策（已确认）

| 决策点 | 选择 |
|---|---|
| SMTP 配置存储 | 环境变量（docker-compose `environment` 传入） |
| 触发方式 | 证书列表详情弹窗内的 "Send Email" 按钮，改为请求服务端接口 |
| 邮件库 | `gopkg.in/gomail.v2` |
| OTP 内容 | 二维码（内嵌 + 附件）+ 文本密钥（Base32 与 `otpauth://` 串） |
| 无 2FA 用户 | 禁用/不渲染发邮件按钮（仅对启用了 2FA 的有效证书显示） |

## SMTP 配置（环境变量）

| 变量 | 说明 | 必填 |
|---|---|---|
| `SMTP_HOST` | SMTP 服务器主机 | 是 |
| `SMTP_PORT` | 端口（如 587 / 465 / 25） | 是 |
| `SMTP_USER` | 登录用户名 | 否（视服务器） |
| `SMTP_PASSWORD` | 登录密码 | 否（视服务器） |
| `SMTP_FROM` | 发件人邮箱地址 | 是 |
| `SMTP_FROM_NAME` | 发件人显示名 | 否（默认 "OpenVPN"） |
| `SMTP_ENCRYPTION` | `none` / `ssl` / `starttls`（默认 `starttls`） | 否 |

未配置 `SMTP_HOST`/`SMTP_FROM` 等必填项时，发送接口返回明确错误（flash 提示 "SMTP 未配置"），不影响其它功能。

## 组件设计

### 1. `lib/mailer.go`（新增）

职责：读取 SMTP 环境变量、组装并发送带附件的邮件。

```
type SMTPConfig struct { Host, Port, User, Password, From, FromName, Encryption string }

func LoadSMTPConfig() (SMTPConfig, error)   // 读 env；缺必填项返回 error

type ClientMail struct {
    To          string   // 收件人
    ClientName  string
    OVPNPath    string   // .ovpn 附件路径
    Has2FA      bool
    QRPath      string   // <name>.png 路径（Has2FA 时）
    OTPSecret   string   // Base32
    OTPAuthURL  string   // otpauth://...
}

func SendClientConfigEmail(m ClientMail) error
```

- 用 gomail 构建：HTML 正文 + 纯文本兜底；`.ovpn` 作为附件；2FA 时内嵌 QR 图片（`Embed`）并在正文展示 Base32 与 `otpauth://`。
- 根据 `Encryption` 选择 TLS/STARTTLS/明文；gomail `Dialer` 设置 `SSL=true`（ssl）或默认 STARTTLS。
- 接口职责单一：只发送，不查文件、不算密钥。

### 2. `lib/oath.go`（新增小工具）

职责：由 `oath.secrets` + issuer 重建 OTP 文本密钥与 URL。

```
func GetOATHSecret(ovconfigPath, tfaName, issuer string) (base32Secret, otpauthURL string, err error)
```

- 读 `<ovconfigPath>/clients/oath.secrets`，按 `tfaName:` 前缀（忽略大小写，取第一条）取出 `userhash`。
- 执行 `oathtool --totp -v <userhash>`，解析出 `Base32` 行得到密钥。
- 组装 `otpauth://totp/<issuer>:<tfaName>?secret=<base32>`（issuer 来自 `OVClientConfig`/`SettingsC.TFAIssuer`，与创建时一致）。
- 找不到条目或 oathtool 失败时返回 error。

### 3. `controllers/certificates.go`（改动）

新增 handler：

```
// @router /certificates/sendemail/:key/:serial/:tfaname [get]
func (c *CertificatesController) SendEmail()
```

流程：
1. `name := :key`；从 `lib.ReadCerts(index.txt)` 找到该证书，取 `Details.Email`（收件人）、`Details.TFAName`、`EntryType`。
2. 校验：邮箱非空且证书有效（`EntryType == "V"`）且启用了 2FA（`TFAName != ""` 且 `!= "none"`）。否则 flash.Error 返回。
3. 重新生成 `.ovpn`：复用 `saveClientConfig(filepath.Join(OVConfigPath,"pki/issued"), name)` 拿到路径。
4. QR 路径：`<OVConfigPath>/clients/<name>.png`。
5. 取 OTP：`lib.GetOATHSecret(OVConfigPath, tfaName, issuer)`。
6. `lib.SendClientConfigEmail(...)`；成功/失败走 flash，最后 `showCerts()` 重新渲染列表（与 Revoke/Renew 一致）。

### 4. `views/certificates.html`（改动）

- 将弹窗内 "Send Email" 按钮（line 184）从触发 mailto JS，改为与 Renew/Revoke 同风格的 `urlfor` 链接：
  `{{urlfor "CertificatesController.SendEmail" ":key" .Details.Name ":serial" .Serial ":tfaname" .Details.TFAName}}`
- 按钮仅在 2FA 模式且证书有效时渲染（即放进 `{{ if and (eq (printf "%d" $.SettingsC.FuncMode) "1") (eq .EntryType "V") (ne .Details.Name "") }}` 条件内），满足"无 2FA 禁用按钮"的决策。
- 移除/不再使用对应的 `send-email-with-qr-btn` 的 mailto JS（line ~356-398）；该 JS 仅服务此按钮，属于本次改动产生的孤儿代码，应删除。

### 5. 依赖

- `go get gopkg.in/gomail.v2`
- `go mod tidy && go mod vendor`（已 vendored，需更新 vendor 目录）

### 6. 文档（`openvpn-server` 仓库）

- `docker-compose.yml` 的 `openvpn-ui` 服务 `environment` 增加上述 SMTP 变量（带注释，默认注释掉示例值）。
- README 增加一节说明 SMTP 配置与发邮件功能。

## 数据流

```
管理员点 Send Email
  → GET /certificates/sendemail/:key/:serial/:tfaname
    → 读 index.txt 找收件人/2FA 信息（校验有效 + 启用 2FA）
    → saveClientConfig 重生成 .ovpn
    → GetOATHSecret 重算 Base32 + otpauth URL（oathtool）
    → LoadSMTPConfig（env）
    → SendClientConfigEmail（gomail：正文 + .ovpn 附件 + 内嵌 QR）
  → flash 成功/失败 → 重渲染证书列表
```

## 错误处理

- SMTP 未配置 → flash.Error "SMTP 未配置，请检查环境变量"。
- 收件人邮箱为空 → flash.Error "该用户未登记邮箱"。
- 证书无效 / 未启用 2FA → 不渲染按钮（防御性地在 handler 再校验一次）。
- `.ovpn` 生成失败、oath.secrets 缺条目、oathtool 失败、SMTP 发送失败 → 各自 `logs.Error` + flash.Error，向管理员透出具体原因。

## 测试与验证

- `go build ./...` 通过、`go vet ./...` 通过。
- `LoadSMTPConfig`：缺必填项返回 error；齐全时正确解析（表驱动单测，通过临时设置 env）。
- `GetOATHSecret`：构造临时 `oath.secrets`，mock/真实 `oathtool` 验证能取出 Base32 并拼出 otpauth URL（若 CI 无 oathtool，则将解析逻辑与命令执行分离，单测解析部分）。
- 手动验证：用 MailHog/本地 SMTP（如 `mailhog`，1025 端口，`SMTP_ENCRYPTION=none`）点击 Send Email，确认收到邮件且含 `.ovpn` 附件、内嵌二维码、Base32 文本。

## 非目标（YAGNI）

- 不做创建用户时自动发送（本次选择按钮触发）。
- 不新增 SMTP 的 UI 设置页（用环境变量）。
- 不做邮件模板自定义、不做发送历史记录。
- 不改动 `genclient.sh` 行为。
