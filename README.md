# Vault — 跑在 Cloudflare Workers 上的零知识密码管理器

> 线上地址：<https://vault.suchangv.com>
> 访问控制：Cloudflare Access（仅 Google 登录，白名单 `suchangv@gmail.com`）

一个单用户的个人密码保险库。数据在浏览器里用主密码加密后才上传，Worker + D1
只保存密文和 KDF 参数。即使 Cloudflare 账号被攻破，没有主密码也无法解密内容。

---

## 安全模型

| 层 | 机制 |
| --- | --- |
| 边缘鉴权 | Cloudflare Access 自托管应用，IdP 仅 Google，策略 `allow: suchangv@gmail.com`，`auto_redirect_to_identity`，8 小时会话 |
| 应用鉴权 | Worker 对**每个**请求（包括静态资源）校验 `Cf-Access-Jwt-Assertion`（或 `CF_Authorization` cookie）：RS256 验签、`aud` = 本应用 AUD、`iss` = 团队域名、`exp`/`nbf`、邮箱白名单。任一失败即 `403`，默认拒绝 |
| 传输 | 全站 HTTPS；Worker 返回 `Strict-Transport-Security`、`X-Frame-Options: DENY`、`X-Robots-Tag: noindex` |
| 存储 | D1 单行：`owner`(邮箱)、`version`、`kdf`(salt/迭代次数)、`ciphertext`、时间戳。**没有明文，没有主密码** |
| 加密 | 浏览器 WebCrypto：PBKDF2-SHA256(600,000 次) → AES-256-GCM；随机 12 字节 IV；AAD `cf-vault:v1`；密文格式 `v1.<iv>.<ciphertext>` |
| 密钥生命周期 | `CryptoKey` 不可导出（`extractable: false`），只存在于当前标签页内存；锁定/刷新即消失 |
| 防泄漏 | 剪贴板 30 秒后自动清空；主密码错误仅提示、不泄露细节；CSP 禁止内联脚本、外链资源、iframe；`Cache-Control: no-store` |
| 开发绕过 | 仅在同时设置 `DEV_AUTH_BYPASS=true` 与 `DEV_AUTH_EMAIL` 时生效；两者只写在 git-ignored 的 `.dev.vars`，生产配置里 `DEV_AUTH_BYPASS="false"` 且没有 `DEV_AUTH_EMAIL` |

### 主密码无法找回

保险库只保存密文。忘记主密码 = 数据不可恢复，只能在解锁页删除旧保险库重新开始。
请定期在「设置 → 导出备份」导出明文 JSON 并离线保存（导出时会再次验证主密码）。

### 威胁模型边界

- 能防御：服务器/数据库泄露、Cloudflare 内部读取、网络窃听、Access 之外的匿名访问。
- 不能防御：浏览器已被恶意扩展/木马控制、主密码被键盘记录、你自己导出的明文备份泄露。

---

## 功能

- 三种条目：登录（网址/用户名/密码）、银行卡（卡号/CVV/有效期）、安全笔记
- 搜索、筛选（全部/收藏/登录/银行卡/笔记）、标签、收藏
- 密码生成器（长度、字符集、排除易混淆字符）、强度提示
- 一键复制、显示/隐藏、复制 30 秒后自动清空剪贴板
- 闲置自动锁定（1/5/15/30/60 分钟或关闭），手动锁定，`Ctrl/⌘ + L`
- 深色/浅色/跟随系统主题
- 修改主密码（重新加盐，全量重加密）
- 导入导出：Vault JSON、Bitwarden CSV、Chrome CSV
- 多标签页并发编辑：版本号冲突时按条目 `updatedAt` 自动合并
- 移动端适配（列表 ↔ 详情）、快捷键 `Ctrl/⌘ + K` 搜索、`N` 新建

---

## 项目结构

```
vault/
├── src/
│   ├── index.ts        # Worker：路由、REST API、静态资源网关、安全响应头
│   └── access.ts       # Access JWT 校验（JWKS 缓存、aud/iss/exp、邮箱白名单）
├── public/             # 前端（无构建步骤，原生 ES module）
│   ├── index.html
│   ├── app.js          # 加密、状态、渲染、交互全部在这里
│   ├── app.css
│   └── favicon.svg
├── migrations/
│   └── 0001_init.sql   # D1 表结构
├── access/app.json     # Access 应用定义（可复现重建）
├── scripts/{dev,deploy}.sh
└── wrangler.jsonc
```

### API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/me` | 返回 Access 身份（邮箱、会话过期时间） |
| `GET` | `/api/vault` | 返回密文 + KDF 参数；不存在时 `404 {error:"no_vault"}` |
| `PUT` | `/api/vault` | 乐观并发写入（`version` 不匹配返回 `409` + 当前密文） |
| `DELETE` | `/api/vault` | 删除保险库（前端要求主密码 + 输入 `DELETE` 二次确认） |
| `GET` | `/api/health` | 已登录时的健康检查 |

---

## 本地开发

```sh
cp .dev.vars.example .dev.vars      # 按需修改 DEV_AUTH_EMAIL
npm install
npm run dev                         # 自动应用本地 D1 迁移并启动 http://localhost:8787
```

本地用 `DEV_AUTH_BYPASS` 伪造身份，不需要走 Access；生产的 `wrangler.jsonc` 里该值为
`false` 且没有 `DEV_AUTH_EMAIL`，所以绕过逻辑在线上不可能生效。

```sh
npm run check     # TypeScript 类型检查
npm run deploy    # 应用远程 D1 迁移 + wrangler deploy
npm run tail      # 线上日志
```

---

## Cloudflare Access 配置

线上应用的 AUD 已写入 `wrangler.jsonc` 的 `ACCESS_AUD`：

```
AUD = 149e46306afc0148504a20a2a391e7c26206eac55fecfd114eb683967ff59ead
```

如需重建（例如换域名），用 `cf` CLI（需要 Zero Trust 写权限）：

```sh
# 1. 找到 Google IdP 的 id
cf zero-trust identity-providers list

# 2. 用模板创建应用（把 GOOGLE_IDP_ID 替换成上一步的 id）
cf zero-trust access applications create \
  --body "$(sed 's/GOOGLE_IDP_ID/<google-idp-id>/' access/app.json)"

# 3. 把返回的 aud 写进 wrangler.jsonc 的 ACCESS_AUD，然后部署
npm run deploy
```

应用创建后，访问 `https://vault.suchangv.com` 会直接跳转 Google 登录，
非 `suchangv@gmail.com` 的账号会被 Access 拒绝；即使 Access 策略被放宽，
Worker 里的邮箱白名单仍会二次拦截。

---

## 数据表

```sql
CREATE TABLE vaults (
  owner      TEXT PRIMARY KEY,   -- Cloudflare Access 邮箱
  version    INTEGER NOT NULL,   -- 乐观锁，每次写入 +1
  kdf        TEXT NOT NULL,      -- {"algorithm":"PBKDF2-SHA256","salt":"…","iterations":600000}
  ciphertext TEXT NOT NULL,      -- v1.<base64 iv>.<base64 AES-GCM 密文>
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

删除云端数据：`npx wrangler d1 execute vault-db --remote --command "DELETE FROM vaults"`。
