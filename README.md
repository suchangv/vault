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
| 密钥生命周期 | 会话 `CryptoKey` 不可导出（`extractable: false`），只存在于当前标签页内存 |
| 免密解锁 | 可选 7/30/90 天。用 IndexedDB 里一个**不可导出**的 AES-GCM 设备密钥包裹保险库密钥，只存包裹后的密文与到期时间；手动锁定 / 闲置锁定 / 退出登录会立即删除凭证 |
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
- 免密解锁：本设备 7 / 30 / 90 天内刷新或重开无需主密码（可在设置中关闭或随时「忘记此设备」）
- 标签管理：侧栏标签筛选、改名 / 合并 / 删除（批量应用到所有条目）、编辑时自动补全
- 深色/浅色/跟随系统主题
- 修改主密码（重新加盐，全量重加密）
- 导入导出：Vault JSON、Bitwarden CSV、Chrome CSV
- 多标签页并发编辑：版本号冲突时按条目 `updatedAt` 自动合并
- 移动端适配（列表 ↔ 详情）、快捷键 `Ctrl/⌘ + K` 搜索、`N` 新建
- **PWA**：可安装到桌面/主屏，独立窗口运行；桌面端启用 **Window Controls Overlay**（系统窗口按钮直接叠在页面上，标题栏与页面背景融为一体）；离线时可加载应用外壳与明确的「无法连接服务器」提示；`?new=login` / `?new=note` 快捷入口

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
│   ├── manifest.webmanifest
│   ├── sw.js           # Service Worker：只缓存应用外壳，绝不缓存 API
│   ├── icons/          # PWA 图标（192/512/maskable/apple-touch）
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

## PWA / 离线

- `manifest.webmanifest`：`standalone` 独立窗口、`display_override: ["window-controls-overlay", "standalone"]`、主题色、maskable 图标、两个快捷入口
- 桌面安装后自动进入 Window Controls Overlay：`navigator.windowControlsOverlay` 汇报标题栏高度，
  页面顶部预留同高的透明带（露出页面自身背景）并设为拖拽区，系统按钮直接浮在上面
- `theme-color` 跟随深/浅主题动态更新（Android 状态栏、部分桌面窗口边框），
  iOS 用 `black-translucent` + `env(safe-area-inset-*)` 让内容避开刘海/状态栏/Home 指示条
- `sw.js`：预缓存应用外壳（HTML/CSS/JS/图标），导航请求走「网络优先 + 5 秒超时」，
  离线时回退到缓存；**`/api/*` 与 `/cdn-cgi/*` 从不经过缓存**，所以 Cache Storage
  里不会有密文、也不会出现任何解密后的凭据
- 安装入口在「设置 → 应用 → 安装到桌面」；iOS Safari 会给出「分享 → 添加到主屏幕」的指引
- 离线时只能打开界面，保险库本身仍需要联网取回密文才能解密
- 部署后 `sw.js` 返回 `Cache-Control: no-cache`，配合 `network-first` 保证新版本及时生效

## 免密解锁（记住此设备）

刷新页面不必重新输入主密码，默认 7 天（可改 30 / 90 天，或关闭）：

1. 用主密码解锁成功后，把 PBKDF2 派生出的密钥字节用**设备密钥**（AES-GCM，`extractable: false`，
   存在 IndexedDB）包裹，只保存 `v1.<iv>.<ciphertext>` + 到期时间。
2. 之后页面加载时读出包裹密文 → 用设备密钥解包 → 得到会话密钥 → 解密保险库。
3. 手动锁定 / 闲置锁定 / 退出登录 / 删除保险库都会立即删除该凭证；改主密码会重新包裹。
4. 设备密钥不可导出、且绑定当前 origin，复制 localStorage / cookie 到别的机器无法使用；
   清除站点数据或「忘记此设备」后必须重新输入主密码。

需要知道的取舍：这相当于把「本机浏览器配置」也当成了解锁因子。任何能在此浏览器配置里
执行同源脚本的人（例如恶意扩展、已被控制的浏览器）都可以解开保险库 —— 这也是所有密码
管理器的「记住我 / PIN 解锁」共同的前提。共享电脑上请在设置里关闭它，或离开前点「锁定」。

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
