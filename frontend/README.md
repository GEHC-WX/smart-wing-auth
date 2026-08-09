# @smart-wing/frontend-auth

Smart Wing 平台**前端**共享认证包：门户 SSO 握手与会话管理。

后端共享认证（令牌签发/验签/守卫）在 `@smart-wing/auth`（本仓库根包），
本包专门收敛**各业务模块前端 `auth.ts`** 里重复的那份「门户握手 + 令牌/租户
会话」逻辑——四个模块此前各自复制了几乎相同的 `auth.ts`（只有模块 id 前缀
不同），改一处要同步四处，历史教训是「复制时源码复制了、测试忘了」。

## 为什么不用根包 `@smart-wing/auth`

根包是后端包（peerDependencies 含 `@nestjs/*`、`jose`），前端装它会把
NestJS 依赖拖进浏览器 bundle。前端会话逻辑与后端验签逻辑是两码事，独立成
子包互不污染。

## 安装

各业务模块在各自仓库里用 git URL + 子目录引用（跟后端包同一种分发方式，
不需要私有 registry）：

```bash
npm install "github:GEHC-WX/smart-wing-auth#v0.3.0&path=frontend"
```

用 tag 锁版本。升级时改 tag、重新 `npm install`。

## 用法

模块的 `auth.ts` 变成薄壳：只保留模块特有的能力类型与按能力的便捷判断，
会话逻辑全部来自工厂。

```ts
import { createPortalAuth, type PortalAuthUser } from '@smart-wing/frontend-auth';

interface Capabilities {
  canReadAssets: boolean;
  canEditAssets: boolean;
}

export type AuthUser = PortalAuthUser<Capabilities>;

export const {
  PORTAL_WEB,
  getToken,
  getUser,
  setSession,
  clearSession,
  redirectToPortal,
  exchangePortalCode,
  getSelectedTenant,
  setSelectedTenant,
  getActiveTenant,
} = createPortalAuth<Capabilities>({ moduleId: 'it-ot-asset-management' });
```

`moduleId` 决定 localStorage key 前缀（`<moduleId>:token` / `<moduleId>:tenant`），
多模块在同一浏览器域下共存互不串扰。

行为约定（与各模块原 `auth.ts` 逐项对齐）：
- 门户地址 `VITE_PORTAL_WEB_URL` / `VITE_PORTAL_API_URL` 环境变量优先，
  本地/内网回退到当前主机名（`http://<host>:5100` / `:4000/api/v1`）。
- 前端**不自行按 roles 推导能力**——能力取自后端 `GET /me` 算好的
  `capabilities`，判权规则只存一份（后端）。
- `exchangePortalCode` 拿门户一次性码换令牌；失败抛「门户握手失败」。
- 未配置 `VITE_PREVIEW_MODE` 时 `PREVIEW_MODE` 为 `false`。

## 测试

```bash
npm test          # 单测
npm run test:cov  # 覆盖率（门槛 80%）
```
