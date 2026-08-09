# @smart-wing/auth

Smart Wing 平台的共享认证包。门户（签发方）与各业务模块（验签方）共用同一份实现。

> **双包结构**：本仓库从 v0.3.0 起包含两个 npm 包——
> - 根包 `@smart-wing/auth`：后端共享认证（令牌签发/验签/JWKS/Nest 守卫）
> - 子包 `@smart-wing/frontend-auth`（`frontend/` 目录）：前端门户 SSO 握手与会话管理
>
> 两者各自独立 `build`/`test`/版本。前端包通过
> `github:GEHC-WX/smart-wing-auth#v0.3.0&path=frontend` 引用，见
> `frontend/README.md`。

## 为什么要有这个包

同一套认证逻辑此前在门户与模块二各写了一遍。复制的时候**源码复制了、测试忘了**，
导致门户覆盖率长期不达标却没人发现。三个模块就是三份，改一处要同步三处。

## 安装

模块在各自的仓库里，用 git URL 引用（不需要私有 registry）：

```bash
npm install "git+https://github.com/GEHC-WX/smart-wing-auth.git#v0.1.0"
```

用 tag 锁版本。升级时改 tag、重新 `npm install`。

## 令牌方案：RS256 + JWKS

**门户持私钥签发，模块只拿公钥验签，模块无法伪造令牌。**

这是相对 HS256 的核心差别：HS256 下每个模块都必须持有**签发用**的那把密钥才能验签，
等于任何一个模块（或拿到它配置的人）都能签出「门户签发」的令牌。

### 门户侧（签发）

```ts
import { TokenIssuer, toPublicJwks } from '@smart-wing/auth';

const issuer = new TokenIssuer({
  issuer: 'https://portal.example.com',
  ttlSeconds: 8 * 3600,
  keyPair: { privateKeyPem: process.env.JWT_PRIVATE_KEY!, keyId: 'portal-key-1' },
});

const { accessToken, expiresIn } = await issuer.issue(user);

// 暴露 /.well-known/jwks.json 供各模块验签（只含公钥）
const jwks = await toPublicJwks([issuer.keyPair]);
```

生成密钥对：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out portal-key.pem
```

PEM 可以单行存放（用 `\n` 表示换行），包内会自动还原 —— 很多部署系统只能传单行。

### 模块侧（验签）

```ts
import { JwtAuthGuard, TOKEN_VERIFIER, TokenVerifier } from '@smart-wing/auth';

const verifier = new TokenVerifier({
  jwksUri: 'https://portal.example.com/.well-known/jwks.json',
  issuer: 'https://portal.example.com',
  audience: 'it-ot-asset-management', // 签发方设了 audience 时必填
});

@Module({
  providers: [{ provide: TOKEN_VERIFIER, useValue: verifier }, JwtAuthGuard],
})
```

模块**不需要配置任何密钥**，只需要知道 JWKS 地址。

### 已覆盖的攻击面

| 场景 | 结果 |
|---|---|
| 别人用自己的私钥签发 | 拒绝 |
| **alg 混淆**：拿公钥当 HS256 共享密钥伪造 | 拒绝（只接受 RS256） |
| 签发方（issuer）不符 | 拒绝 |
| 受众（audience）不符 —— 发给别的模块的令牌 | 拒绝 |
| 过期令牌 | 拒绝 |
| JWKS 里混入私钥分量 | 导出时逐字段挑选，`d/p/q` 不会外泄 |

验签失败一律返回同一句提示，不区分「过期 / 签名不对 / 受众不符」，避免给探测者额外信息。

## 其他导出

| 导出 | 用途 |
|---|---|
| `AuthProvider` / `AuthenticatedUser` | 认证适配缝：换 IdP 只实现这个接口 |
| `DevAuthProvider` | 开发环境预设账户；`NODE_ENV=production` 时拒绝构造 |
| `OidcProvider` / `mapClaims` | 企业统一认证（授权码 + PKCE），claim 名与角色映射可配置 |
| `resolveAuthMethods` / `devLoginAllowed` | 登录方式可用性；生产环境据此**在服务端**停用预设账户 |
| `ExchangeStore` | SSO 回调的一次性交换码，避免把令牌拼进 URL |
| `JwtAuthGuard` / `CurrentUser` / `TenantId` | NestJS 守卫与装饰器 |
| `PermissionGuard` / `RequirePermission` / `createPermissionRegistry` | 基于能力的判权，未知角色默认拒绝 |

`TenantId` 从令牌取租户，请求头 `X-Tenant-Id` 只能在令牌允许的租户里选一个，越权返回 403。

## 判权：角色 → 能力

**权限目录是各模块自己的业务知识，不长在共享包里**——门户不关心 `assets:write`，
模块二不关心 `leave-plans:approve`。共享包只提供通用算法：给一张角色表，算某组角色
有没有某个能力。

```ts
// 模块自己的 permissions.ts
import { createPermissionRegistry } from '@smart-wing/auth';

export const PERMISSIONS = {
  ASSETS_READ: 'assets:read',
  ASSETS_WRITE: 'assets:write',
} as const;

export const { hasPermission, permissionsOf } = createPermissionRegistry<
  (typeof PERMISSIONS)[keyof typeof PERMISSIONS]
>({
  admin: [PERMISSIONS.ASSETS_READ, PERMISSIONS.ASSETS_WRITE],
  viewer: [PERMISSIONS.ASSETS_READ],
});
```

```ts
// 模块自己的 auth.module.ts：把 hasPermission 注入给 PermissionGuard
import { PERMISSION_CHECKER, PermissionGuard, JwtAuthGuard } from '@smart-wing/auth';
import { hasPermission } from './permissions';

@Module({
  providers: [
    { provide: PERMISSION_CHECKER, useValue: hasPermission },
    JwtAuthGuard,
    PermissionGuard,
  ],
})
export class AuthModule {}
```

```ts
// 控制器上用
@UseGuards(JwtAuthGuard, PermissionGuard)
@Controller('assets')
export class AssetsController {
  @Patch(':id')
  @RequirePermission(PERMISSIONS.ASSETS_WRITE)
  update() { /* ... */ }
}
```

"能力转前端友好布尔值"（`capabilitiesOf`）同理由各模块自己写一个小函数，不放共享包——
不同模块的能力名称完全不同，硬塞一个通用形状没有意义。

## 开发

```bash
npm install --ignore-scripts   # prepare 会跑 build，首次安装先跳过
npm run build
npm run test:cov              # 覆盖率门槛 80%
```

发布新版本：改 `package.json` 的 version → 提交 → 打 tag → 推送。
消费方改 git URL 里的 tag 即可升级。
