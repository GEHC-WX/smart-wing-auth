/**
 * Smart Wing 平台共享认证包。
 *
 * 门户（签发方）与各业务模块（验签方）共用这一份实现，避免同一套逻辑在
 * 多个仓库里各写一遍 —— 之前门户从模块二复制代码时漏了测试，
 * 导致覆盖率长期不达标却没人发现，就是重复带来的代价。
 *
 * 典型用法：
 *   门户：TokenIssuer 签发 + toPublicJwks 暴露 /.well-known/jwks.json
 *   模块：TokenVerifier 按 JWKS 验签，配 JwtAuthGuard 使用
 */

export type { AuthenticatedUser, AuthProvider, RequestWithUser } from './types';
export { AUTH_PROVIDER } from './types';

export { DevAuthProvider } from './dev-auth.provider';
export {
  devLoginAllowed,
  isProduction,
  missingOidcVars,
  resolveAuthMethods,
  REQUIRED_OIDC_VARS,
  type AuthMethods,
} from './auth-methods';
export { ExchangeStore, EXCHANGE_TTL_MS } from './exchange-store';

export { OidcProvider, oidcConfigFrom, type OidcConfig } from './oidc/oidc.provider';
export {
  claimMappingFrom,
  mapClaims,
  parseAliases,
  toStringArray,
  type ClaimMapping,
} from './oidc/oidc-claims';

export { loadKeyPair, normalizePem, toPublicJwks, type KeyPairConfig, type LoadedKeyPair } from './tokens/keys';
export { TokenIssuer, DEFAULT_TTL_SECONDS, type IssuerConfig, type TokenClaims } from './tokens/issuer';
export { TokenVerifier, type VerifierConfig } from './tokens/verifier';

export { createPermissionRegistry } from './permission-registry';

export { JwtAuthGuard, TOKEN_VERIFIER, extractBearerToken } from './nest/jwt-auth.guard';
export { CurrentUser, extractCurrentUser } from './nest/current-user.decorator';
export { TenantId, extractTenantId } from './nest/tenant-id.decorator';
export {
  PermissionGuard,
  PERMISSION_CHECKER,
  type PermissionChecker,
} from './nest/permission.guard';
export { RequirePermission, REQUIRED_PERMISSION } from './nest/require-permission.decorator';
