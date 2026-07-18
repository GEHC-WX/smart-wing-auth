/**
 * ID Token 的 claims → 平台身份的映射。**纯函数**，OIDC 网络交互在 oidc.provider.ts。
 *
 * 各家 IdP 放租户和角色的字段名都不一样（Entra ID 用 groups / roles，
 * Okta 常用自定义 claim，PingFederate 又是另一套），所以字段名做成可配置，
 * 而不是写死。接入时只改环境变量。
 */
import type { AuthenticatedUser } from '../types';

export interface ClaimMapping {
  /** 用户唯一标识，默认 sub */
  userIdClaim: string;
  /** 显示名，默认 name，回退到 preferred_username / email / sub */
  displayNameClaim: string;
  /** 租户列表所在 claim */
  tenantsClaim: string;
  /** 角色列表所在 claim */
  rolesClaim: string;
  /**
   * IdP 的组名 → 平台角色名的映射，形如 "GEHC-Plant-Admins=admin,GEHC-Plant-Viewers=viewer"。
   * 不配则原样使用 IdP 给的角色名。
   */
  roleAliases: Record<string, string>;
  /** 未匹配到任何租户时的兜底（可空）。为空则该用户登录后看不到任何模块 */
  defaultTenants: string[];
}

export function claimMappingFrom(env: NodeJS.ProcessEnv): ClaimMapping {
  return {
    userIdClaim: env.OIDC_CLAIM_USER_ID ?? 'sub',
    displayNameClaim: env.OIDC_CLAIM_DISPLAY_NAME ?? 'name',
    tenantsClaim: env.OIDC_CLAIM_TENANTS ?? 'tenants',
    rolesClaim: env.OIDC_CLAIM_ROLES ?? 'roles',
    roleAliases: parseAliases(env.OIDC_ROLE_ALIASES ?? ''),
    defaultTenants: (env.OIDC_DEFAULT_TENANTS ?? '')
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean),
  };
}

export function parseAliases(raw: string): Record<string, string> {
  const aliases: Record<string, string> = {};

  for (const pair of raw.split(',').map((p) => p.trim()).filter(Boolean)) {
    const [from, to] = pair.split('=').map((p) => p?.trim() ?? '');
    if (from && to) aliases[from] = to;
  }

  return aliases;
}

/** claim 可能是数组、逗号分隔字符串、或单个字符串，统一成数组 */
export function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((v) => String(v).trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value.split(',').map((v) => v.trim()).filter(Boolean);
  }
  return [];
}

export function mapClaims(
  claims: Record<string, unknown>,
  mapping: ClaimMapping,
): AuthenticatedUser {
  const userId = String(claims[mapping.userIdClaim] ?? claims.sub ?? '').trim();
  if (!userId) {
    throw new Error(`ID Token 缺少用户标识 claim: ${mapping.userIdClaim}`);
  }

  const displayName =
    String(
      claims[mapping.displayNameClaim] ??
        claims.name ??
        claims.preferred_username ??
        claims.email ??
        userId,
    ).trim() || userId;

  const rawRoles = toStringArray(claims[mapping.rolesClaim]);
  // 未在别名表里的组名原样保留 —— 平台侧对未知角色本就是「不授予任何能力」，
  // 在这里丢掉反而会让排查时看不出 IdP 到底给了什么
  const roles = rawRoles.map((role) => mapping.roleAliases[role] ?? role);

  const tenants = toStringArray(claims[mapping.tenantsClaim]);

  return {
    userId,
    displayName,
    tenants: tenants.length > 0 ? tenants : mapping.defaultTenants,
    roles,
  };
}
