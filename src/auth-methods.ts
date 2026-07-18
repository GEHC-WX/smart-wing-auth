/**
 * 登录方式的可用性判定。**纯函数，只看配置，不做 IO**，便于单测。
 *
 * 规则（与产品要求一致）：
 *   - 开发环境：手动维护的预设账户可用；SSO 若配置了也一并显示，便于联调
 *   - 正式环境：**预设账户完全关闭**（不是隐藏按钮，是服务端直接拒绝），
 *     只保留 SSO，且前端默认走 SSO
 *
 * 「隐藏」若只做在前端，等于没做 —— 按钮不显示但接口还在，构造一个请求照样能用
 * 预设账户登录。所以这里的判定同时驱动前端展示与服务端放行。
 */

export interface AuthMethods {
  /** 手动维护的预设账户登录（仅开发环境） */
  devAccounts: boolean;
  /** 企业统一认证 */
  sso: boolean;
  /** 前端默认高亮/直接跳转的方式 */
  preferred: 'sso' | 'devAccounts' | 'none';
  /** SSO 未启用时的原因，便于排查配置问题（不含任何密钥） */
  ssoDisabledReason?: string;
}

export function isProduction(env: NodeJS.ProcessEnv): boolean {
  return env.NODE_ENV === 'production';
}

/** SSO 需要这几项配置齐全才算可用 */
export const REQUIRED_OIDC_VARS = [
  'OIDC_ISSUER',
  'OIDC_CLIENT_ID',
  'OIDC_CLIENT_SECRET',
  'OIDC_REDIRECT_URI',
] as const;

export function missingOidcVars(env: NodeJS.ProcessEnv): string[] {
  return REQUIRED_OIDC_VARS.filter((name) => !env[name]);
}

export function resolveAuthMethods(env: NodeJS.ProcessEnv): AuthMethods {
  const production = isProduction(env);
  const missing = missingOidcVars(env);
  const sso = missing.length === 0;

  // 预设账户只在非生产环境可用，且必须配了账户与口令
  const devAccounts = !production && Boolean(env.DEV_AUTH_USERS && env.DEV_AUTH_PASSWORD);

  return {
    devAccounts,
    sso,
    // 正式环境一律默认 SSO；开发环境有 SSO 也优先展示 SSO，
    // 让开发期就走与生产一致的路径，避免上线才发现流程没通
    preferred: sso ? 'sso' : devAccounts ? 'devAccounts' : 'none',
    ...(sso ? {} : { ssoDisabledReason: `缺少配置：${missing.join('、')}` }),
  };
}

/**
 * 生产环境禁用预设账户登录。
 * 服务端据此直接拒绝 /auth/login，而不是只在前端藏起入口。
 */
export function devLoginAllowed(env: NodeJS.ProcessEnv): boolean {
  return resolveAuthMethods(env).devAccounts;
}
