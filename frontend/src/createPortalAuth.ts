/**
 * 门户 SSO 前端握手 + 会话管理（跨模块共享）。
 *
 * 各业务模块此前各自复制了一份几乎相同的 auth.ts（TOKEN_KEY/TENANT_KEY
 * 前缀、HOST/PORTAL_WEB/PORTAL_API 计算、setSession/exchangePortalCode/
 * getActiveTenant 等逻辑完全一样，只有模块 id 前缀不同）。这份重复是
 * 历史教训的重演：复制时「源码复制了、测试忘了」，改一处要同步多处。
 *
 * 本包用 `createPortalAuth({ moduleId })` 工厂收敛公共逻辑，模块侧只留
 * 薄壳 + 各自的能力类型。行为与各模块原 auth.ts 逐项对齐：
 * - 令牌/租户存 localStorage，key 带模块前缀（`<moduleId>:token`）
 * - 门户地址：环境变量优先（VITE_PORTAL_WEB_URL / VITE_PORTAL_API_URL），
 *   本地/内网回退到当前主机名（避免每人单独配 .env）
 * - 前端不自行按 roles 推导能力，能力取自后端 /me（判权规则只存一份）
 */

export interface PortalAuthUser<C = Record<string, boolean>> {
  userId: string;
  displayName: string;
  tenants: string[];
  roles: string[];
  capabilities?: C;
}

export interface PortalAuthOptions {
  /** 模块 id，用于给 localStorage key 加前缀，避免多模块共用一套 key。 */
  moduleId: string;
  /**
   * 取令牌 key 时读取的 import.meta.env 对象。测试注入用；生产各模块
   * 传 `import.meta.env`。
   */
  env?: Record<string, string | undefined>;
}

export interface PortalAuth<C = Record<string, boolean>> {
  PORTAL_WEB: string;
  PREVIEW_MODE: boolean;
  getToken(): string | null;
  getUser(): PortalAuthUser<C> | null;
  setSession(accessToken: string, user: PortalAuthUser<C>): void;
  clearSession(): void;
  redirectToPortal(): void;
  exchangePortalCode(code: string): Promise<PortalAuthUser<C>>;
  getSelectedTenant(): string;
  setSelectedTenant(tenant: string): void;
  getActiveTenant(): string;
}

export function createPortalAuth<C = Record<string, boolean>>(
  options: PortalAuthOptions,
): PortalAuth<C> {
  const { moduleId, env = {} } = options;
  const TOKEN_KEY = `${moduleId}:token`;
  const TENANT_KEY = `${moduleId}:tenant`;

  const HOST = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  const PORTAL_WEB = env.VITE_PORTAL_WEB_URL ?? `https://${HOST}`;
  const PORTAL_API = env.VITE_PORTAL_API_URL ?? `http://${HOST}:4000/api/v1`;
  const PREVIEW_MODE = env.VITE_PREVIEW_MODE === 'true';

  let token: string | null = localStorage.getItem(TOKEN_KEY);
  let currentUser: PortalAuthUser<C> | null = null;

  function getToken(): string | null {
    return token;
  }

  function getUser(): PortalAuthUser<C> | null {
    return currentUser;
  }

  function setSession(accessToken: string, user: PortalAuthUser<C>): void {
    token = accessToken;
    currentUser = user;
    localStorage.setItem(TOKEN_KEY, accessToken);

    if (!user.tenants.includes(getSelectedTenant())) {
      setSelectedTenant(user.tenants[0] ?? '');
    }
  }

  function clearSession(): void {
    token = null;
    currentUser = null;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(TENANT_KEY);
  }

  /** 跳门户登录。门户登录完会带一次性码跳回本页 */
  function redirectToPortal(): void {
    const back = encodeURIComponent(window.location.origin + window.location.pathname);
    window.location.href = `${PORTAL_WEB}/?returnToModule=${back}`;
  }

  /** 拿门户给的一次性码换令牌 */
  async function exchangePortalCode(code: string): Promise<PortalAuthUser<C>> {
    const response = await fetch(`${PORTAL_API}/auth/sso/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });

    if (!response.ok) {
      throw new Error('门户握手失败，请重新从门户进入');
    }

    const result = (await response.json()) as {
      accessToken: string;
      user: PortalAuthUser<C>;
    };
    setSession(result.accessToken, result.user);
    return result.user;
  }

  function getSelectedTenant(): string {
    return localStorage.getItem(TENANT_KEY) ?? '';
  }

  function setSelectedTenant(tenant: string): void {
    if (tenant) localStorage.setItem(TENANT_KEY, tenant);
    else localStorage.removeItem(TENANT_KEY);
  }

  function getActiveTenant(): string {
    const tenants = currentUser?.tenants ?? [];
    const selected = getSelectedTenant();
    return selected && tenants.includes(selected) ? selected : (tenants[0] ?? '');
  }

  return {
    PORTAL_WEB,
    PREVIEW_MODE,
    getToken,
    getUser,
    setSession,
    clearSession,
    redirectToPortal,
    exchangePortalCode,
    getSelectedTenant,
    setSelectedTenant,
    getActiveTenant,
  };
}
