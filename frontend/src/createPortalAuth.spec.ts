import { createPortalAuth, type PortalAuthUser } from './createPortalAuth';

/** 最小 localStorage mock：Node 测试环境没有 window/localStorage */
function mockLocalStorage() {
  const store = new Map<string, string>();
  const storage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    get length() {
      return store.size;
    },
  };
  (globalThis as { localStorage?: unknown }).localStorage = storage;
  return storage;
}

interface TestCapabilities {
  canReadAssets: boolean;
}

function user(overrides: Partial<PortalAuthUser<TestCapabilities>> = {}): PortalAuthUser<TestCapabilities> {
  return {
    userId: 'u1',
    displayName: '测试用户',
    tenants: ['t1', 't2'],
    roles: ['viewer'],
    capabilities: { canReadAssets: true },
    ...overrides,
  };
}

function makeAuth(moduleId: string) {
  return createPortalAuth<TestCapabilities>({ moduleId });
}

describe('createPortalAuth', () => {
  beforeEach(() => {
    mockLocalStorage();
    // redirectToPortal 用 window.location.href；测试里不真正导航，
    // 通过 spy 在调用前替换。其余函数不触碰 window。
    (globalThis as { window?: unknown }).window = {
      location: { hostname: 'test-host', origin: 'http://test-host:5100', pathname: '/apps/test' },
    };
  });

  it('令牌 key 带模块前缀，多个模块互不串扰', () => {
    const a = makeAuth('module-a');
    const b = makeAuth('module-b');

    a.setSession('tok-a', user({ tenants: ['t1'] }));
    expect(b.getToken()).toBeNull();
    expect(a.getToken()).toBe('tok-a');
  });

  it('setSession 记录令牌与用户，并归一化选中租户到用户租户列表', () => {
    const auth = makeAuth('it-ot');

    auth.setSession('tok', user({ tenants: ['t1', 't2'] }));
    expect(auth.getToken()).toBe('tok');
    expect(auth.getUser()?.displayName).toBe('测试用户');
    expect(auth.getActiveTenant()).toBe('t1'); // 未选过 → 用第一个
  });

  it('选中租户不在用户租户列表时，setSession 重置到第一个租户', () => {
    const auth = makeAuth('it-ot');
    auth.setSelectedTenant('stale');
    auth.setSession('tok', user({ tenants: ['t1'] }));

    expect(auth.getActiveTenant()).toBe('t1');
  });

  it('clearSession 清空令牌、用户与两个 storage key', () => {
    const auth = makeAuth('it-ot');
    auth.setSession('tok', user({ tenants: ['t1'] }));
    auth.setSelectedTenant('t1');

    auth.clearSession();
    expect(auth.getToken()).toBeNull();
    expect(auth.getUser()).toBeNull();
    expect(localStorage.getItem('it-ot:token')).toBeNull();
    expect(localStorage.getItem('it-ot:tenant')).toBeNull();
  });

  it('redirectToPortal 带 returnToModule 参数跳门户', () => {
    const auth = makeAuth('it-ot');
    const location = { hostname: 'test-host', origin: 'http://test-host:5100', pathname: '/apps/it-ot' };
    const locationMock: { href: string } = { href: '' };
    Object.defineProperty(locationMock, 'origin', { value: location.origin });
    Object.defineProperty(locationMock, 'pathname', { value: location.pathname });
    Object.defineProperty(locationMock, 'hostname', { value: location.hostname });
    (globalThis as { window?: unknown }).window = { location: locationMock };

    auth.redirectToPortal();
    expect(locationMock.href).toContain('http://test-host:5100/?returnToModule=');
    expect(locationMock.href).toContain(encodeURIComponent('http://test-host:5100/apps/it-ot'));
  });

  it('setSelectedTenant 传空字符串时移除 storage key', () => {
    const auth = makeAuth('it-ot');
    auth.setSelectedTenant('t1');
    expect(localStorage.getItem('it-ot:tenant')).toBe('t1');

    auth.setSelectedTenant('');
    expect(localStorage.getItem('it-ot:tenant')).toBeNull();
    expect(auth.getSelectedTenant()).toBe('');
  });

  it('setSession 用户无租户时 activeTenant 为空字符串', () => {
    const auth = makeAuth('it-ot');
    auth.setSession('tok', user({ tenants: [] }));

    expect(auth.getActiveTenant()).toBe('');
  });

  it('getActiveTenant 优先返回已选且有权访问的租户', () => {
    const auth = makeAuth('it-ot');
    auth.setSession('tok', user({ tenants: ['t1', 't2'] }));
    auth.setSelectedTenant('t2');

    expect(auth.getActiveTenant()).toBe('t2');
  });

  it('getActiveTenant 在选中租户无权时回退到第一个', () => {
    const auth = makeAuth('it-ot');
    auth.setSession('tok', user({ tenants: ['t1', 't2'] }));
    auth.setSelectedTenant('other-tenant');

    expect(auth.getActiveTenant()).toBe('t1');
  });

  it('PORTAL_WEB / PREVIEW_MODE 优先读注入的 env', () => {
    const auth = createPortalAuth<TestCapabilities>({
      moduleId: 'it-ot',
      env: {
        VITE_PORTAL_WEB_URL: 'https://portal.example.com',
        VITE_PREVIEW_MODE: 'true',
      },
    });
    expect(auth.PORTAL_WEB).toBe('https://portal.example.com');
    expect(auth.PREVIEW_MODE).toBe(true);
  });

  it('未配置 env 时 PORTAL_WEB 回退到当前主机名 + 默认端口', () => {
    const auth = makeAuth('it-ot');
    expect(auth.PORTAL_WEB).toBe('http://test-host:5100');
  });

  it('exchangePortalCode 成功后写入会话并返回用户', async () => {
    const auth = makeAuth('it-ot');
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ accessToken: 'new-tok', user: user() }),
    });
    (globalThis as { fetch?: unknown }).fetch = fetchMock;

    const result = await auth.exchangePortalCode('code-1');
    expect(fetchMock).toHaveBeenCalledWith(
      'http://test-host:4000/api/v1/auth/sso/exchange',
      expect.objectContaining({ method: 'POST', body: JSON.stringify({ code: 'code-1' }) }),
    );
    expect(result.userId).toBe('u1');
    expect(auth.getToken()).toBe('new-tok');
  });

  it('exchangePortalCode 在门户握手失败时抛错', async () => {
    const auth = makeAuth('it-ot');
    (globalThis as { fetch?: unknown }).fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ message: 'bad code' }),
    });

    await expect(auth.exchangePortalCode('bad')).rejects.toThrow('门户握手失败');
    expect(auth.getToken()).toBeNull();
  });
});
