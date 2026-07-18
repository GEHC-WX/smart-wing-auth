import { devLoginAllowed, missingOidcVars, resolveAuthMethods } from './auth-methods';

const FULL_OIDC = {
  OIDC_ISSUER: 'https://idp.example.com',
  OIDC_CLIENT_ID: 'portal',
  OIDC_CLIENT_SECRET: 'x', // secrets-gate:allow 测试夹具
  OIDC_REDIRECT_URI: 'http://localhost:4000/api/v1/auth/sso/callback',
} as NodeJS.ProcessEnv;

const DEV_ACCOUNTS = {
  DEV_AUTH_USERS: 'a:t1:admin',
  DEV_AUTH_PASSWORD: 'x', // secrets-gate:allow 测试夹具
} as NodeJS.ProcessEnv;

describe('missingOidcVars', () => {
  it('配置齐全时无缺项', () => {
    expect(missingOidcVars(FULL_OIDC)).toEqual([]);
  });

  it('列出所有缺失项，便于一次性补齐', () => {
    expect(missingOidcVars({} as NodeJS.ProcessEnv)).toEqual([
      'OIDC_ISSUER',
      'OIDC_CLIENT_ID',
      'OIDC_CLIENT_SECRET',
      'OIDC_REDIRECT_URI',
    ]);
  });
});

describe('resolveAuthMethods —— 开发环境', () => {
  it('只配预设账户时，预设账户可用、SSO 不可用', () => {
    const methods = resolveAuthMethods({ ...DEV_ACCOUNTS } as NodeJS.ProcessEnv);

    expect(methods).toMatchObject({ devAccounts: true, sso: false, preferred: 'devAccounts' });
    expect(methods.ssoDisabledReason).toContain('OIDC_ISSUER');
  });

  it('两者都配时都可用，且默认走 SSO —— 开发期就走与生产一致的路径', () => {
    const methods = resolveAuthMethods({ ...DEV_ACCOUNTS, ...FULL_OIDC } as NodeJS.ProcessEnv);

    expect(methods).toMatchObject({ devAccounts: true, sso: true, preferred: 'sso' });
  });

  it('什么都没配时 preferred 为 none', () => {
    expect(resolveAuthMethods({} as NodeJS.ProcessEnv).preferred).toBe('none');
  });

  it('只配了账户没配口令，不算可用', () => {
    expect(
      resolveAuthMethods({ DEV_AUTH_USERS: 'a:t1' } as NodeJS.ProcessEnv).devAccounts,
    ).toBe(false);
  });
});

describe('resolveAuthMethods —— 正式环境', () => {
  const prod = { ...DEV_ACCOUNTS, ...FULL_OIDC, NODE_ENV: 'production' } as NodeJS.ProcessEnv;

  it('即便配了预设账户也一律停用', () => {
    expect(resolveAuthMethods(prod)).toMatchObject({
      devAccounts: false,
      sso: true,
      preferred: 'sso',
    });
  });

  it('devLoginAllowed 在生产环境恒为 false —— 服务端据此拒绝 /auth/login', () => {
    expect(devLoginAllowed(prod)).toBe(false);
    expect(devLoginAllowed({ ...DEV_ACCOUNTS } as NodeJS.ProcessEnv)).toBe(true);
  });

  it('生产环境且 SSO 未配置时无任何可用登录方式', () => {
    const methods = resolveAuthMethods({ ...DEV_ACCOUNTS, NODE_ENV: 'production' } as NodeJS.ProcessEnv);

    expect(methods).toMatchObject({ devAccounts: false, sso: false, preferred: 'none' });
  });
});
