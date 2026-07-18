import { UnauthorizedException } from '@nestjs/common';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { OidcProvider, oidcConfigFrom } from './oidc.provider';

const ISSUER = 'https://idp.example.com';
const CLIENT_ID = 'portal';

const ENV = {
  OIDC_ISSUER: ISSUER,
  OIDC_CLIENT_ID: CLIENT_ID,
  OIDC_CLIENT_SECRET: 'client-secret-value', // secrets-gate:allow 测试夹具
  OIDC_REDIRECT_URI: 'http://localhost:4000/api/v1/auth/sso/callback',
} as NodeJS.ProcessEnv;

const DISCOVERY = {
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
};

/** 一个最小的假 IdP：提供元数据、JWKS 与签发 ID Token 的能力 */
async function fakeIdp() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };

  const signIdToken = (claims: Record<string, unknown>, overrides: { issuer?: string; audience?: string } = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(overrides.issuer ?? ISSUER)
      .setAudience(overrides.audience ?? CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

  return { jwk, signIdToken };
}

/** 按 URL 分发的 fetch 打桩 */
function stubFetch(handlers: {
  jwk: JWK;
  idToken?: string;
  tokenStatus?: number;
  tokenBody?: unknown;
}) {
  return jest.fn(async (input: RequestInfo | URL) => {
    const url = String(input);

    if (url.endsWith('/.well-known/openid-configuration')) {
      return { ok: true, status: 200, json: async () => DISCOVERY } as Response;
    }
    if (url.endsWith('/jwks')) {
      return { ok: true, status: 200, json: async () => ({ keys: [handlers.jwk] }) } as Response;
    }
    if (url.endsWith('/token')) {
      const status = handlers.tokenStatus ?? 200;
      return {
        ok: status < 400,
        status,
        json: async () => handlers.tokenBody ?? { id_token: handlers.idToken },
      } as Response;
    }
    throw new Error(`未打桩的请求: ${url}`);
  }) as unknown as typeof fetch;
}

// jose 的 createRemoteJWKSet 取 JWKS 用的是**全局 fetch**，不走注入的那个，
// 所以这里必须把 global.fetch 也打桩，否则测试会真的去访问 idp.example.com
const originalFetch = global.fetch;
afterEach(() => {
  global.fetch = originalFetch;
});

describe('OidcProvider.createAuthorizationUrl', () => {
  it('带上 PKCE、state、nonce 等必需参数', async () => {
    const { jwk } = await fakeIdp();
    const provider = new OidcProvider(oidcConfigFrom(ENV), stubFetch({ jwk }), createLocalJWKSet({ keys: [jwk] }));

    const url = new URL(await provider.createAuthorizationUrl('/'));

    expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBeTruthy();
    expect(url.searchParams.get('nonce')).toBeTruthy();
  });

  it('URL 里不出现 client_secret 与 code_verifier —— 它们只在后端换令牌时用', async () => {
    const { jwk } = await fakeIdp();
    const provider = new OidcProvider(oidcConfigFrom(ENV), stubFetch({ jwk }), createLocalJWKSet({ keys: [jwk] }));

    const url = await provider.createAuthorizationUrl('/');

    expect(url).not.toContain('client-secret-value');
    expect(url).not.toContain('code_verifier');
  });

  it('每次发起的 state 都不同', async () => {
    const { jwk } = await fakeIdp();
    const provider = new OidcProvider(oidcConfigFrom(ENV), stubFetch({ jwk }), createLocalJWKSet({ keys: [jwk] }));

    const a = new URL(await provider.createAuthorizationUrl('/')).searchParams.get('state');
    const b = new URL(await provider.createAuthorizationUrl('/')).searchParams.get('state');

    expect(a).not.toBe(b);
  });
});

describe('OidcProvider.handleCallback', () => {
  async function setup(claimsOverride: Record<string, unknown> = {}, signOptions = {}) {
    const { jwk, signIdToken } = await fakeIdp();
    const provider = new OidcProvider(oidcConfigFrom(ENV), stubFetch({ jwk }), createLocalJWKSet({ keys: [jwk] }));
    const url = new URL(await provider.createAuthorizationUrl('/dashboard'));
    const state = url.searchParams.get('state')!;
    const nonce = url.searchParams.get('nonce')!;

    const idToken = await signIdToken(
      { sub: 'u1', name: '张三', tenants: ['wuxi-plant'], roles: ['admin'], nonce, ...claimsOverride },
      signOptions,
    );

    // 重新构造 provider 的 fetch，让 /token 返回刚签好的 ID Token
    const stub = stubFetch({ jwk, idToken });
    (provider as unknown as { fetchImpl: typeof fetch }).fetchImpl = stub;
    global.fetch = stub;

    return { provider, state, nonce, signIdToken, jwk };
  }

  it('正常回调返回映射后的身份与原始 returnTo', async () => {
    const { provider, state } = await setup();

    const result = await provider.handleCallback('the-code', state);

    expect(result.user).toMatchObject({ userId: 'u1', tenants: ['wuxi-plant'], roles: ['admin'] });
    expect(result.returnTo).toBe('/dashboard');
  });

  it('state 是一次性的 —— 重放同一个回调会被拒', async () => {
    const { provider, state } = await setup();
    await provider.handleCallback('the-code', state);

    await expect(provider.handleCallback('the-code', state)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('未知 state 直接拒绝（防 CSRF）', async () => {
    const { provider } = await setup();

    await expect(provider.handleCallback('the-code', 'forged-state')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('nonce 对不上时拒绝 —— 防止重放别处签发的 ID Token', async () => {
    const { provider, state } = await setup({ nonce: 'someone-elses-nonce' });

    await expect(provider.handleCallback('the-code', state)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('签发方不对的 ID Token 被拒', async () => {
    const { provider, state } = await setup({}, { issuer: 'https://evil.example.com' });

    await expect(provider.handleCallback('the-code', state)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('受众不是本客户端的 ID Token 被拒', async () => {
    const { provider, state } = await setup({}, { audience: 'another-app' });

    await expect(provider.handleCallback('the-code', state)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('换令牌失败时抛 401，且不回显 IdP 的原始报文', async () => {
    const { jwk } = await fakeIdp();
    const provider = new OidcProvider(
      oidcConfigFrom(ENV),
      stubFetch({ jwk, tokenStatus: 400, tokenBody: { error: 'invalid_grant', hint: '内部细节' } }),
      createLocalJWKSet({ keys: [jwk] }),
    );
    const state = new URL(await provider.createAuthorizationUrl('/')).searchParams.get('state')!;

    const error = await provider.handleCallback('bad-code', state).catch((e) => e);

    expect(error).toBeInstanceOf(UnauthorizedException);
    expect(JSON.stringify(error.getResponse())).not.toContain('内部细节');
  });

  it('IdP 没返回 id_token 时抛 401', async () => {
    const { jwk } = await fakeIdp();
    const provider = new OidcProvider(
      oidcConfigFrom(ENV),
      stubFetch({ jwk, tokenBody: { access_token: 'only-access-token' } }),
      createLocalJWKSet({ keys: [jwk] }),
    );
    const state = new URL(await provider.createAuthorizationUrl('/')).searchParams.get('state')!;

    await expect(provider.handleCallback('the-code', state)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
