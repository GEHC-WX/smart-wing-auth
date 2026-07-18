import { generateKeyPairSync } from 'node:crypto';
import { createLocalJWKSet, exportJWK, SignJWT, type JWK } from 'jose';
import { loadKeyPair, normalizePem, toPublicJwks } from './keys';
import { TokenIssuer } from './issuer';
import { TokenVerifier } from './verifier';

const USER = {
  userId: 'u1',
  displayName: '张三',
  tenants: ['wuxi-plant', 'shanghai-plant'],
  roles: ['admin'],
};

const ISSUER = 'https://portal.example.com';

function rsaPem(): string {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey as unknown as string;
}

async function setup(overrides: { audience?: string } = {}) {
  const pem = rsaPem();
  const issuer = new TokenIssuer({
    issuer: ISSUER,
    ttlSeconds: 3600,
    keyPair: { privateKeyPem: pem, keyId: 'portal-key-1' },
    ...(overrides.audience ? { audience: overrides.audience } : {}),
  });

  const jwks = await toPublicJwks([issuer.keyPair]);
  const verifier = new TokenVerifier(
    { jwksUri: `${ISSUER}/.well-known/jwks.json`, issuer: ISSUER, ...overrides },
    createLocalJWKSet(jwks as { keys: JWK[] }),
  );

  return { issuer, verifier, jwks, pem };
}

describe('normalizePem', () => {
  it('把单行 PEM 里的 \\n 还原成真换行 —— 很多部署系统只能传单行', () => {
    expect(normalizePem('-----BEGIN-----\\nAAA\\n-----END-----')).toContain('\n');
  });

  it('已经是多行的原样返回', () => {
    const pem = '-----BEGIN-----\nAAA\n-----END-----';
    expect(normalizePem(pem)).toBe(pem);
  });
});

describe('loadKeyPair', () => {
  it('装载 RSA 私钥并派生公钥', () => {
    const pair = loadKeyPair({ privateKeyPem: rsaPem(), keyId: 'k1' });

    expect(pair.keyId).toBe('k1');
    expect(pair.privateKey.asymmetricKeyType).toBe('rsa');
    expect(pair.publicKey.asymmetricKeyType).toBe('rsa');
  });

  it('空私钥报可读错误', () => {
    expect(() => loadKeyPair({ privateKeyPem: '  ', keyId: 'k1' })).toThrow('缺少 RS256 私钥');
  });

  it('私钥格式不对时报可读错误，而不是抛底层异常', () => {
    expect(() => loadKeyPair({ privateKeyPem: 'not-a-pem', keyId: 'k1' })).toThrow('解析失败');
  });

  it('非 RSA 密钥被拒 —— RS256 必须是 RSA', () => {
    const ec = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    }).privateKey as unknown as string;

    expect(() => loadKeyPair({ privateKeyPem: ec, keyId: 'k1' })).toThrow('需要 RSA 私钥');
  });
});

describe('toPublicJwks', () => {
  it('只导出公钥参数，绝不含私钥分量', async () => {
    const pair = loadKeyPair({ privateKeyPem: rsaPem(), keyId: 'k1' });
    const jwks = await toPublicJwks([pair]);
    const serialized = JSON.stringify(jwks);

    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', kid: 'k1', alg: 'RS256', use: 'sig' });
    // d/p/q/dp/dq/qi 是 RSA 私钥分量，一个都不能出现
    for (const secretParam of ['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"']) {
      expect(serialized).not.toContain(secretParam);
    }
  });

  it('私钥对象误传进来也不会泄漏私钥分量', async () => {
    const pair = loadKeyPair({ privateKeyPem: rsaPem(), keyId: 'k1' });
    // 故意把 publicKey 换成 privateKey，模拟将来重构时的手滑
    const jwks = await toPublicJwks([{ ...pair, publicKey: pair.privateKey }]);

    expect(JSON.stringify(jwks)).not.toContain('"d"');
  });
});

describe('签发与验签', () => {
  it('门户签发的令牌，模块用 JWKS 公钥能验通过并还原身份', async () => {
    const { issuer, verifier } = await setup();

    const { accessToken, expiresIn } = await issuer.issue(USER);

    expect(expiresIn).toBe(3600);
    await expect(verifier.verify(accessToken)).resolves.toEqual(USER);
  });

  it('令牌头部带 kid，验签方据此选公钥（密钥轮换的前提）', async () => {
    const { issuer } = await setup();
    const { accessToken } = await issuer.issue(USER);

    const header = JSON.parse(Buffer.from(accessToken.split('.')[0], 'base64url').toString());

    expect(header).toMatchObject({ alg: 'RS256', kid: 'portal-key-1' });
  });

  it('别人用自己的私钥签的令牌验不过 —— 这正是 RS256 相对 HS256 的意义', async () => {
    const { verifier } = await setup();
    const attacker = new TokenIssuer({
      issuer: ISSUER,
      ttlSeconds: 3600,
      keyPair: { privateKeyPem: rsaPem(), keyId: 'portal-key-1' },
    });

    const { accessToken } = await attacker.issue({ ...USER, roles: ['admin'] });

    await expect(verifier.verify(accessToken)).rejects.toThrow();
  });

  it('拒绝 alg 混淆攻击：拿公钥当 HS256 共享密钥伪造的令牌不认', async () => {
    const { issuer, verifier } = await setup();
    const publicJwk = await exportJWK(issuer.keyPair.publicKey);

    // 攻击手法：把公钥（本就是公开的）当作 HMAC 密钥去签
    const forged = await new SignJWT({ sub: 'evil', name: 'evil', tenants: ['wuxi-plant'], roles: ['admin'] })
      .setProtectedHeader({ alg: 'HS256', kid: 'portal-key-1' })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(Buffer.from(JSON.stringify(publicJwk)));

    await expect(verifier.verify(forged)).rejects.toThrow();
  });

  it('签发方不符的令牌被拒', async () => {
    const { verifier, issuer } = await setup();
    const other = new TokenIssuer({
      issuer: 'https://evil.example.com',
      ttlSeconds: 3600,
      keyPair: { privateKeyPem: (issuer as never as { config: { keyPair: { privateKeyPem: string } } }).config.keyPair.privateKeyPem, keyId: 'portal-key-1' },
    });

    const { accessToken } = await other.issue(USER);

    await expect(verifier.verify(accessToken)).rejects.toThrow();
  });

  it('受众不符的令牌被拒 —— 发给别的模块的令牌不能拿来用', async () => {
    const pem = rsaPem();
    const issuer = new TokenIssuer({
      issuer: ISSUER,
      audience: 'module-a',
      ttlSeconds: 3600,
      keyPair: { privateKeyPem: pem, keyId: 'k1' },
    });
    const jwks = await toPublicJwks([issuer.keyPair]);
    const verifierForB = new TokenVerifier(
      { jwksUri: 'x', issuer: ISSUER, audience: 'module-b' },
      createLocalJWKSet(jwks as { keys: JWK[] }),
    );

    const { accessToken } = await issuer.issue(USER);

    await expect(verifierForB.verify(accessToken)).rejects.toThrow();
  });

  it('过期令牌被拒', async () => {
    const pem = rsaPem();
    const issuer = new TokenIssuer({
      issuer: ISSUER,
      ttlSeconds: -10,
      keyPair: { privateKeyPem: pem, keyId: 'k1' },
    });
    const jwks = await toPublicJwks([issuer.keyPair]);
    const verifier = new TokenVerifier(
      { jwksUri: 'x', issuer: ISSUER, clockToleranceSeconds: 0 },
      createLocalJWKSet(jwks as { keys: JWK[] }),
    );

    const { accessToken } = await issuer.issue(USER);

    await expect(verifier.verify(accessToken)).rejects.toThrow();
  });

  it('缺 tenants/roles 的令牌还原为空数组，不产生 undefined', async () => {
    const { issuer, verifier } = await setup();
    const { accessToken } = await issuer.issue({
      userId: 'u2',
      displayName: 'U2',
      tenants: [],
      roles: [],
    });

    const user = await verifier.verify(accessToken);

    expect(user.tenants).toEqual([]);
    expect(user.roles).toEqual([]);
  });
});
