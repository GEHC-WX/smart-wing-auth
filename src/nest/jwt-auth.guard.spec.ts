import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { createLocalJWKSet, type JWK } from 'jose';
import { generateKeyPairSync } from 'node:crypto';
import { TokenIssuer } from '../tokens/issuer';
import { toPublicJwks } from '../tokens/keys';
import { TokenVerifier } from '../tokens/verifier';
import { extractBearerToken, JwtAuthGuard } from './jwt-auth.guard';
import type { RequestWithUser } from '../types';

const ISSUER = 'https://portal.example.com';
const USER = { userId: 'u1', displayName: 'U1', tenants: ['t1'], roles: ['admin'] };

function ctxOf(request: Partial<RequestWithUser>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function rsaPem(): string {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey as unknown as string;
}

async function setup() {
  const issuer = new TokenIssuer({
    issuer: ISSUER,
    ttlSeconds: 3600,
    keyPair: { privateKeyPem: rsaPem(), keyId: 'k1' },
  });
  const jwks = await toPublicJwks([issuer.keyPair]);
  const verifier = new TokenVerifier(
    { jwksUri: 'unused', issuer: ISSUER },
    createLocalJWKSet(jwks as { keys: JWK[] }),
  );

  return { issuer, guard: new JwtAuthGuard(verifier) };
}

describe('extractBearerToken', () => {
  it('取出 Bearer 令牌', () => {
    expect(extractBearerToken({ headers: { authorization: 'Bearer abc' } })).toBe('abc');
  });

  it('大小写不敏感', () => {
    expect(extractBearerToken({ headers: { authorization: 'bearer abc' } })).toBe('abc');
  });

  it('非 Bearer 方案不接受', () => {
    expect(extractBearerToken({ headers: { authorization: 'Basic xyz' } })).toBeNull();
  });

  it('缺失、只有方案名、类型不对时都返回 null', () => {
    expect(extractBearerToken({ headers: {} })).toBeNull();
    expect(extractBearerToken({ headers: { authorization: 'Bearer' } })).toBeNull();
    expect(extractBearerToken({ headers: { authorization: 123 } })).toBeNull();
  });
});

describe('JwtAuthGuard', () => {
  it('门户签发的令牌放行，并把身份挂到 request 上', async () => {
    const { issuer, guard } = await setup();
    const { accessToken } = await issuer.issue(USER);
    const request: Partial<RequestWithUser> = { headers: { authorization: `Bearer ${accessToken}` } };

    await expect(guard.canActivate(ctxOf(request))).resolves.toBe(true);
    expect(request.user).toEqual(USER);
  });

  it('无令牌抛 401', async () => {
    const { guard } = await setup();

    await expect(guard.canActivate(ctxOf({ headers: {} }))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('别人私钥签发的令牌抛 401', async () => {
    const { guard } = await setup();
    const attacker = new TokenIssuer({
      issuer: ISSUER,
      ttlSeconds: 3600,
      keyPair: { privateKeyPem: rsaPem(), keyId: 'k1' },
    });
    const { accessToken } = await attacker.issue({ ...USER, roles: ['admin'] });

    await expect(
      guard.canActivate(ctxOf({ headers: { authorization: `Bearer ${accessToken}` } })),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('乱码令牌抛 401', async () => {
    const { guard } = await setup();

    await expect(
      guard.canActivate(ctxOf({ headers: { authorization: 'Bearer not-a-jwt' } })),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('失败时不回显具体原因（乱码与伪造提示一致）', async () => {
    const { guard } = await setup();
    const attacker = new TokenIssuer({
      issuer: ISSUER,
      ttlSeconds: 3600,
      keyPair: { privateKeyPem: rsaPem(), keyId: 'k1' },
    });
    const { accessToken } = await attacker.issue(USER);

    const a = await guard
      .canActivate(ctxOf({ headers: { authorization: 'Bearer not-a-jwt' } }))
      .catch((e) => e);
    const b = await guard
      .canActivate(ctxOf({ headers: { authorization: `Bearer ${accessToken}` } }))
      .catch((e) => e);

    expect(a.message).toBe(b.message);
  });
});
