import { Logger, UnauthorizedException } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { AuthenticatedUser } from '../types';
import { claimMappingFrom, mapClaims, type ClaimMapping } from './oidc-claims';

/**
 * 企业统一认证（OIDC 授权码 + PKCE）。
 *
 * 为什么是 OIDC：新建 Web 平台的事实标准；若贵司实际用 SAML，通常也会前置一个
 * 支持 OIDC 的代理。真要走纯 SAML，替换本文件即可，上层（守卫、控制器、前端）不动。
 *
 * 安全要点：
 * - **PKCE**：即使授权码在回调 URL 里被截获，没有 code_verifier 也换不到令牌
 * - **state**：防 CSRF，回调时必须能对上一次发起的请求
 * - **nonce**：防 ID Token 重放，验签后要比对
 * - ID Token 用 IdP 的 JWKS 公钥验签，**不接受 alg=none，也不信任 IdP 返回的 alg**
 */

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  mapping: ClaimMapping;
}

export function oidcConfigFrom(env: NodeJS.ProcessEnv): OidcConfig {
  return {
    issuer: (env.OIDC_ISSUER ?? '').replace(/\/$/, ''),
    clientId: env.OIDC_CLIENT_ID ?? '',
    clientSecret: env.OIDC_CLIENT_SECRET ?? '',
    redirectUri: env.OIDC_REDIRECT_URI ?? '',
    scope: env.OIDC_SCOPE ?? 'openid profile email',
    mapping: claimMappingFrom(env),
  };
}

interface PendingLogin {
  codeVerifier: string;
  nonce: string;
  createdAt: number;
  /** 登录成功后前端要跳回哪里 */
  returnTo: string;
}

/** 待回调的登录请求保留时长 */
const PENDING_TTL_MS = 10 * 60 * 1000;

export class OidcProvider {
  readonly name = 'oidc';

  private readonly logger = new Logger(OidcProvider.name);
  private readonly pending = new Map<string, PendingLogin>();
  private jwks?: JWTVerifyGetKey;
  private discovered?: { authorizationEndpoint: string; tokenEndpoint: string; jwksUri: string };

  constructor(
    private readonly config: OidcConfig,
    private readonly fetchImpl: typeof fetch = fetch,
    /**
     * ID Token 的验签密钥来源。默认按 IdP 的 jwks_uri 远程取。
     * 做成可注入是因为 jose 取 JWKS 走的是它自己的 HTTP 实现、绕开注入的 fetch，
     * 测试里没法打桩；也便于将来换成本地缓存的密钥集。
     */
    private readonly keyResolver?: JWTVerifyGetKey,
  ) {}

  /** 发起登录：生成 state/nonce/PKCE，返回要跳转的 IdP 地址 */
  async createAuthorizationUrl(returnTo: string): Promise<string> {
    const meta = await this.discover();

    const state = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    this.sweepExpired();
    this.pending.set(state, { codeVerifier, nonce, createdAt: Date.now(), returnTo });

    const url = new URL(meta.authorizationEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', this.config.scope);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return url.toString();
  }

  /** 处理回调：校验 state → 换令牌 → 验签 ID Token → 映射成平台身份 */
  async handleCallback(code: string, state: string): Promise<{ user: AuthenticatedUser; returnTo: string }> {
    const pendingLogin = this.pending.get(state);
    // state 一次性：用过即删，避免回调被重放
    this.pending.delete(state);

    if (!pendingLogin) {
      throw new UnauthorizedException('登录请求已失效，请重新发起');
    }
    if (Date.now() - pendingLogin.createdAt > PENDING_TTL_MS) {
      throw new UnauthorizedException('登录请求已超时，请重新发起');
    }

    const meta = await this.discover();
    const idToken = await this.exchangeCode(meta.tokenEndpoint, code, pendingLogin.codeVerifier);
    const claims = await this.verifyIdToken(idToken, pendingLogin.nonce);

    return { user: mapClaims(claims, this.config.mapping), returnTo: pendingLogin.returnTo };
  }

  private async exchangeCode(tokenEndpoint: string, code: string, codeVerifier: string): Promise<string> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code_verifier: codeVerifier,
    });

    const response = await this.fetchImpl(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!response.ok) {
      // 不把 IdP 的原始报文回显给前端，避免泄漏配置细节；只记服务端日志
      this.logger.error(`换取令牌失败：HTTP ${response.status}`);
      throw new UnauthorizedException('企业认证失败');
    }

    const payload = (await response.json()) as { id_token?: string };
    if (!payload.id_token) {
      throw new UnauthorizedException('企业认证未返回 ID Token');
    }

    return payload.id_token;
  }

  private async verifyIdToken(idToken: string, nonce: string): Promise<Record<string, unknown>> {
    const meta = await this.discover();
    this.jwks ??= this.keyResolver ?? createRemoteJWKSet(new URL(meta.jwksUri));

    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(idToken, this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.clientId,
      });
      payload = verified.payload as Record<string, unknown>;
    } catch (error) {
      this.logger.error(`ID Token 验签失败：${(error as Error).message}`);
      throw new UnauthorizedException('企业认证失败');
    }

    // nonce 必须对上，否则可能是重放别处签发的 ID Token
    if (payload.nonce !== nonce) {
      this.logger.error('ID Token 的 nonce 与本次登录请求不一致');
      throw new UnauthorizedException('企业认证失败');
    }

    return payload;
  }

  private async discover(): Promise<NonNullable<OidcProvider['discovered']>> {
    if (this.discovered) return this.discovered;

    const url = `${this.config.issuer}/.well-known/openid-configuration`;
    const response = await this.fetchImpl(url);
    if (!response.ok) {
      throw new Error(`读取 OIDC 元数据失败（${url}）：HTTP ${response.status}`);
    }

    const meta = (await response.json()) as {
      authorization_endpoint?: string;
      token_endpoint?: string;
      jwks_uri?: string;
    };

    if (!meta.authorization_endpoint || !meta.token_endpoint || !meta.jwks_uri) {
      throw new Error('OIDC 元数据缺少 authorization_endpoint / token_endpoint / jwks_uri');
    }

    this.discovered = {
      authorizationEndpoint: meta.authorization_endpoint,
      tokenEndpoint: meta.token_endpoint,
      jwksUri: meta.jwks_uri,
    };
    return this.discovered;
  }

  private sweepExpired(): void {
    const now = Date.now();
    for (const [state, entry] of this.pending) {
      if (now - entry.createdAt > PENDING_TTL_MS) this.pending.delete(state);
    }
  }

  /** 仅供测试与运维观察，不含任何密钥 */
  get pendingCount(): number {
    return this.pending.size;
  }
}
