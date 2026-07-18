import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { AuthenticatedUser } from '../types';
import type { TokenClaims } from './issuer';

/**
 * 平台访问令牌的验签。**各模块只需要这一段**：
 * 按门户的 JWKS 地址取公钥验签，模块自身不持有任何签发能力，也就无法伪造令牌。
 *
 * 这是 RS256 相对 HS256 的核心差别：HS256 下模块必须持有签发密钥才能验签，
 * 等于每个模块都能签出「门户签发」的令牌。
 */

export interface VerifierConfig {
  /** 门户的 JWKS 地址，如 https://portal.example.com/.well-known/jwks.json */
  jwksUri: string;
  /** 必须与签发方一致，防止接受别处签发的令牌 */
  issuer: string;
  /** 本模块的受众标识。签发方设了 audience 时必须核对 */
  audience?: string;
  /** 允许的时钟偏移（秒），跨机部署时留一点余量 */
  clockToleranceSeconds?: number;
}

export class TokenVerifier {
  private jwks?: JWTVerifyGetKey;

  constructor(
    private readonly config: VerifierConfig,
    /**
     * 密钥来源。默认按 jwksUri 远程取（jose 会自带缓存与密钥轮换处理）。
     * 可注入是因为 jose 取 JWKS 走它自己的 HTTP 实现，测试里没法用打桩的 fetch 拦截。
     */
    private readonly keyResolver?: JWTVerifyGetKey,
  ) {}

  /**
   * 验签并还原身份。任何一步不通过都抛 Error，调用方（守卫）统一转成 401 ——
   * 不区分「过期 / 签名不对 / 受众不符」，避免给探测者额外信息。
   */
  async verify(token: string): Promise<AuthenticatedUser> {
    this.jwks ??= this.keyResolver ?? createRemoteJWKSet(new URL(this.config.jwksUri));

    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.config.issuer,
      ...(this.config.audience ? { audience: this.config.audience } : {}),
      clockTolerance: this.config.clockToleranceSeconds ?? 5,
      // 只接受 RS256。不写死的话，攻击者可以拿一个 alg=HS256 的令牌，
      // 用公钥当共享密钥来伪造签名（经典的 alg 混淆攻击）
      algorithms: ['RS256'],
    });

    const claims = payload as unknown as TokenClaims;
    if (!claims.sub) {
      throw new Error('令牌缺少 sub');
    }

    return {
      userId: claims.sub,
      displayName: claims.name ?? claims.sub,
      tenants: Array.isArray(claims.tenants) ? claims.tenants : [],
      roles: Array.isArray(claims.roles) ? claims.roles : [],
    };
  }
}
