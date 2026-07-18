import { SignJWT } from 'jose';
import type { AuthenticatedUser } from '../types';
import { loadKeyPair, type KeyPairConfig, type LoadedKeyPair } from './keys';

/**
 * 平台访问令牌的签发。**只有门户应当持有签发能力**，各模块只验签。
 */

export interface TokenClaims {
  sub: string;
  name: string;
  tenants: string[];
  roles: string[];
}

export interface IssuerConfig {
  /** 令牌签发方标识，验签方会核对。建议用门户对外地址 */
  issuer: string;
  /** 令牌受众：哪些模块可以接受它。留空表示不限制 */
  audience?: string | string[];
  ttlSeconds: number;
  keyPair: KeyPairConfig;
}

export const DEFAULT_TTL_SECONDS = 8 * 60 * 60; // 一个工作日

export class TokenIssuer {
  private readonly keys: LoadedKeyPair;

  constructor(private readonly config: IssuerConfig) {
    this.keys = loadKeyPair(config.keyPair);
  }

  /** 当前用于签发的密钥（供 JWKS 端点导出公钥） */
  get keyPair(): LoadedKeyPair {
    return this.keys;
  }

  async issue(user: AuthenticatedUser): Promise<{ accessToken: string; expiresIn: number }> {
    const claims: TokenClaims = {
      sub: user.userId,
      name: user.displayName,
      tenants: user.tenants,
      roles: user.roles,
    };

    const token = new SignJWT({ ...claims })
      // kid 必须带上，验签方据此在 JWKS 里选公钥；轮换密钥时这是关键
      .setProtectedHeader({ alg: 'RS256', kid: this.keys.keyId })
      .setIssuer(this.config.issuer)
      .setIssuedAt()
      .setExpirationTime(`${this.config.ttlSeconds}s`);

    if (this.config.audience) token.setAudience(this.config.audience);

    return {
      accessToken: await token.sign(this.keys.privateKey),
      expiresIn: this.config.ttlSeconds,
    };
  }
}
