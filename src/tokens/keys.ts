import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { exportJWK, type JWK } from 'jose';

/**
 * RS256 密钥装载。
 *
 * 为什么用非对称而不是共享密钥（HS256）：
 * HS256 下每个模块都必须持有**签发用**的那把密钥才能验签，
 * 也就意味着任何一个模块（或拿到它配置的人）都能伪造出「门户签发」的令牌。
 * RS256 下门户持私钥签发，模块只拿公钥验签，模块无法伪造。
 *
 * 私钥只在门户配置；模块侧连公钥都不用配，按 JWKS 地址取即可（见 verifier.ts）。
 */

export interface KeyPairConfig {
  /** PEM 格式私钥（PKCS#8）。仅签发方需要 */
  privateKeyPem: string;
  /** 密钥标识，随令牌头部下发，供验签方在 JWKS 里选对公钥 */
  keyId: string;
}

export interface LoadedKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyId: string;
}

/**
 * 环境变量里的 PEM 常被写成一行、用 \n 表示换行（很多部署系统只能传单行），
 * 这里统一还原。
 */
export function normalizePem(raw: string): string {
  return raw.includes('\\n') ? raw.replace(/\\n/g, '\n') : raw;
}

export function loadKeyPair(config: KeyPairConfig): LoadedKeyPair {
  const pem = normalizePem(config.privateKeyPem).trim();
  if (!pem) {
    throw new Error('缺少 RS256 私钥（PEM）');
  }

  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(pem);
  } catch (error) {
    throw new Error(`RS256 私钥解析失败：${(error as Error).message}`);
  }

  if (privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error(`RS256 需要 RSA 私钥，实际是 ${privateKey.asymmetricKeyType ?? '未知类型'}`);
  }

  return { privateKey, publicKey: createPublicKey(privateKey), keyId: config.keyId };
}

/**
 * 导出 JWKS（只含公钥）。签发方把它挂在 /.well-known/jwks.json，
 * 各模块据此验签。
 *
 * 这里逐字段挑选而不是把 exportJWK 的结果整个抛出去 ——
 * 万一将来传进来的是私钥对象，也不至于把 d/p/q 这些私钥参数一起发出去。
 */
export async function toPublicJwks(pairs: LoadedKeyPair[]): Promise<{ keys: JWK[] }> {
  const keys = await Promise.all(
    pairs.map(async (pair) => {
      const jwk = await exportJWK(pair.publicKey);
      return {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        kid: pair.keyId,
        alg: 'RS256',
        use: 'sig',
      } as JWK;
    }),
  );

  return { keys };
}
