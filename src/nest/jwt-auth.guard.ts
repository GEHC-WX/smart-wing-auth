import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { RequestWithUser } from '../types';
import { TokenVerifier } from '../tokens/verifier';

export const TOKEN_VERIFIER = Symbol('TOKEN_VERIFIER');

/**
 * 平台统一的令牌守卫。各模块只需提供一个 TokenVerifier（按门户 JWKS 验签），
 * 无需自己实现验签逻辑，也就不会各写一遍、各错一遍。
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(@Inject(TOKEN_VERIFIER) private readonly verifier: TokenVerifier) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const token = extractBearerToken(request);

    if (!token) {
      throw new UnauthorizedException('缺少访问令牌');
    }

    try {
      request.user = await this.verifier.verify(token);
    } catch {
      // 不回显具体原因（过期 / 签名不对 / 受众不符），避免给探测者额外信息
      throw new UnauthorizedException('访问令牌无效或已过期');
    }

    return true;
  }
}

export function extractBearerToken(request: { headers: Record<string, unknown> }): string | null {
  const header = request.headers?.authorization;
  if (typeof header !== 'string') return null;

  const [scheme, value] = header.split(' ');
  return scheme?.toLowerCase() === 'bearer' && value ? value : null;
}
