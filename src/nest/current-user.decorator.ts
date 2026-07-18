import { createParamDecorator, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import type { AuthenticatedUser } from '../types';
import type { RequestWithUser } from '../types';

export function extractCurrentUser(_data: unknown, ctx: ExecutionContext): AuthenticatedUser {
  const request = ctx.switchToHttp().getRequest<RequestWithUser>();

  if (!request.user) {
    // 只会在忘记挂 JwtAuthGuard 时发生 —— 宁可 401 也不要放行
    throw new UnauthorizedException('未认证');
  }

  return request.user;
}

export const CurrentUser = createParamDecorator(extractCurrentUser);
