import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { RequestWithUser } from '../types';
import { hasPermission, type Permission } from '../permissions';
import { REQUIRED_PERMISSION } from './require-permission.decorator';

/**
 * 能力判权。必须排在 JwtAuthGuard 之后 —— 它依赖后者挂在 request 上的身份。
 *
 * 没有标注 @RequirePermission 的端点直接放行：判权在端点上显式声明，
 * 不做「默认需要某某角色」的隐式规则，免得读代码时看不出一个端点到底要什么权限。
 */
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Permission | undefined>(
      REQUIRED_PERMISSION,
      [context.getHandler(), context.getClass()],
    );

    if (!required) return true;

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const roles = request.user?.roles ?? [];

    if (!hasPermission(roles, required)) {
      throw new ForbiddenException(`当前角色无权执行该操作（需要 ${required}）`);
    }

    return true;
  }
}
