import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { RequestWithUser } from '../types';
import { REQUIRED_PERMISSION } from './require-permission.decorator';

export const PERMISSION_CHECKER = Symbol('PERMISSION_CHECKER');

/** 由消费模块提供：给定角色列表和所需能力，判断是否放行 */
export type PermissionChecker = (roles: string[], permission: string) => boolean;

/**
 * 能力判权。必须排在 JwtAuthGuard 之后 —— 它依赖后者挂在 request 上的身份。
 *
 * 判权逻辑（角色→能力表）由各模块通过 PERMISSION_CHECKER 注入，共享包本身
 * 不硬编码任何具体权限——门户不关心 assets:write，模块二不关心
 * leave-plans:approve，各自的权限目录是各自的业务知识。
 *
 * 没有标注 @RequirePermission 的端点直接放行：判权在端点上显式声明，
 * 不做「默认需要某某角色」的隐式规则，免得读代码时看不出一个端点到底要什么权限。
 */
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(PERMISSION_CHECKER) private readonly hasPermission: PermissionChecker,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string | undefined>(REQUIRED_PERMISSION, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!required) return true;

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const roles = request.user?.roles ?? [];

    if (!this.hasPermission(roles, required)) {
      throw new ForbiddenException(`当前角色无权执行该操作（需要 ${required}）`);
    }

    return true;
  }
}
