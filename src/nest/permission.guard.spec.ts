import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionGuard } from './permission.guard';
import { createPermissionRegistry } from '../permission-registry';

const PERMISSIONS = { WRITE: 'test:write' } as const;

// 校验 PermissionGuard 只依赖注入进来的 hasPermission，不关心具体权限目录长什么样
const { hasPermission } = createPermissionRegistry<(typeof PERMISSIONS)['WRITE']>({
  admin: [PERMISSIONS.WRITE],
  viewer: [],
});

function ctxOf(roles: string[] | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => (roles === undefined ? {} : { user: { roles } }),
    }),
    getHandler: () => () => undefined,
    getClass: () => class {},
  } as unknown as ExecutionContext;
}

function guardRequiring(permission: string | undefined): PermissionGuard {
  const reflector = { getAllAndOverride: () => permission } as unknown as Reflector;
  return new PermissionGuard(reflector, hasPermission);
}

describe('PermissionGuard', () => {
  it('端点没标注所需能力时直接放行', () => {
    expect(guardRequiring(undefined).canActivate(ctxOf(['viewer']))).toBe(true);
  });

  it('具备所需能力时放行', () => {
    expect(guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf(['admin']))).toBe(true);
  });

  it('viewer 访问写端点抛 403', () => {
    expect(() => guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf(['viewer']))).toThrow(
      ForbiddenException,
    );
  });

  it('未知角色访问写端点抛 403', () => {
    expect(() =>
      guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf(['idp-new-group'])),
    ).toThrow(ForbiddenException);
  });

  it('无角色抛 403', () => {
    expect(() => guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf([]))).toThrow(
      ForbiddenException,
    );
  });

  it('request 上没有身份时按无角色处理，抛 403 而不是崩溃', () => {
    expect(() => guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf(undefined))).toThrow(
      ForbiddenException,
    );
  });

  it('错误信息里带上所需能力，便于排查', () => {
    try {
      guardRequiring(PERMISSIONS.WRITE).canActivate(ctxOf(['viewer']));
      fail('应当抛出');
    } catch (error) {
      expect((error as Error).message).toContain('test:write');
    }
  });
});
