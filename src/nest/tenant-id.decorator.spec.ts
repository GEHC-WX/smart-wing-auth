import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { AuthenticatedUser } from '../types';
import { extractTenantId } from './tenant-id.decorator';

function ctxOf(
  user: AuthenticatedUser | undefined,
  headers: Record<string, unknown> = {},
): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ user, headers }) }),
  } as unknown as ExecutionContext;
}

const singleTenant: AuthenticatedUser = {
  userId: 'u1',
  displayName: 'u1',
  tenants: ['wuxi-plant'],
  roles: [],
};

const multiTenant: AuthenticatedUser = {
  userId: 'u2',
  displayName: 'u2',
  tenants: ['wuxi-plant', 'shanghai-plant'],
  roles: [],
};

describe('extractTenantId —— 租户来自令牌，不来自请求头', () => {
  it('未认证时抛 401（守卫漏挂也不放行）', () => {
    expect(() => extractTenantId(undefined, ctxOf(undefined))).toThrow(UnauthorizedException);
  });

  it('不传请求头时用令牌里的第一个租户', () => {
    expect(extractTenantId(undefined, ctxOf(multiTenant))).toBe('wuxi-plant');
  });

  it('传的租户在令牌列表内时按其取值', () => {
    expect(
      extractTenantId(undefined, ctxOf(multiTenant, { 'x-tenant-id': 'shanghai-plant' })),
    ).toBe('shanghai-plant');
  });

  it('传的租户不在令牌列表内时抛 403 —— 这是认证前那个洞的核心', () => {
    expect(() =>
      extractTenantId(undefined, ctxOf(singleTenant, { 'x-tenant-id': 'shanghai-plant' })),
    ).toThrow(ForbiddenException);
  });

  it('伪造一个完全不存在的租户同样 403', () => {
    expect(() =>
      extractTenantId(undefined, ctxOf(multiTenant, { 'x-tenant-id': 'evil-tenant' })),
    ).toThrow(ForbiddenException);
  });

  it('空字符串按未指定处理', () => {
    expect(extractTenantId(undefined, ctxOf(multiTenant, { 'x-tenant-id': '' }))).toBe(
      'wuxi-plant',
    );
  });

  it('重复请求头（数组）抛 403，不取其中任意一个', () => {
    expect(() =>
      extractTenantId(
        undefined,
        ctxOf(multiTenant, { 'x-tenant-id': ['wuxi-plant', 'evil-tenant'] }),
      ),
    ).toThrow(ForbiddenException);
  });

  it('账户未分配任何租户时抛 403', () => {
    expect(() => extractTenantId(undefined, ctxOf({ ...singleTenant, tenants: [] }))).toThrow(
      ForbiddenException,
    );
  });
});
