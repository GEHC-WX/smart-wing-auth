import { createParamDecorator, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { extractCurrentUser } from './current-user.decorator';

/**
 * 解析本次请求作用于哪个租户。
 *
 * **租户来自令牌，不来自请求头。** 这是与认证之前最大的区别：
 * 以前 X-Tenant-Id 既是「作用于哪个租户」又充当了身份凭据，
 * 任何人构造一个请求头就能读任意租户的数据。
 *
 * 现在 X-Tenant-Id 退化为一个「在我有权访问的租户里选一个」的开关：
 *   - 传了：必须在令牌的 tenants 列表内，否则 403
 *   - 没传：用列表里的第一个
 * 用户能访问哪些租户完全由服务端签发的令牌决定，前端无法扩权。
 */
export function extractTenantId(_data: unknown, ctx: ExecutionContext): string {
  const user = extractCurrentUser(undefined, ctx);
  const request = ctx.switchToHttp().getRequest<{ headers: Record<string, unknown> }>();
  const requested = request.headers['x-tenant-id'];

  if (user.tenants.length === 0) {
    throw new ForbiddenException('该账户未分配任何租户');
  }

  if (requested === undefined || requested === null || requested === '') {
    return user.tenants[0];
  }

  if (Array.isArray(requested)) {
    throw new ForbiddenException('X-Tenant-Id 请求头重复');
  }

  const tenantId = String(requested);
  if (!user.tenants.includes(tenantId)) {
    throw new ForbiddenException(`无权访问租户 ${tenantId}`);
  }

  return tenantId;
}

export const TenantId = createParamDecorator(extractTenantId);
