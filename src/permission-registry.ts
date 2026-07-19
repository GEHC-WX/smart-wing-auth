/**
 * 角色 → 能力映射的通用实现。
 *
 * 每个模块的权限目录（有哪些能力、哪个角色有哪些能力）是各模块自己的业务知识，
 * 不该长在共享包里——门户不关心 assets:write，模块二不关心 leave-plans:approve。
 * 共享包只提供"给定一张角色表，算某组角色有没有某个能力"这个通用算法，
 * 各模块用 createPermissionRegistry(表) 生成自己的 hasPermission，
 * 配 PermissionGuard 的 PERMISSION_CHECKER 注入点使用。
 */

export function createPermissionRegistry<P extends string>(
  rolePermissions: Record<string, P[]>,
): {
  permissionsOf: (roles: string[]) => Set<P>;
  hasPermission: (roles: string[], permission: string) => boolean;
} {
  function permissionsOf(roles: string[]): Set<P> {
    const granted = new Set<P>();

    for (const role of roles) {
      for (const permission of rolePermissions[role] ?? []) {
        granted.add(permission);
      }
    }

    return granted;
  }

  // permission 故意收 string 而不是 P：这样返回的函数能直接满足
  // PermissionGuard 的 PERMISSION_CHECKER（参数类型是 string），不需要在
  // 每个消费模块里做类型断言。查一个不属于 P 的字符串本来就该返回 false——
  // 未知权限视为未授予，跟"未知角色不授予任何能力"是同一条默认拒绝原则。
  function hasPermission(roles: string[], permission: string): boolean {
    return (permissionsOf(roles) as Set<string>).has(permission);
  }

  return { permissionsOf, hasPermission };
}
