/**
 * 角色 → 能力映射。
 *
 * 判权一律基于**能力**而不是角色名：控制器上写的是「需要 assets:write」，
 * 不是「需要 admin」。这样企业认证接入后，只要把 IdP 的组/角色映射到这里，
 * 业务代码不用改；新增角色也只改这一张表。
 *
 * 角色名来自令牌（开发环境由 DEV_AUTH_USERS 配置，正式环境由企业 IdP 提供）。
 */

export const PERMISSIONS = {
  ASSETS_READ: 'assets:read',
  ASSETS_WRITE: 'assets:write',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  admin: [PERMISSIONS.ASSETS_READ, PERMISSIONS.ASSETS_WRITE],
  editor: [PERMISSIONS.ASSETS_READ, PERMISSIONS.ASSETS_WRITE],
  viewer: [PERMISSIONS.ASSETS_READ],
  auditor: [PERMISSIONS.ASSETS_READ],
};

/**
 * 未知角色不授予任何能力（默认拒绝）。
 * 反过来做——未知角色当成管理员——会让 IdP 那边加一个新组就悄悄提权。
 */
export function permissionsOf(roles: string[]): Set<Permission> {
  const granted = new Set<Permission>();

  for (const role of roles) {
    for (const permission of ROLE_PERMISSIONS[role] ?? []) {
      granted.add(permission);
    }
  }

  return granted;
}

export function hasPermission(roles: string[], permission: Permission): boolean {
  return permissionsOf(roles).has(permission);
}

/** 供前端展示用：当前身份能做什么。前端据此禁用编辑，但**判权以服务端为准**。 */
export function capabilitiesOf(roles: string[]): Record<string, boolean> {
  const granted = permissionsOf(roles);

  return {
    canReadAssets: granted.has(PERMISSIONS.ASSETS_READ),
    canEditAssets: granted.has(PERMISSIONS.ASSETS_WRITE),
  };
}
