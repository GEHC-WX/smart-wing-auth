import { createPermissionRegistry } from './permission-registry';

const PERMISSIONS = {
  READ: 'thing:read',
  WRITE: 'thing:write',
} as const;

const { permissionsOf, hasPermission } = createPermissionRegistry<
  (typeof PERMISSIONS)[keyof typeof PERMISSIONS]
>({
  admin: [PERMISSIONS.READ, PERMISSIONS.WRITE],
  viewer: [PERMISSIONS.READ],
});

describe('permissionsOf', () => {
  it('admin 具备读写', () => {
    expect(permissionsOf(['admin'])).toEqual(new Set([PERMISSIONS.READ, PERMISSIONS.WRITE]));
  });

  it('viewer 只读', () => {
    expect(permissionsOf(['viewer'])).toEqual(new Set([PERMISSIONS.READ]));
  });

  it('多角色取并集', () => {
    expect(permissionsOf(['viewer', 'admin'])).toEqual(
      new Set([PERMISSIONS.READ, PERMISSIONS.WRITE]),
    );
  });

  it('未知角色不授予任何能力 —— 默认拒绝', () => {
    // 反过来做（未知角色当管理员）会让 IdP 那边加个新组就悄悄提权
    expect(permissionsOf(['some-new-idp-group'])).toEqual(new Set());
  });

  it('未知角色不会连带放大已有角色的权限', () => {
    expect(permissionsOf(['viewer', 'unknown-role'])).toEqual(new Set([PERMISSIONS.READ]));
  });

  it('空角色列表无任何能力', () => {
    expect(permissionsOf([])).toEqual(new Set());
  });
});

describe('hasPermission', () => {
  it('具备能力时返回 true', () => {
    expect(hasPermission(['admin'], PERMISSIONS.WRITE)).toBe(true);
  });

  it('不具备能力时返回 false', () => {
    expect(hasPermission(['viewer'], PERMISSIONS.WRITE)).toBe(false);
  });
});

describe('两个模块各自的权限表互不影响', () => {
  it('同一个工厂函数生成的两份注册表相互独立', () => {
    const moduleA = createPermissionRegistry<'a:read'>({ admin: ['a:read'] });
    const moduleB = createPermissionRegistry<'b:read'>({ admin: [] });

    expect(moduleA.hasPermission(['admin'], 'a:read')).toBe(true);
    expect(moduleB.hasPermission(['admin'], 'b:read')).toBe(false);
  });
});
