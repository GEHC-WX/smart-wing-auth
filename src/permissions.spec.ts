import { capabilitiesOf, hasPermission, PERMISSIONS, permissionsOf } from './permissions';

describe('permissionsOf', () => {
  it('admin 具备读写', () => {
    expect(permissionsOf(['admin'])).toEqual(
      new Set([PERMISSIONS.ASSETS_READ, PERMISSIONS.ASSETS_WRITE]),
    );
  });

  it('viewer 只读', () => {
    expect(permissionsOf(['viewer'])).toEqual(new Set([PERMISSIONS.ASSETS_READ]));
  });

  it('auditor 只读', () => {
    expect(permissionsOf(['auditor'])).toEqual(new Set([PERMISSIONS.ASSETS_READ]));
  });

  it('多角色取并集', () => {
    expect(permissionsOf(['viewer', 'admin'])).toEqual(
      new Set([PERMISSIONS.ASSETS_READ, PERMISSIONS.ASSETS_WRITE]),
    );
  });

  it('未知角色不授予任何能力 —— 默认拒绝', () => {
    // 反过来做（未知角色当管理员）会让 IdP 那边加个新组就悄悄提权
    expect(permissionsOf(['some-new-idp-group'])).toEqual(new Set());
  });

  it('未知角色不会连带放大已有角色的权限', () => {
    expect(permissionsOf(['viewer', 'unknown-role'])).toEqual(
      new Set([PERMISSIONS.ASSETS_READ]),
    );
  });

  it('空角色列表无任何能力', () => {
    expect(permissionsOf([])).toEqual(new Set());
  });
});

describe('hasPermission', () => {
  it('admin 可写', () => {
    expect(hasPermission(['admin'], PERMISSIONS.ASSETS_WRITE)).toBe(true);
  });

  it('viewer 不可写', () => {
    expect(hasPermission(['viewer'], PERMISSIONS.ASSETS_WRITE)).toBe(false);
  });

  it('无角色不可读', () => {
    expect(hasPermission([], PERMISSIONS.ASSETS_READ)).toBe(false);
  });
});

describe('capabilitiesOf', () => {
  it('admin 可读可写', () => {
    expect(capabilitiesOf(['admin'])).toEqual({ canReadAssets: true, canEditAssets: true });
  });

  it('viewer 可读不可写', () => {
    expect(capabilitiesOf(['viewer'])).toEqual({ canReadAssets: true, canEditAssets: false });
  });

  it('未知角色什么都不能', () => {
    expect(capabilitiesOf(['nobody'])).toEqual({ canReadAssets: false, canEditAssets: false });
  });
});
