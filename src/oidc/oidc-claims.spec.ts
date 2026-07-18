import { claimMappingFrom, mapClaims, parseAliases, toStringArray } from './oidc-claims';

const DEFAULT_MAPPING = claimMappingFrom({} as NodeJS.ProcessEnv);

describe('toStringArray', () => {
  it('数组原样取用并去空白', () => {
    expect(toStringArray([' a ', 'b'])).toEqual(['a', 'b']);
  });

  it('逗号分隔字符串拆成数组 —— 有的 IdP 就是这么给的', () => {
    expect(toStringArray('a, b ,c')).toEqual(['a', 'b', 'c']);
  });

  it('缺失或类型不对时返回空数组，不抛异常', () => {
    expect(toStringArray(undefined)).toEqual([]);
    expect(toStringArray(42)).toEqual([]);
    expect(toStringArray(null)).toEqual([]);
  });
});

describe('parseAliases', () => {
  it('解析 IdP 组名到平台角色的映射', () => {
    expect(parseAliases('GEHC-Plant-Admins=admin, GEHC-Viewers=viewer')).toEqual({
      'GEHC-Plant-Admins': 'admin',
      'GEHC-Viewers': 'viewer',
    });
  });

  it('写坏的条目跳过', () => {
    expect(parseAliases('ok=admin,,broken,=x,y=')).toEqual({ ok: 'admin' });
  });
});

describe('mapClaims', () => {
  it('按默认 claim 名映射身份', () => {
    const user = mapClaims(
      { sub: 'u1', name: '张三', tenants: ['wuxi-plant'], roles: ['admin'] },
      DEFAULT_MAPPING,
    );

    expect(user).toEqual({
      userId: 'u1',
      displayName: '张三',
      tenants: ['wuxi-plant'],
      roles: ['admin'],
    });
  });

  it('displayName 依次回退 name → preferred_username → email → sub', () => {
    expect(mapClaims({ sub: 'u1', preferred_username: 'zhangsan' }, DEFAULT_MAPPING).displayName)
      .toBe('zhangsan');
    expect(mapClaims({ sub: 'u1', email: 'z@x.com' }, DEFAULT_MAPPING).displayName).toBe('z@x.com');
    expect(mapClaims({ sub: 'u1' }, DEFAULT_MAPPING).displayName).toBe('u1');
  });

  it('缺用户标识时抛错 —— 没有身份就不该签发令牌', () => {
    expect(() => mapClaims({ name: '无 sub' }, DEFAULT_MAPPING)).toThrow('缺少用户标识');
  });

  it('claim 名可配置，适配不同 IdP', () => {
    const mapping = claimMappingFrom({
      OIDC_CLAIM_USER_ID: 'oid',
      OIDC_CLAIM_DISPLAY_NAME: 'displayName',
      OIDC_CLAIM_TENANTS: 'plants',
      OIDC_CLAIM_ROLES: 'groups',
    } as NodeJS.ProcessEnv);

    const user = mapClaims(
      { oid: 'abc', displayName: '李四', plants: 'wuxi-plant,shanghai-plant', groups: ['G1'] },
      mapping,
    );

    expect(user).toMatchObject({
      userId: 'abc',
      displayName: '李四',
      tenants: ['wuxi-plant', 'shanghai-plant'],
      roles: ['G1'],
    });
  });

  it('IdP 组名按别名表翻译成平台角色', () => {
    const mapping = claimMappingFrom({
      OIDC_ROLE_ALIASES: 'GEHC-Plant-Admins=admin',
    } as NodeJS.ProcessEnv);

    expect(mapClaims({ sub: 'u', roles: ['GEHC-Plant-Admins'] }, mapping).roles).toEqual(['admin']);
  });

  it('未在别名表里的组名原样保留 —— 丢掉会让排查时看不出 IdP 给了什么', () => {
    const mapping = claimMappingFrom({
      OIDC_ROLE_ALIASES: 'A=admin',
    } as NodeJS.ProcessEnv);

    expect(mapClaims({ sub: 'u', roles: ['A', 'Unknown-Group'] }, mapping).roles).toEqual([
      'admin',
      'Unknown-Group',
    ]);
  });

  it('IdP 没给租户时用默认租户兜底', () => {
    const mapping = claimMappingFrom({
      OIDC_DEFAULT_TENANTS: 'wuxi-plant',
    } as NodeJS.ProcessEnv);

    expect(mapClaims({ sub: 'u' }, mapping).tenants).toEqual(['wuxi-plant']);
  });

  it('没给租户也没配兜底时租户为空 —— 该用户登录后看不到任何模块，而不是看到全部', () => {
    expect(mapClaims({ sub: 'u' }, DEFAULT_MAPPING).tenants).toEqual([]);
  });
});
