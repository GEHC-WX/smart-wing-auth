import { UnauthorizedException } from '@nestjs/common';
import { DevAuthProvider } from './dev-auth.provider';

const BASE_ENV = {
  DEV_AUTH_PASSWORD: 'local-dev-secret', // secrets-gate:allow 测试夹具
  DEV_AUTH_USERS: 'wuxi-admin:wuxi-plant:admin,multi:wuxi-plant|shanghai-plant:admin|auditor',
} as NodeJS.ProcessEnv;

describe('DevAuthProvider —— 启动期防护', () => {
  it('生产环境下拒绝启用', () => {
    expect(() => new DevAuthProvider({ ...BASE_ENV, NODE_ENV: 'production' })).toThrow(
      '不能在生产环境启用',
    );
  });

  it('缺少口令时拒绝启动', () => {
    expect(() => new DevAuthProvider({ DEV_AUTH_USERS: 'a:t' } as NodeJS.ProcessEnv)).toThrow(
      'DEV_AUTH_PASSWORD',
    );
  });

  it('没有任何预设账户时拒绝启动', () => {
    expect(
      () => new DevAuthProvider({ DEV_AUTH_PASSWORD: 'x', DEV_AUTH_USERS: '' } as NodeJS.ProcessEnv),
    ).toThrow('未配置任何预设账户');
  });
});

describe('DevAuthProvider.parseUsers', () => {
  it('解析用户名、多租户与多角色', () => {
    const users = DevAuthProvider.parseUsers('multi:wuxi-plant|shanghai-plant:admin|auditor');

    expect(users.get('multi')).toEqual({
      userId: 'multi',
      displayName: 'multi',
      tenants: ['wuxi-plant', 'shanghai-plant'],
      roles: ['admin', 'auditor'],
    });
  });

  it('角色可省略', () => {
    expect(DevAuthProvider.parseUsers('a:t1')?.get('a')?.roles).toEqual([]);
  });

  it('跳过写坏的条目而不是整份配置失效', () => {
    const users = DevAuthProvider.parseUsers('good:t1, :t2, bad-no-tenant, alsogood:t3');

    expect([...users.keys()]).toEqual(['good', 'alsogood']);
  });

  it('空配置返回空表', () => {
    expect(DevAuthProvider.parseUsers('').size).toBe(0);
  });
});

describe('DevAuthProvider.authenticate', () => {
  let provider: DevAuthProvider;

  beforeEach(() => {
    provider = new DevAuthProvider(BASE_ENV);
  });

  it('用户名与口令都对时返回身份', async () => {
    await expect(provider.authenticate('wuxi-admin', 'local-dev-secret')).resolves.toMatchObject({
      userId: 'wuxi-admin',
      tenants: ['wuxi-plant'],
      roles: ['admin'],
    });
  });

  it('多租户账户带回全部租户', async () => {
    const user = await provider.authenticate('multi', 'local-dev-secret');

    expect(user.tenants).toEqual(['wuxi-plant', 'shanghai-plant']);
  });

  it('口令错误抛 401', async () => {
    await expect(provider.authenticate('wuxi-admin', 'wrong')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('用户不存在抛 401，且提示与口令错误一致（不泄漏用户是否存在）', async () => {
    const notFound = await provider.authenticate('nobody', 'local-dev-secret').catch((e) => e);
    const wrongPassword = await provider.authenticate('wuxi-admin', 'wrong').catch((e) => e);

    expect(notFound.message).toBe(wrongPassword.message);
  });

  it('空口令不放行', async () => {
    await expect(provider.authenticate('wuxi-admin', '')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
