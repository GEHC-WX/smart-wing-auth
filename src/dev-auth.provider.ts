import { Logger, UnauthorizedException } from '@nestjs/common';
import { timingSafeEqual } from 'node:crypto';
import type { AuthenticatedUser, AuthProvider } from './types';

/**
 * 开发环境的预设账户认证。**不可用于生产。**
 *
 * 账户配置在 backend/.env：
 *   DEV_AUTH_PASSWORD=<所有预设账户共用的口令>
 *   DEV_AUTH_USERS=wuxi-admin:wuxi-plant:admin,shanghai-viewer:shanghai-plant:viewer
 *                  └用户名────┘ └租户（可用 | 分隔多个）┘ └角色┘
 *
 * 共用一个口令而不是每人一个：预设账户的意义是「用不同身份验证租户与角色行为」，
 * 不是模拟真实的口令管理。口令只从环境变量读，不入库、不写进仓库任何文件。
 *
 * 构造时会拒绝在 NODE_ENV=production 下启用 —— 让误配置在启动时就炸，
 * 而不是留一个人人可登录的后门在生产里跑。
 */
// 不加 @Injectable：由 AuthModule 用工厂构造并注入 env（见 auth.module.ts）
export class DevAuthProvider implements AuthProvider {
  readonly name = 'dev-preset';

  private readonly logger = new Logger(DevAuthProvider.name);
  private readonly password: string;
  private readonly users: Map<string, AuthenticatedUser>;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    if (env.NODE_ENV === 'production') {
      throw new Error(
        'DevAuthProvider 不能在生产环境启用。正式环境请实现 AuthProvider 接口接入企业统一认证。',
      );
    }

    const password = env.DEV_AUTH_PASSWORD ?? '';
    if (!password) {
      throw new Error('缺少 DEV_AUTH_PASSWORD，请参考 backend/.env.example 配置预设账户');
    }
    this.password = password;
    this.users = DevAuthProvider.parseUsers(env.DEV_AUTH_USERS ?? '');

    if (this.users.size === 0) {
      throw new Error('DEV_AUTH_USERS 未配置任何预设账户');
    }

    this.logger.warn(
      `已启用开发环境预设账户认证（${this.users.size} 个账户）。此实现不可用于生产。`,
    );
  }

  /** 解析 `用户名:租户1|租户2:角色1|角色2` 形式的配置，容错跳过写坏的条目 */
  static parseUsers(raw: string): Map<string, AuthenticatedUser> {
    const users = new Map<string, AuthenticatedUser>();

    for (const entry of raw.split(',').map((item) => item.trim()).filter(Boolean)) {
      const [username, tenantPart, rolePart] = entry.split(':').map((part) => part?.trim() ?? '');
      if (!username || !tenantPart) continue;

      const tenants = tenantPart.split('|').map((t) => t.trim()).filter(Boolean);
      if (tenants.length === 0) continue;

      users.set(username, {
        userId: username,
        displayName: username,
        tenants,
        roles: (rolePart ?? '').split('|').map((r) => r.trim()).filter(Boolean),
      });
    }

    return users;
  }

  async authenticate(username: string, password: string): Promise<AuthenticatedUser> {
    const user = this.users.get(username);

    // 用户名不存在时也走一次比对，避免用响应时间区分「用户不存在」和「口令错误」
    const passwordOk = this.verifyPassword(password);
    if (!user || !passwordOk) {
      throw new UnauthorizedException('用户名或口令不正确');
    }

    return user;
  }

  private verifyPassword(candidate: string): boolean {
    const expected = Buffer.from(this.password);
    const actual = Buffer.from(candidate ?? '');

    // timingSafeEqual 要求等长，长度不同直接判否（长度本身不是秘密）
    if (expected.length !== actual.length) return false;
    return timingSafeEqual(expected, actual);
  }
}
