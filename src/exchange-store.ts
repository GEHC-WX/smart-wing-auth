import { randomBytes } from 'node:crypto';
import type { AuthenticatedUser } from './types';

/**
 * SSO 回调后的一次性交换码。
 *
 * 为什么不直接把访问令牌拼在回调 URL 上：URL 会留在浏览器历史、可能随 Referer
 * 外泄、也会出现在各级日志里。改成回调只带一个短命的一次性码，前端再用它
 * POST 换取真正的令牌 —— 码用过即废，且不出现在任何长期存储里。
 */

interface PendingExchange {
  user: AuthenticatedUser;
  createdAt: number;
}

/** 交换码存活时间。前端拿到回调后应立即兑换，一分钟足够 */
export const EXCHANGE_TTL_MS = 60 * 1000;

export class ExchangeStore {
  private readonly entries = new Map<string, PendingExchange>();

  constructor(private readonly now: () => number = Date.now) {}

  issue(user: AuthenticatedUser): string {
    this.sweep();
    const code = randomBytes(24).toString('base64url');
    this.entries.set(code, { user, createdAt: this.now() });
    return code;
  }

  /** 兑换即失效；无效或过期一律返回 null，调用方统一按 401 处理 */
  redeem(code: string): AuthenticatedUser | null {
    const entry = this.entries.get(code);
    if (!entry) return null;

    this.entries.delete(code);

    if (this.now() - entry.createdAt > EXCHANGE_TTL_MS) return null;
    return entry.user;
  }

  private sweep(): void {
    const now = this.now();
    for (const [code, entry] of this.entries) {
      if (now - entry.createdAt > EXCHANGE_TTL_MS) this.entries.delete(code);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}
