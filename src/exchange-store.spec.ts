import { EXCHANGE_TTL_MS, ExchangeStore } from './exchange-store';

const USER = { userId: 'u1', displayName: 'U1', tenants: ['t1'], roles: ['admin'] };

describe('ExchangeStore', () => {
  it('签发的码可以兑换回身份', () => {
    const store = new ExchangeStore();
    const code = store.issue(USER);

    expect(store.redeem(code)).toEqual(USER);
  });

  it('码是一次性的 —— 兑换过就作废', () => {
    const store = new ExchangeStore();
    const code = store.issue(USER);

    expect(store.redeem(code)).toEqual(USER);
    expect(store.redeem(code)).toBeNull();
  });

  it('不存在的码返回 null 而不是抛异常', () => {
    expect(new ExchangeStore().redeem('nope')).toBeNull();
  });

  it('超过有效期的码作废', () => {
    let now = 1_000_000;
    const store = new ExchangeStore(() => now);
    const code = store.issue(USER);

    now += EXCHANGE_TTL_MS + 1;

    expect(store.redeem(code)).toBeNull();
  });

  it('每次签发的码都不同', () => {
    const store = new ExchangeStore();

    expect(store.issue(USER)).not.toBe(store.issue(USER));
  });

  it('签发时清理过期条目，不让内存无限增长', () => {
    let now = 1_000_000;
    const store = new ExchangeStore(() => now);
    store.issue(USER);
    store.issue(USER);
    expect(store.size).toBe(2);

    now += EXCHANGE_TTL_MS + 1;
    store.issue(USER); // 触发清理

    expect(store.size).toBe(1);
  });
});
