/**
 * 认证适配缝。
 *
 * 平台的认证分两个阶段：
 *   - 开发环境：DevAuthProvider，预设账户，配置在 backend/.env
 *   - 正式环境：企业统一认证（OIDC / SAML / 其他），实现本接口即可接入
 *
 * 之所以先抽接口而不是直接写死一种协议：企业侧用哪套认证还没定，
 * 但**上层需要的东西是确定的** —— 一个身份，外加这个身份能访问哪些租户。
 * 只要企业适配器把它的令牌/断言映射成 AuthenticatedUser，
 * 守卫、控制器、前端都不需要改。
 */

export interface AuthenticatedUser {
  userId: string;
  displayName: string;
  /**
   * 该用户可访问的租户。**由服务端决定，前端无权指定。**
   * 数据隔离最终以此为准：请求想作用于哪个租户，必须在这个列表里。
   */
  tenants: string[];
  roles: string[];
}

export interface AuthProvider {
  /** 供运维/日志识别当前启用的是哪个实现 */
  readonly name: string;

  /**
   * 校验凭据并返回身份。凭据不对时抛 UnauthorizedException。
   *
   * 企业认证接入时，这里通常不再是「用户名+口令」，而是校验 IdP signed token
   * 并把 claims 映射成 AuthenticatedUser；届时 /auth/login 端点会下线，
   * 换成 IdP 回调。接口形状保持不变。
   */
  authenticate(username: string, password: string): Promise<AuthenticatedUser>;
}

export const AUTH_PROVIDER = Symbol('AUTH_PROVIDER');

/** 挂在 request 上的已认证身份，供守卫与装饰器共享 */
export interface RequestWithUser {
  headers: Record<string, unknown>;
  user?: AuthenticatedUser;
}
