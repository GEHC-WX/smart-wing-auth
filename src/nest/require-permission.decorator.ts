import { SetMetadata } from '@nestjs/common';

export const REQUIRED_PERMISSION = 'required_permission';

/** 标注某个端点需要的能力，由 PermissionGuard 读取。能力字符串由各模块自己定义 */
export const RequirePermission = (permission: string) => SetMetadata(REQUIRED_PERMISSION, permission);
