package cn.ea.service;

import cn.ea.entity.Role;

public interface RolePermissionService {

    void setPermissions(Role role, long[] permissionIds);
    void deleteByRole(long roleId);
    void deleteByPermission(long permissionId);
}
