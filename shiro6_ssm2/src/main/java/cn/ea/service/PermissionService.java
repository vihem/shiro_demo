package cn.ea.service;

import cn.ea.entity.Permission;
import cn.ea.entity.Role;

import java.util.List;
import java.util.Set;

public interface PermissionService {
    Set<String> listPermissions(String userName);

    List<Permission> list();
    void add(Permission permission);
    void delete(Long id);
    Permission get(Long id);
    void update(Permission permission);

    List<Permission> list(Role role);
}
