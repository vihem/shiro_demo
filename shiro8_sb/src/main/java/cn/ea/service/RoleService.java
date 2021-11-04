package cn.ea.service;

import cn.ea.entity.Role;
import cn.ea.entity.User;

import java.util.List;
import java.util.Set;

public interface RoleService {
    Set<String> listRoleNames(String username);
    List<Role> listRoles(String username);
    List<Role> listRoles(User user);

    List<Role> list();
    void add(Role role);
    void delete(Long id);
    Role get(Long id);
    void update(Role role);
}
