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

    /**
     * 对请求的 requestURI 是否要进行拦截
     */
    boolean needInterceptor(String requestURI);

    /**
     * 获取某个用户所拥有的 权限地址url 集合
     */
    Set<String> listPermissionURLs(String username);
}
