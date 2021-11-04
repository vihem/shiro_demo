package cn.ea.service.impl;

import cn.ea.entity.*;
import cn.ea.mapper.PermissionMapper;
import cn.ea.mapper.RolePermissionMapper;
import cn.ea.service.PermissionService;
import cn.ea.service.RoleService;
import cn.ea.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class PermissionServiceImpl implements PermissionService {
    @Resource private PermissionMapper permissionMapper;
    @Resource private RolePermissionMapper rolePermissionMapper;
    @Resource private UserService userService;
    @Resource private RoleService roleService;

    @Override 
    public Set<String> listPermissions(String userName) {
//        List<Permission> permissions = permissionMapper.listPermissionsByUsername(userName);
//        Set<String> result = new HashSet<>();
//        for (Permission permission: permissions) {
//            result.add(permission.getName());
//        }
//        return result;
        Set<String> result = new HashSet<>();
        List<Role> roles = roleService.listRoles(userName);

        List<RolePermission> rolePermissions = new ArrayList<>();
        for (Role role : roles) {
            RolePermissionExample example = new RolePermissionExample();
            example.createCriteria().andRidEqualTo(role.getId());
            List<RolePermission> rps= rolePermissionMapper.selectByExample(example);
            rolePermissions.addAll(rps);
        }

        for (RolePermission rolePermission : rolePermissions) {
            Permission p = permissionMapper.selectByPrimaryKey(rolePermission.getPid());
            result.add(p.getName());
        }

        return result;
    }

    @Override
    public List<Permission> list() {
        PermissionExample example =new PermissionExample();
        example.setOrderByClause("id desc");
        return permissionMapper.selectByExample(example);
    }

    @Override
    public void add(Permission permission)  {
        permissionMapper.insert(permission);
    }

    @Override
    public void delete(Long id)  {
        permissionMapper.deleteByPrimaryKey(id);
    }

    @Override
    public Permission get(Long id)  {
        return permissionMapper.selectByPrimaryKey(id);
    }

    @Override
    public void update(Permission permission)  {
        permissionMapper.updateByPrimaryKeySelective(permission);
    }

    @Override
    public List<Permission> list(Role role) {
        List<Permission> result = new ArrayList<>();
        RolePermissionExample example = new RolePermissionExample();
        example.createCriteria().andRidEqualTo(role.getId());
        List<RolePermission> rps = rolePermissionMapper.selectByExample(example);
        for (RolePermission rolePermission : rps) {
            result.add(permissionMapper.selectByPrimaryKey(rolePermission.getPid()));
        }
        return result;
    }

    /**
     * 判断依据是如果访问的某个url,在权限系统里存在，就要进行拦截。 如果不存在，就放行了。
     * 这一种策略，也可以切换成另一个，即，访问的地址如果不存在于权限系统中，就提示没有拦截。 
     * 这两种做法没有对错之分，取决于业务上希望如何制定权限策略。
     */
    @Override
    public boolean needInterceptor(String requestURI) {
        List<Permission> permissions = this.list();
        for (Permission p : permissions){
            if (p.getUrl().equals(requestURI)){
                return true;
            }
        }
        return false;
    }

    /**
     * 获取某个用户所拥有的 权限地址url 集合
     */
    @Override
    public Set<String> listPermissionURLs(String username) {
        // 1. 查询所有的角色
        List<Role> roles = roleService.listRoles(username);
        // 2. 根据 roleId->rid，查询所有的权限id
        List<RolePermission> rolePermissions = new ArrayList<>();
        for (Role role : roles) {
            RolePermissionExample example = new RolePermissionExample();
            example.createCriteria().andRidEqualTo(role.getId());
            List<RolePermission> rps = rolePermissionMapper.selectByExample(example);
            rolePermissions.addAll(rps);
        }

        // 3. 获取权限表 中对应的 url字段值： /addProduct /deleteProduct。。。
        Set<String> result = new HashSet<>();
        for (RolePermission rolePermission : rolePermissions){
            Permission p = permissionMapper.selectByPrimaryKey(rolePermission.getPid());
            result.add(p.getUrl());
        }
        return result;// 返回： /addProduct /deleteProduct。。。
    }
}
