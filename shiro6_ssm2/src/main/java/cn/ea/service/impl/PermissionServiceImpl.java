package cn.ea.service.impl;

import cn.ea.entity.Permission;
import cn.ea.entity.Role;
import cn.ea.entity.RolePermission;
import cn.ea.entity.PermissionExample;
import cn.ea.entity.RolePermissionExample;
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
}
