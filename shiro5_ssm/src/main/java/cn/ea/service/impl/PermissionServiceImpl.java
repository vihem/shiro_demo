package cn.ea.service.impl;

import cn.ea.entity.Permission;
import cn.ea.mapper.PermissionMapper;
import cn.ea.service.PermissionService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class PermissionServiceImpl implements PermissionService {
    @Resource
    private PermissionMapper permissionMapper;

    @Override
    public Set<String> listPermissions(String userName) {
        List<Permission> permissions = permissionMapper.listPermissionsByUserName(userName);
        Set<String> result = new HashSet<>();
        for (Permission permission: permissions) {
            result.add(permission.getName());
        }
        return result;
    }
}
