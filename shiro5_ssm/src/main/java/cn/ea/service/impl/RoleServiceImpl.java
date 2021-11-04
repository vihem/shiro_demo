package cn.ea.service.impl;

import cn.ea.entity.Role;
import cn.ea.mapper.RoleMapper;
import cn.ea.service.RoleService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class RoleServiceImpl implements RoleService {
    @Resource private RoleMapper roleMapper;

    @Override
    public Set<String> listRoles(String userName) {
        List<Role> roles = roleMapper.listRolesByUserName(userName);
        Set<String> result = new HashSet<>();
        for (Role role: roles) {
            result.add(role.getName());
        }
        return result;
    }
}
