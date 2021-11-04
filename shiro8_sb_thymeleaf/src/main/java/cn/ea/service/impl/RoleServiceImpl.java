package cn.ea.service.impl;

import cn.ea.entity.*;
import cn.ea.mapper.RoleMapper;
import cn.ea.mapper.UserRoleMapper;
import cn.ea.service.RoleService;
import cn.ea.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class RoleServiceImpl implements RoleService {
    @Resource private RoleMapper roleMapper;
    @Resource private UserService userService;
    @Resource private UserRoleMapper userRoleMapper;
    
    @Override
    public Set<String> listRoleNames(String username) {
        Set<String> result = new HashSet<>();
        List<Role> roles = listRoles(username);
        for (Role role : roles) {
            result.add(role.getName());
        }
        return result;
    }

    @Override
    public List<Role> listRoles(String username) {
        List<Role> roles = new ArrayList<>();
        User user = userService.getByName(username);
        if(null==user) return roles;
        roles = listRoles(user);
        return roles;
    }

    @Override
    public List<Role> listRoles(User user) {
        UserRoleExample example = new UserRoleExample();
        example.createCriteria().andUidEqualTo(user.getId());
        List<UserRole> userRoles= userRoleMapper.selectByExample(example);

        List<Role> roles = new ArrayList<>();
        for (UserRole userRole : userRoles) {
            Role role=roleMapper.selectByPrimaryKey(userRole.getRid());
            roles.add(role);
        }
        return roles;
    }

    @Override
    public List<Role> list() {
        RoleExample example = new RoleExample();
        example.setOrderByClause("id desc");
        return roleMapper.selectByExample(example);
    }

    @Override
    public void add(Role role)  {
        roleMapper.insert(role);
    }

    @Override
    public void delete(Long id)  {
        roleMapper.deleteByPrimaryKey(id);
    }

    @Override
    public Role get(Long id) {
        return roleMapper.selectByPrimaryKey(id);
    }

    @Override
    public void update(Role role)  {
        roleMapper.updateByPrimaryKeySelective(role);
    }
}
