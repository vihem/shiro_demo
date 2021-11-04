package cn.ea.mapper;

import cn.ea.entity.Role;

import java.util.List;

public interface RoleMapper {
    List<Role> listRolesByUserName(String userName);
}
