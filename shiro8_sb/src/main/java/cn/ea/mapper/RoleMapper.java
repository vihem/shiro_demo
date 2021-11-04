package cn.ea.mapper;

import cn.ea.entity.Role;
import cn.ea.entity.RoleExample;

import java.util.List;

public interface RoleMapper {
    List<Role> listRolesByUsername(String userName);

    int deleteByPrimaryKey(Long id);

    int insert(Role record);

    int insertSelective(Role record);

    List<Role> selectByExample(RoleExample example);

    Role selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Role record);

    int updateByPrimaryKey(Role record);
}
