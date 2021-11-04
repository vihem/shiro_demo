package cn.ea.mapper;

import cn.ea.entity.Permission;
import cn.ea.entity.PermissionExample;

import java.util.List;

public interface PermissionMapper {
    List<Permission> listPermissionsByUsername(String userName);

    int deleteByPrimaryKey(Long id);

    int insert(Permission record);

    int insertSelective(Permission record);

    List<Permission> selectByExample(PermissionExample example);

    Permission selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Permission record);

    int updateByPrimaryKey(Permission record);
}
