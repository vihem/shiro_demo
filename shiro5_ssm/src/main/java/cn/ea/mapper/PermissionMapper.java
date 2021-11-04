package cn.ea.mapper;

import cn.ea.entity.Permission;

import java.util.List;

public interface PermissionMapper {
    List<Permission> listPermissionsByUserName(String userName);
}
