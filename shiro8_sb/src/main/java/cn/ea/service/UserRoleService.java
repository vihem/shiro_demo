package cn.ea.service;

import cn.ea.entity.User;
import org.springframework.stereotype.Service;

@Service
public interface UserRoleService {
    void setRoles(User user, long[] roleIds);
    void deleteByUser(long userId);
    void deleteByRole(long roleId);
}
