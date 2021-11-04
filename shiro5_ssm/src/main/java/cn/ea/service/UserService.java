package cn.ea.service;

import cn.ea.entity.User;

public interface UserService {
    String getPassword(String name);
    User getUserByName(String name);
}
