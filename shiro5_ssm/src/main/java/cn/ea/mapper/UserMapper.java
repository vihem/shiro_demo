package cn.ea.mapper;

import cn.ea.entity.User;

public interface UserMapper {
    User getByName(String name);
}
