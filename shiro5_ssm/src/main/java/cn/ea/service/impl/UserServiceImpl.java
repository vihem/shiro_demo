package cn.ea.service.impl;

import cn.ea.entity.User;
import cn.ea.mapper.UserMapper;
import cn.ea.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class UserServiceImpl implements UserService {
    
    @Resource private UserMapper userMapper;
    
    @Override
    public String getPassword(String name) {
        User u  = userMapper.getByName(name);
        if(null==u) return null;
        return u.getPassword();
    }

    @Override
    public User getUserByName(String name) {
        return userMapper.getByName(name);
    }
}
