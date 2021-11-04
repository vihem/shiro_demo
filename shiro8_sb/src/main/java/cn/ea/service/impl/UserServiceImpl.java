package cn.ea.service.impl;

import cn.ea.entity.User;
import cn.ea.entity.UserExample;
import cn.ea.mapper.UserMapper;
import cn.ea.service.UserRoleService;
import cn.ea.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    
    @Resource private UserMapper userMapper;
    @Resource private UserRoleService userRoleService;
    
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

    @Override
    public User getByName(String name){
        UserExample example = new UserExample();
        example.createCriteria().andNameEqualTo(name);
        List<User> users = userMapper.selectByExample(example);
        if(users.isEmpty())
            return null;
        return users.get(0);
    }

    @Override
    public List<User> list(){
        UserExample example =new UserExample();
        example.setOrderByClause("id desc");
        return userMapper.selectByExample(example);
    }

    @Override
    public void add(User user) {
        userMapper.insert(user);
    }

    @Override
    public void delete(Long id) {
        userMapper.deleteByPrimaryKey(id);
        userRoleService.deleteByUser(id);
    }

    @Override
    public User get(Long id) {
        return userMapper.selectByPrimaryKey(id);
    }

    @Override
    public void update(User user)  {
        userMapper.updateByPrimaryKeySelective(user);
    }
}
