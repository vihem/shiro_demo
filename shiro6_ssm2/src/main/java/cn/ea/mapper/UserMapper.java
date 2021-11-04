package cn.ea.mapper;

import cn.ea.entity.User;
import cn.ea.entity.UserExample;

import java.util.List;

public interface UserMapper {
    User getByName(String name);
    
    int deleteByPrimaryKey(Long id);

    int insert(User record);

    int insertSelective(User record);

    List<User> selectByExample(UserExample example);

    User selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(User record);

    int updateByPrimaryKey(User record);
}
