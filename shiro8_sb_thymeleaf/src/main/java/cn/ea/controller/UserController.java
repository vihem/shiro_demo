package cn.ea.controller;

import cn.ea.entity.Role;
import cn.ea.entity.User;
import cn.ea.service.RoleService;
import cn.ea.service.UserRoleService;
import cn.ea.service.UserService;
import cn.ea.vo.ResultVo;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.*;

@Controller
@RequestMapping("config")
public class UserController {

    @Autowired private RoleService roleService;
    @Autowired private UserRoleService userRoleService;
    @Autowired private UserService userService;

    @RequestMapping("listUser")
    public String list(Model model){
        // 查询所有用户，并显示到前端
        List<User> users = userService.list();
        model.addAttribute("users", users);
        
        // 查询每一个用户赋予的角色
        Map<User, List<Role>> user_roles = new HashMap<>();
        for (User user:users){
            user_roles.put(user, roleService.listRoles(user));
        }
        model.addAttribute("user_roles", user_roles);
        return "listUser";
    }
    
    //editUser?id=${u.id}
    @RequestMapping("editUser")
    public String edit(Model model,long id){
        // 根据id查询当前用户
        User user = userService.get(id);
        List<Role> allRoles = roleService.list();
        List<Role> curRoles = roleService.listRoles(user);
        
        List<ResultVo> resultVos = new ArrayList<>();
        for (Role role : allRoles) {
            ResultVo resultVO = new ResultVo(role.getId(), role.getName(), role, false);
            for (Role cur: curRoles){
                if (Objects.equals(cur.getId(), role.getId())){
                    resultVO.setFlag(true);
                }
            }
            resultVos.add(resultVO);
        }

        // 显示当前用户名，及其所拥有的角色，和所有角色
        model.addAttribute("user", user);
//        model.addAttribute("currentRoles", curRoles);
//        model.addAttribute("roles", allRoles);
        model.addAttribute("resultVos", resultVos);
        return "editUser";
    }
    
    @RequestMapping("deleteUser")
    public String delete(Model model,long id){
        userService.delete(id);
        return "redirect:listUser";
    }
    
    //<form action="updateUser" method="post">
    @RequestMapping("updateUser")
    public String update(User user,long[] roleIds){
        // 为 user 设置新的角色
        userRoleService.setRoles(user,roleIds);

        // 更新 user 数据库
        userService.update(user);
        // 重定向到 listUser.jsp
        return "redirect:listUser";
    }

    /**
     * 添加新用户
     */
    @RequestMapping("addUser")
    public String add(String name, String password){
        // 1. 配置salt，为 密码加密
        String salt = new SecureRandomNumberGenerator().nextBytes().toString();
        String encodedPassword = new SimpleHash("md5",password,salt,2).toString();

        User user = new User();
        user.setName(name);
        user.setPassword(encodedPassword);
        user.setSalt(salt);
        userService.add(user);
        return "redirect:listUser";
    }
}
