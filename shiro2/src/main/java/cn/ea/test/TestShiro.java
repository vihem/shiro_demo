package cn.ea.test;

import java.util.ArrayList;
import java.util.List;

import cn.ea.entity.User;
import cn.ea.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class TestShiro {

    public static void main(String[] args) {
        if (ShiroUtil.login(new User("zhang3","12345"))){
            System.out.println("登录成功");
            ShiroUtil.hasRole("admin");
        } else {
            System.out.println("登录失败");
        }
    }
    
    public static void test1() {
        //用户们
        User zhang3 = new User("zhang3", "12345");
        User li4 = new User("li4", "abcde");
        User wang5 = new User("wang5", "123");

        List<User> users = new ArrayList<>();
        users.add(zhang3);
        users.add(li4);
        users.add(wang5);

        //角色们
        List<String> roles = new ArrayList<>();
        roles.add("admin");
        roles.add("productManager");

        //权限们
        List<String> permits = new ArrayList<>();
        permits.add("addProduct");
        permits.add("addOrder");
        
        System.out.println("-------登录每个用户------");
        //登录每个用户
        for (User user : users) {
            if(ShiroUtil.login(user))
                System.out.printf("%s \t登录成功，用的密码是 %s %n",user.getName(),user.getPassword());
            else
                System.out.printf("%s \t登录失败，用的密码是 %s %n",user.getName(),user.getPassword());
        }

        System.out.println("-------判断能够登录的用户是否拥有某个角色------");

        //判断能够登录的用户是否拥有某个角色
        for (User user : users) {
            for (String role : roles) {
                //1. 先登录当前用户
                if(ShiroUtil.login(user)) {
                    //2. 判断是否拥有这个 角色
                    if(ShiroUtil.hasRole(role))
                        System.out.printf("%s\t 拥有角色: %s %n",user.getName(),role);
                    else
                        System.out.printf("%s\t 不拥有角色: %s %n",user.getName(),role);
                }
            }
        }
        System.out.println("-------判断能够登录的用户，是否拥有某种权限------");

        //判断能够登录的用户，是否拥有某种权限
        for (User user : users) {
            for (String permit : permits) {
                //1. 先登录当前用户
                if(ShiroUtil.login(user)) {
                    //2. 判断是否拥有这个 权限
                    if(ShiroUtil.isPermitted(permit))
                        System.out.printf("%s\t 拥有权限: %s %n",user.getName(),permit);
                    else
                        System.out.printf("%s\t 不拥有权限: %s %n",user.getName(),permit);
                }
            }
        }
    }


}