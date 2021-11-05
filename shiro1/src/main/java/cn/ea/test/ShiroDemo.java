package cn.ea.test;

import cn.ea.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;

public class ShiroDemo {
    public static void main(String[] args) {
        // 1. 获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager 
        //      SecurityManager---->Factory
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 2. 从工厂中获取 SecurityManager 的实例
        SecurityManager securityManager = factory.getInstance();//ctrl+alt+v：快速生成变量及对应的数据类型
        // 3. 把 securityManager 实例绑定到全局 SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);//当前用户：Subject--->SecurityUtils

        // 4. 获取当前 主体(subject)/用户
        Subject subject = SecurityUtils.getSubject();//当前用户
        // 5. 对传进来的用户名/密码进行UsernamePasswordToken封装(创建用户名/密码身份验证Token（即用户身份/凭证）)
        UsernamePasswordToken token = new UsernamePasswordToken("zhang3","12345");//通过UsernamePasswordToken来模拟html/jsp传递过来的用户名与密码
        //  通过shiro来判断用户是否登录成功;ctrl+alt+t
        try {
            //6. 通过shiro进行登录,即身份验证
            subject.login(token);
            System.out.println("登录成功");
        } catch (AuthenticationException e) {
            System.out.println("登录失败");
        }
        Assert.assertTrue(subject.isAuthenticated());//断言是否登录 同下：
        System.out.println("是否已经登录："+(subject.isAuthenticated()?"是":"没有"));
        // 7. 判断是否拥有 某角色/权限
        System.out.println("是否有admin角色："+(ShiroUtil.hasRole("admin")?"有的":"没有"));
        System.out.println("是否有addProduct的权限："+(ShiroUtil.isPermitted("addProduct")?"有":"没有"));
        subject.logout();
    }
}
