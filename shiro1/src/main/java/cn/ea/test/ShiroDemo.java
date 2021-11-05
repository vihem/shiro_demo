package cn.ea.test;

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
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager 
        //      SecurityManager---->Factory
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();//ctrl+alt+v：快速生成变量及对应的数据类型
        SecurityUtils.setSecurityManager(securityManager);//当前用户：Subject--->SecurityUtils

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();//当前用户
        //  通过UsernamePasswordToken来模拟html/jsp传递过来的用户名与密码
        UsernamePasswordToken token = new UsernamePasswordToken("zhang3","12345");
        //  通过shiro来判断用户是否登录成功;ctrl+alt+t
        try {
            //4、登录，即身份验证
            subject.login(token);
            System.out.println("登录成功");
        } catch (AuthenticationException e) {
            System.out.println("登录失败");
        }
        System.out.println(subject.isAuthenticated());
        Assert.assertTrue(subject.isAuthenticated());
        subject.logout();
    }
}
