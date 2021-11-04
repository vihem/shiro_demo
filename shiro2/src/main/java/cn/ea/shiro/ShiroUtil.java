package cn.ea.shiro;

import cn.ea.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class ShiroUtil {

    public static boolean login(User user) {
        // 1. 获取当前主体
        Subject subject= getSubject();
        //退出 之前已经登录的用户
        if(subject.isAuthenticated()){
            subject.logout();
        }

        // 2. 封装用户的数据
        UsernamePasswordToken token = new UsernamePasswordToken(user.getName(), user.getPassword());
        try {
            // 3. 将用户的数据token 最终传递到Realm中进行对比
            subject.login(token);
        } catch (AuthenticationException e) {
            //验证错误
            return false;
        }
        return subject.isAuthenticated();
    }

    public static boolean hasRole(String role) {
        Subject subject = getSubject();
        return subject.hasRole(role);
    }

    public static boolean isPermitted(String permit) {
        Subject subject = getSubject();
        return subject.isPermitted(permit);
    }

    private static Subject getSubject() {
        //1. 加载配置文件，并获取工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //2. 获取安全管理者实例
        SecurityManager sm = factory.getInstance();
        //3. 将安全管理者放入全局对象
        SecurityUtils.setSecurityManager(sm);
        //4. 全局对象通过安全管理者生成Subject对象
        return SecurityUtils.getSubject();
    }
}
