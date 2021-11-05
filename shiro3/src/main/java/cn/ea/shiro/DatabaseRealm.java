package cn.ea.shiro;

import cn.ea.dao.Dao;
import cn.ea.entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Set;

public class DatabaseRealm extends AuthorizingRealm {

    @Override
    public String getName(){return "databaseRealm";}
    
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 能进入这里，表示账号已经通过验证了
        System.out.println(" --> DatabaseRealm -> AuthorizationInfo 授权信息");
        // 1. 获取用户名
        String username = (String) principals.getPrimaryPrincipal();
        // 2. 获取角色和权限
        Set<String> roles = new Dao().listRoles(username);
        Set<String> permissions = new Dao().listPermissions(username);
        // 3. 创建 授权信息 对象
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 4. 添加相应的 角色 和 权限
        info.addRoles(roles);
        info.addStringPermissions(permissions);
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println(" --> DatabaseRealm -> AuthenticationInfo 认证信息");
        // 1. 获取输入的 用户名/密码
        String username = (String) token.getPrincipal();
        String entryPwd = new String((char[])token.getCredentials());
        // 也可以用下面这种方式 
        // UsernamePasswordToken token1 = (UsernamePasswordToken) token;
        // token1.getUsername(); // new String(token1.getPassword());
        
        //把用户通过 UsernamePasswordToken 传进来的密码，以及数据库里取出来的 salt 进行加密，加密之后再与数据库里的密文进行比较，判断用户是否能够通过验证。
        // 2. 获取 数据库的密码
        User user = new Dao().getUser(username);
        String dbPwd = user.getPassword();
        String salt = user.getSalt();
        String entryPwdEncrypt = ShiroUtil.encryptPassword("md5", entryPwd, salt, 2);
        
        if (user == null || !dbPwd.equals(entryPwdEncrypt)){
            //如果为空就是账号不存在，如果不相同就是密码错误，但是都抛出 AuthenticationException，而不是抛出具体错误原因，免得给破解者提供帮助信息
            throw new AuthenticationException();
        }
        // 3. 返回认证信息，存放 输入的 账号密码
        return new SimpleAuthenticationInfo(username, entryPwd, getName());
    }
}
