package cn.ea.shiro;

import cn.ea.dao.Dao;
import cn.ea.entity.User;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.Set;

public class DatabaseRealm2 extends AuthorizingRealm {

    @Override
    public String getName(){return "databaseRealm2";}
    
    //授权信息
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 能进入这里，表示账号已经通过验证了
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

    //身份验证信息
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println(this.getCredentialsMatcher());
        // 1. 获取输入的 用户名
        String username = (String) token.getPrincipal();
        
        // 2. 获取 数据库的密码/盐
        User user = new Dao().getUser(username);
        String dbPwd = user.getPassword();
        String salt = user.getSalt();
        
        // 3. 返回认证信息，存放 数据库的 账号密码
        //  盐也放进去
        //  这样通过shiro.ini里配置的 HashedCredentialsMatcher 进行自动校验
        return new SimpleAuthenticationInfo(username, dbPwd, ByteSource.Util.bytes(salt), getName());
    }
}
