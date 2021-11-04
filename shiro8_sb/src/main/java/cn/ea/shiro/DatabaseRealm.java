package cn.ea.shiro;

import cn.ea.entity.User;
import cn.ea.service.PermissionService;
import cn.ea.service.RoleService;
import cn.ea.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;

public class DatabaseRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;
    @Resource
    private RoleService roleService;
    @Resource
    private PermissionService permissionService;
    
    @Override
    public String getName(){return "databaseRealm";}
    
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 能进入这里，表示账号已经通过验证了
        System.out.println(" --> DatabaseRealm -> AuthorizationInfo 授权信息");
        // 1. 获取用户名
        String username = (String) principals.getPrimaryPrincipal();
        // 2. 创建 授权信息 对象
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 3. 添加相应的 角色 和 权限
        info.addRoles(roleService.listRoleNames(username));
        info.addStringPermissions(permissionService.listPermissions(username));
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println(" --> DatabaseRealm -> AuthenticationInfo 认证信息");
        // 1. 获取输入的 用户名
        String username = (String) token.getPrincipal();
        
        // 2. 获取数据库中用户信息
//        User user = userService.getUserByName(username);
        User user = userService.getByName(username);
        if (user == null) throw new AuthenticationException();
        
        // 3. 返回认证信息，存放 输入的 账号密码
        return new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getSalt()), getName());
    }
}
