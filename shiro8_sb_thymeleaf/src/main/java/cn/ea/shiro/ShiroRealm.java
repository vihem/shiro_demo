package cn.ea.shiro;

import cn.ea.entity.User;
import cn.ea.service.PermissionService;
import cn.ea.service.RoleService;
import cn.ea.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;

public class ShiroRealm extends AuthorizingRealm {
    
    @Resource private UserService userService;
    @Resource private RoleService roleService;
    @Resource private PermissionService permissionService;
    
    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 1. 获取主体
        String username = principals.getPrimaryPrincipal().toString();
        // 2. 创建 授权信息 对象
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 3. 添加 授权信息 相应的 角色/权限
        info.addRoles(roleService.listRoleNames(username));
        info.addStringPermissions(permissionService.listPermissions(username));
        return info;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 1. 获取 输入的用户名
        String username = (String) token.getPrincipal();
        // 2. 获取 数据库中的用户信息
        User user = userService.getByName(username);
        if (null == user) throw new AuthenticationException();
        // 3. 返回 认证信息
        return new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getSalt()), getName());
    }
}
