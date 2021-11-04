package cn.ea.filter;

import cn.ea.service.PermissionService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Set;

/**
 * PathMatchingFilter 是shiro 内置过滤器 PathMatchingFilter 继承了这个它。
 * 基本思路如下：
 * 1. 如果没登录就跳转到登录
 * 2. 如果当前访问路径没有在权限系统里维护，则允许访问
 * 3. 当前用户所拥有的权限如果不包含当前的访问地址，则跳转到/unauthorized，否则就允许访问
 */
public class URLPathMatchingFilter extends PathMatchingFilter {
    
    @Autowired
    private PermissionService permissionService;

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // 1. 获取当前主体, 并判断是否登录
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()){
            WebUtils.issueRedirect(request, response, "/login");
            return false;
        }
        // 2. 获取 请求链接requestURI，并判断 请求链接requestURI 在(数据库)权限里有没有维护
        String requestURI = super.getPathWithinApplication(request); System.out.println("requestURI:" + requestURI);
        boolean needInterceptor = permissionService.needInterceptor(requestURI);
        if (!needInterceptor){
            return true; // 如果没有维护(即不需要拦截该url)，一律放行(也可以改为一律不放行)
        } else {
            // 3. 当数据库中有维护 requestURI
            boolean hasPermission = false;
            String username = subject.getPrincipal().toString();
            // 4. 获取当前用户 拥有的 所有权限url，并判断 requestURI 是否在里面
            Set<String> permissionURLs = permissionService.listPermissionURLs(username);
            for (String url : permissionURLs){
                if (url.equals(requestURI)){
                    hasPermission = true;   // 当前用户拥有访问 url权限
                    break;
                }
            }
            // 5. 如果拥有 访问requestURI的权限，返回true
            if (hasPermission) return true;
            else {
                UnauthorizedException ex = new UnauthorizedException("当前用户没有访问路径 " + requestURI + " 的权限");
                subject.getSession().setAttribute("ex", ex);
                WebUtils.issueRedirect(request, response, "/unauthorized");
                return false;
            }
        }
    }
}
