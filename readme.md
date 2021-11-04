
## shiro_demo

### 一、shiro 基本流程
1. 获取 SecurityManager 的工厂：Factory<SecurityManager> factory = ...;
2. 从工厂中获取 SecurityManager 的实例：SecurityManager securityManager = factory.getInstance();
3. 把 securityManager 实例绑定到全局 SecurityUtils：SecurityUtils.setSecurityManager(securityManager);
4. 获取当前 主体(subject)/用户：Subject subject = SecurityUtils.getSubject();
5. 对传进来的用户名/密码进行UsernamePasswordToken封装：new UsernamePasswordToken(用户名,密码);
6. 通过shiro进行登录：subject.login(token)
7. 判断是否拥有 某角色/权限：subject.hasRole(role);/subject.isPermitted(permit);

### 二、Realm 
1. 继承 AuthorizingRealm，并继承里面的两个方法；
2. AuthenticationInfo doGetAuthenticationInfo：认证信息的处理，调用 subject.login(token); 时，进入该函数；
3. AuthorizationInfo doGetAuthorizationInfo：授权信息的处理，能进入该函数，表示已经验证了账号信息；在调用其他方法时会进入该函数，比如获取角色、权限信息等；
4. 可以自定义多个Realm。

### 三、shiro3 md5加密
1. 使用了两个 realm

### 四、shiro4_web：shiro 与 web 的搭配
1. 在shiro.ini中配置哪些url链接需要哪些角色/权限，以及无权限/角色的跳转
    1. [main]: 
       1. 配置 realm；
       2. 访问需要验证，但无验证：authc.loginUrl
       3. 访问需要角色，但无角色：roles.unauthorizedUrl
       4. 访问需要权限，但无权限：perms.unauthorizedUrl
    2. [urls]：
       1. logout：退出
       2. anon：可以匿名访问
       3. authc：需要登录验证
       4. roles[]/perms[]：需要某些角色/权限
2. Realm 进行认证和授权 

### 五、shiro5_ssm
1. 使用spring springmvc mybatis
2. realm 使用 service 查询用户/角色/权限
3. applicationContext.xml 配置数据库信息
4. applicationContext-shiro.xml 配置shiro相关信息
5. springmvc.xml 配置mvc/servlet信息，配置控制器异常处理 cn.ea.exception.DefaultExceptionHandler
6. 添加 PageController 专门用于显示页面的控制器；LoginController 登录控制器
7. web.xml
   1. spring的配置文件；
   2. spring mvc核心：
   3. 分发servlet；shiro 配置

### 六、shiro6_ssm2 可以进行权限维护
1. 修改了数据库表结构
2. 添加 用户/角色/权限 管理页面
3. 添加 用户/角色/权限 三个控制器
4. web.xml 加一个 中文过滤器
5. DatabaseRealm 改为 roleService.listRoleNames
6. /config/**=anon  表示 /config/路径下的不需要权限

### 七、shiro7_ssm3 可以进行权限维护，基于URL配置权限
通过URL配置来灵活设置权限，而不是非要在Controller里通过注解来做了
1. PermissionService.java 
   增加了两个方法 needInterceptor，listPermissionURLs
2. PathMatchingFilter 是shiro 内置过滤器 PathMatchingFilter 继承了这个它。
3. applicationContext-shiro.xml 声明 过滤器

### 八、shiro8_sb 可以进行权限维护，使用 spring boot + mybatis + jsp
1. 实际启动方式：使用maven启动，maven -> 项目 -> Plugins -> spring-boot -> spring-boot:run
2. ShiroConfiguration 对应 applicationContext-shiro.xml 
3. SpringContextUtils 

因为 ShiroConfiguration 中的 URLPathMatchingFilter 并没有用@Bean管理起来。
原因是Shiro的bug, URLPathMatchingFilter 也是过滤器，ShiroFilterFactoryBean 也是过滤器，\
当他们都出现的时候，默认的什么anno,authc,logout过滤器就失效了。
所以不能把他声明为@Bean。
5. URLPathMatchingFilter
添加 if (null == permissionService){permissionService = SpringContextUtils.getContext().getBean(PermissionService.class);}

### 九、shiro9_sb_html 可以进行权限维护，使用 spring boot + html
thymeleaf 见项目