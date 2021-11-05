
## Shiro 基础知识
项目GitHub地址：[https://github.com/vihem/shiro_demo.git](https://github.com/vihem/shiro_demo.git)

### 一、shiro 基本流程 -- 见 shiro1
1. 获取 SecurityManager 的工厂：Factory<SecurityManager> factory = ...;
2. 从工厂中获取 SecurityManager 的实例：SecurityManager securityManager = factory.getInstance();
3. 把 securityManager 实例绑定到全局 SecurityUtils：SecurityUtils.setSecurityManager(securityManager);
4. 获取当前 主体(subject)/用户：Subject subject = SecurityUtils.getSubject();
5. 对传进来的用户名/密码进行UsernamePasswordToken封装：new UsernamePasswordToken(用户名,密码);
6. 通过shiro进行登录：subject.login(token)
7. 判断是否拥有 某角色/权限：subject.hasRole(role);/subject.isPermitted(permit);

### 二、Realm -- 见 shiro2
1. 继承 AuthorizingRealm，并继承里面的两个方法；
2. AuthenticationInfo doGetAuthenticationInfo：认证信息的处理，调用 subject.login(token); 时，进入该函数；
3. AuthorizationInfo doGetAuthorizationInfo：授权信息的处理，能进入该函数，表示已经验证了账号信息；在调用其他方法时会进入该函数，比如获取角色、权限信息等；
4. 可以自定义多个Realm。

**身份认证流程**：
1. 首先调用 Subject.login(token) 进行登录，其会自动委托给 Security Manager，调用之前必须通过 SecurityUtils.setSecurityManager() 设置；
2. SecurityManager 负责真正的身份验证逻辑，它会委托给 Authenticator 进行身份验证；
3. Authenticator 才是真正的身份验证者，Shiro API 中核心的身份认证入口点，此处可以自定义插入自己的实现；
4. Authenticator 可能会委托给相应的 AuthenticationStrategy 进行多 Realm 身份验证，默认 ModularRealmAuthenticator 会调用 AuthenticationStrategy 进行多 Realm 身份验证；
5. Authenticator 会把相应的 token 传入 Realm，从 Realm 获取身份验证信息，如果没有返回 / 抛出异常表示身份验证成功了。此处可以配置多个 Realm，将按照相应的顺序及策略进行访问。

**身份验证的步骤**：
1. 收集用户身份/凭证，即如用户名/密码；
2. 调用 Subject.login 进行登录，如果失败将得到相应的 AuthenticationException 异常，根据异常提示用户错误信息；否则登录成功；
3. 最后调用 Subject.logout 进行退出操作。
   如上测试的几个问题：
   用户名 / 密码硬编码在 ini 配置文件，以后需要改成如数据库存储，且密码需要加密存储；
   用户身份 Token 可能不仅仅是用户名 / 密码，也可能还有其他的，如登录时允许用户名 / 邮箱 / 手机号同时登录。

### 三、shiro3 md5加密 -- 见 shiro3
1. 使用了两个 realm：
    1. DatabaseRealm：把用户通过 UsernamePasswordToken 传进来的密码，以及数据库里取出来的 salt 进行加密，加密之后再与数据库里的密文进行比较，判断用户是否能够通过验证。
    2. DatabaseRealm2：身份验证时直接把盐salt/md5一起放入了 SimpleAuthenticationInfo，使用Shiro提供的 HashedCredentialsMatcher 进行验证。
2. 修改了shiro.ini
```ini
[main]
credentialsMatcher=org.apache.shiro.authc.credential.HashedCredentialsMatcher
credentialsMatcher.hashAlgorithmName=md5
credentialsMatcher.hashIterations=2
credentialsMatcher.storedCredentialsHexEncoded=true

databaseRealm=cn.ea.shiro.DatabaseRealm2
databaseRealm.credentialsMatcher=$credentialsMatcher
securityManager.realms=$databaseRealm
```
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