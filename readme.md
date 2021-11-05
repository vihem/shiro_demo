
&nbsp;

> **项目GitHub地址：[https://github.com/vihem/shiro_demo](https://github.com/vihem/shiro_demo)** \
> **项目Gitee地址：[https://gitee.com/vihem/shiro_demo](https://gitee.com/vihem/shiro_demo)** \
> **CSDN地址：[https://blog.csdn.net/vihem/article/details/121153003](https://blog.csdn.net/vihem/article/details/121153003)** \
> **本文需要与项目对应学习** \
> MySQL版本：8.0.22\
> shiro版本：1.7.1\
> jdk 1.8\
> idea

---
### 一、shiro 基本流程
项目见：[shiro1](https://github.com/vihem/shiro_demo/tree/master/shiro1)

1. 获取 SecurityManager 的工厂：Factory<SecurityManager> factory = ...;
2. 从工厂中获取 SecurityManager 的实例：SecurityManager securityManager = factory.getInstance();
3. 把 securityManager 实例绑定到全局 SecurityUtils：SecurityUtils.setSecurityManager(securityManager);
4. 获取当前 主体(subject)/用户：Subject subject = SecurityUtils.getSubject();
5. 对传进来的用户名/密码进行UsernamePasswordToken封装：new UsernamePasswordToken(用户名,密码);
6. 通过shiro进行登录：subject.login(token)
7. 判断是否拥有 某角色/权限：subject.hasRole(role);/subject.isPermitted(permit);

```java
public void test(){
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
    subject.logout();//登出登录
}
```

### 二、Realm
项目见：[shiro2](https://github.com/vihem/shiro_demo/tree/master/shiro2)

1. 继承 AuthorizingRealm，并继承里面的两个方法；
2. AuthenticationInfo doGetAuthenticationInfo：认证信息的处理，调用 subject.login(token); 时，进入该函数；
3. AuthorizationInfo doGetAuthorizationInfo：授权信息的处理，能进入该函数，表示已经验证了账号信息；在调用其他方法时会进入该函数，比如获取角色、权限信息等；
4. 可以自定义多个Realm。

![身份认证流程 ](https://img-blog.csdnimg.cn/e855d5b32f394ae2a31055ae1b2004e4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAdmloZW0=,size_20,color_FFFFFF,t_70,g_se,x_16)

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

```java
public class DatabaseRealm extends AuthorizingRealm {
    @Override
    public String getName(){return "databaseRealm";}
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 能进入这里，表示账号已经通过验证了
        System.out.println(" --> DatabaseRealm -> AuthorizationInfo 授权信息");
        // 1. 获取用户名
        String username = (String) principals.getPrimaryPrincipal();
        // 2. 从数据库中获取角色和权限
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
        // 2. 获取 数据库的密码
        String dbPwd = new Dao().getPassword(username);
        if (dbPwd == null || !dbPwd.equals(entryPwd)){
            //如果为空就是账号不存在，如果不相同就是密码错误，但是都抛出 AuthenticationException，而不是抛出具体错误原因，免得给破解者提供帮助信息
            throw new AuthenticationException();
        }
        // 3. 返回认证信息，存放账号密码
        return new SimpleAuthenticationInfo(username, entryPwd, getName());
    }
}
```

### 三、shiro3 md5加密
项目见：[shiro3](https://github.com/vihem/shiro_demo/tree/master/shiro3)

1. 使用了两个 realm：（通常使用DatabaseRealm2的形式）
    1. DatabaseRealm：把用户通过 UsernamePasswordToken 传进来的密码，以及数据库里取出来的 salt 进行加密，加密之后再与数据库里的密文进行比较，判断用户是否能够通过验证。
    2. DatabaseRealm2：身份验证时直接把盐salt/md5一起放入了 SimpleAuthenticationInfo，使用Shiro提供的 HashedCredentialsMatcher 进行验证。
   ```java
   public class DatabaseRealm2 extends AuthorizingRealm {
       @Override
       public String getName(){return "databaseRealm2";}
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
   ```

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
### 四、shiro 与 web 的搭配
项目见：[shiro4_web](https://github.com/vihem/shiro_demo/tree/master/shiro4_web)

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
2. LoginServlet 映射路径/login的访问。
   ```java
   @WebServlet(name = "loginServlet", urlPatterns = "/login")
   public class LoginServlet extends HttpServlet {
       @Override
       protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
           // 获取账号和密码，然后组成 UsernamePasswordToken 对象，扔给Shiro进行判断。
           String username = req.getParameter("name");
           String password = req.getParameter("password");
           UsernamePasswordToken token = new UsernamePasswordToken(username, password);
   
           Subject subject = SecurityUtils.getSubject();
           // 如果subject.login(token)不报错，即表示成功，客户端跳转到根目录，否则返回login.jsp，并带上错误信息
           try {
               subject.login(token);
               // 登录成功后还会把subject放在shiro的session对象里，shiro的这个session和httpsession之间是同步的，
               //		所以在这里放了，它会自动放在httpsession里。
               Session session = subject.getSession();
               session.setAttribute("subject",subject);
               
               resp.sendRedirect("index.jsp");//响应发送到index.jsp页面
           } catch (AuthenticationException e) {
               req.setAttribute("error", "验证失败");
               req.getRequestDispatcher("login.jsp").forward(req,resp);//转发到login.jsp
           }
       }
   }
   ```
3. Realm 进行认证和授权
4. 启动 tomcat7 ：访问[http://localhost:8080/](http://localhost:8080/)

### 五、shiro 配置 ssm
项目见：[shiro5_ssm](https://github.com/vihem/shiro_demo/tree/master/shiro5_ssm)。

1. 使用spring springmvc mybatis
2. realm 使用 service 查询用户/角色/权限
   ```java
   public class DatabaseRealm extends AuthorizingRealm {
       @Autowired
       private UserService userService;
       @Autowired
       private RoleService roleService;
       @Autowired
       private PermissionService permissionService;
       
       @Override
       protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
           // 能进入这里，表示账号已经通过验证了
           // 1. 获取用户名
           String username = (String) principals.getPrimaryPrincipal();
           // 2. 获取角色和权限
           Set<String> roles = roleService.listRoles(username);
           Set<String> permissions = permissionService.listPermissions(username);
           // 3. 创建 授权信息 对象
           SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
           // 4. 添加相应的 角色 和 权限
           info.addRoles(roles);
           info.addStringPermissions(permissions);
           return info;
       }
       @Override
       protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
           // 1. 获取输入的 用户名
           String username = (String) token.getPrincipal();
           // 2. 获取数据库中用户信息
           User user = userService.getUserByName(username);
           if (user == null) throw new AuthenticationException();
           // 3. 返回认证信息，存放 输入的 账号密码
           return new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getSalt()), getName());
       }
   }
   ```
3. applicationContext.xml 配置数据库信息
4. applicationContext-shiro.xml 配置shiro相关信息，代替了原来的shiro.ini
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns="http://www.springframework.org/schema/beans"
          xmlns:util="http://www.springframework.org/schema/util"
          xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans-4.0.xsd 
       http://www.springframework.org/schema/util
       http://www.springframework.org/schema/util/spring-util.xsd">
       
       <!-- 配置shiro的过滤器工厂类，id- shiroFilter要和我们在web.xml中配置的过滤器一致 -->
       <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
           <!-- 调用我们配置的权限管理器 -->
           <property name="securityManager" ref="securityManager" />
           <!-- 配置我们的登录请求地址 -->
           <property name="loginUrl" value="/login" />
           <!-- 如果您请求的资源不再您的权限范围，则跳转到/403请求地址 -->
           <property name="unauthorizedUrl" value="/unauthorized" />
           <!-- 退出 -->
           <property name="filters">
               <util:map>
                   <entry key="logout" value-ref="logoutFilter" />
               </util:map>
           </property>
           <!-- 权限配置 -->
           <property name="filterChainDefinitions">
               <value>
                   <!-- anon表示此地址不需要任何权限即可访问 -->
                   /login=anon
                   /index=anon
                   /static/**=anon
                   /doLogout=logout
                   <!--所有的请求(除去配置的静态资源请求或请求地址为anon的请求)都要通过登录验证,如果未登录则跳到/login -->
                   /** = authc
               </value>
           </property>
       </bean>
       <!-- 退出过滤器 -->
       <bean id="logoutFilter" class="org.apache.shiro.web.filter.authc.LogoutFilter">
           <property name="redirectUrl" value="/index" />
       </bean>
       
       <!-- 会话ID生成器 -->
       <bean id="sessionIdGenerator"
             class="org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator" />
       <!-- 会话Cookie模板 关闭浏览器立即失效 -->
       <bean id="sessionIdCookie" class="org.apache.shiro.web.servlet.SimpleCookie">
           <constructor-arg value="sid" />
           <property name="httpOnly" value="true" />
           <property name="maxAge" value="-1" />
       </bean>
       <!-- 会话DAO -->
       <bean id="sessionDAO"
             class="org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO">
           <property name="sessionIdGenerator" ref="sessionIdGenerator" />
       </bean>
       <!-- 会话验证调度器，每30分钟执行一次验证 ，设定会话超时及保存 -->
       <bean name="sessionValidationScheduler"
             class="org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler">
           <property name="interval" value="1800000" />
           <property name="sessionManager" ref="sessionManager" />
       </bean>
       <!-- 会话管理器 -->
       <bean id="sessionManager"
             class="org.apache.shiro.web.session.mgt.DefaultWebSessionManager">
           <!-- 全局会话超时时间（单位毫秒），默认30分钟 -->
           <property name="globalSessionTimeout" value="1800000" />
           <property name="deleteInvalidSessions" value="true" />
           <property name="sessionValidationSchedulerEnabled" value="true" />
           <property name="sessionValidationScheduler" ref="sessionValidationScheduler" />
           <property name="sessionDAO" ref="sessionDAO" />
           <property name="sessionIdCookieEnabled" value="true" />
           <property name="sessionIdCookie" ref="sessionIdCookie" />
       </bean>
       
       <!-- 安全管理器 -->
       <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
           <property name="realm" ref="databaseRealm" />
           <property name="sessionManager" ref="sessionManager" />
       </bean>
       <!-- 相当于调用SecurityUtils.setSecurityManager(securityManager) -->
       <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
           <property name="staticMethod" value="org.apache.shiro.SecurityUtils.setSecurityManager" />
           <property name="arguments" ref="securityManager" />
       </bean>
       
       <!-- 声明 shiro Realm-->
       <bean id="databaseRealm" class="cn.ea.shiro.DatabaseRealm" />
       
       <!-- 保证实现了Shiro内部lifecycle函数的bean执行 -->
       <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor" />
   </beans>
   ```
5. springmvc.xml 配置mvc/servlet信息，启动shiro注解，配置控制器异常处理 cn.ea.exception.DefaultExceptionHandler
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <beans xmlns="http://www.springframework.org/schema/beans"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:context="http://www.springframework.org/schema/context"
          xmlns:mvc="http://www.springframework.org/schema/mvc"
          xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
           http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context-3.0.xsd
           http://www.springframework.org/schema/mvc http://www.springframework.org/schema/mvc/spring-mvc-3.2.xsd">
       
       <context:annotation-config/>
       <context:component-scan base-package="cn.ea.controller">
           <context:include-filter type="annotation" expression="org.springframework.stereotype.Controller"/>
       </context:component-scan>
       <mvc:annotation-driven />
       <mvc:default-servlet-handler />
       
       <bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">
           <property name="viewClass" value="org.springframework.web.servlet.view.JstlView" />
           <property name="prefix" value="/WEB-INF/jsp/" />
           <property name="suffix" value=".jsp" />
       </bean>
       
       <!--启用shiro注解 -->
       <bean class="org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator"
               depends-on="lifecycleBeanPostProcessor">
           <property name="proxyTargetClass" value="true" />
       </bean>
       <bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
           <property name="securityManager" ref="securityManager" />
       </bean>
       
       <!-- 控制器异常处理 -->
       <bean id="exceptionHandlerExceptionResolver" 
             class="org.springframework.web.servlet.mvc.method.annotation.ExceptionHandlerExceptionResolver" />
       <bean class="cn.ea.exception.DefaultExceptionHandler"/>
   </beans>
   ```
   ```java
   /**
    * 当发生UnauthorizedException 异常的时候，就表示访问了无授权的资源，
    * 那么就会跳转到unauthorized.jsp，
    * 而在unauthorized.jsp 中就会把错误信息通过变量 ex 取出来。
    * 
    * DefaultExceptionHandler 的使用，是声明在 springMVC.xml 的最后几行：
    */
   @ControllerAdvice
   public class DefaultExceptionHandler {
       
       @ExceptionHandler({UnauthorizedException.class})
       @ResponseStatus(HttpStatus.UNAUTHORIZED)
       public ModelAndView processUnauthenticatedException(NativeWebRequest request, UnauthorizedException exception){
           ModelAndView mv = new ModelAndView();
           mv.addObject("ex", exception);
           mv.setViewName("unauthorized");
           return mv;
       }
   }
   ```

6. 添加 PageController 专门用于显示页面的控制器；LoginController 登录控制器
   **在 PageController  中加了 `@RequiresPermissions("xxx")` 来对浏览器访问的链接需要xxx权限，加`@RequiresRoles("admin")` 表示需要admin角色。**
   ```java
   /**
    * 专门用于显示页面的控制器
    * 因为使用 ssm，所以jsp通常都会放在WEB-INF/jsp 下面，而这个位置是无法通过浏览器直接访问的，所以就会专门做这么一个类，便于访问这些jsp。
    * 比如要访问WEB-INF/jsp/index.jsp文件，那么就通过/index 这个路径来访问。
    */
   @Controller
   @RequestMapping("")
   public class PageController {
       
       @RequestMapping("index")
       public String index(){ return "index"; }
   
       @RequiresPermissions("deleteOrder") //@RequiresPermissions("deleteOrder") 指明了 访问 deleteOrder 需要权限"deleteOrder" 
       @RequestMapping("deleteOrder")
       public String deleteOrder(){
           return "deleteOrder";
       }
       
       @RequiresRoles("admin")    //@RequiresRoles("admin") 指明了 访问 deleteProduct 需要角色"admin"
       @RequestMapping("deleteProduct")
       public String deleteProduct(){
           return "deleteProduct";
       }
       
       @RequestMapping("listProduct")
       public String listProduct(){
           return "listProduct";
       }
   
       // /login 只支持get方式。 post方式是后续用来进行登录行为的，这里的get方式仅仅用于显示登录页面
       @RequestMapping(value="/login", method = RequestMethod.GET)
       public String login(){
           return "login";
       }
       
       @RequestMapping("unauthorized")
       public String noPerms(){
           return "unauthorized";
       }
   }
   ```
   ```java
   @Controller
   @RequestMapping("")
   public class LoginController {
       // 和LoginServlet一样，只是对账号密码进行验证，这里用post，PageController的登录使用get
       @RequestMapping(value="/login",method = RequestMethod.POST)
       public String login(Model model, String name, String password){
           Subject subject = SecurityUtils.getSubject();
           UsernamePasswordToken token = new UsernamePasswordToken(name, password);
           try {
               subject.login(token);
               Session session = subject.getSession();
               session.setAttribute("subject", subject);
               return "redirect:index";
           } catch (AuthenticationException e) {
               model.addAttribute("error", "登录失败");
               return "login";
           }
       }
   }
   ```
7. web.xml
    1. spring的配置文件；
    2. spring mvc核心：
    3. 分发servlet；shiro 配置
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns="http://java.sun.com/xml/ns/javaee"
            xmlns:web="http://java.sun.com/xml/ns/javaee"
            xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" version="2.5">
       
       <!-- 1. spring的配置文件-->
       <context-param>
           <param-name>contextConfigLocation</param-name>
           <param-value>
               classpath:applicationContext.xml,
               classpath:applicationContext-shiro.xml
           </param-value>
       </context-param>
       <listener>
           <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
       </listener>
       <!-- 2. spring mvc核心：分发servlet -->
       <servlet>
           <servlet-name>mvc-dispatcher</servlet-name>
           <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
           <!-- spring mvc的配置文件 -->
           <init-param>
               <param-name>contextConfigLocation</param-name>
               <param-value>classpath:springmvc.xml</param-value>
           </init-param>
           <load-on-startup>1</load-on-startup>
       </servlet>
       <servlet-mapping>
           <servlet-name>mvc-dispatcher</servlet-name>
           <url-pattern>/</url-pattern>
       </servlet-mapping>
       <!-- 3. shiro 配置-->
       <filter>
           <filter-name>shiroFilter</filter-name>
           <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
           <init-param>
               <param-name>targetFilterLifecycle</param-name>
               <param-value>true</param-value>
           </init-param>
       </filter>
       <filter-mapping>
           <filter-name>shiroFilter</filter-name>
           <url-pattern>/*</url-pattern>
       </filter-mapping>
   </web-app>
   ```

### 六、进行权限维护
项目见：[shiro6_ssm2](https://github.com/vihem/shiro_demo/tree/master/shiro6_ssm2)

1. 修改了数据库表结构
2. 添加 用户/角色/权限 管理页面
3. 添加 用户/角色/权限 三个控制器
4. web.xml 加一个 中文过滤器（不加也行）
   ```java
   <!-- 中文过滤器 -->
   <filter>
       <filter-name>CharacterEncodingFilter</filter-name>
       <filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
       <init-param>
           <param-name>encoding</param-name>
           <param-value>utf-8</param-value>
       </init-param>
   </filter>
   <filter-mapping>
       <filter-name>CharacterEncodingFilter</filter-name>
       <url-pattern>/*</url-pattern>
   </filter-mapping>
   ```
5. DatabaseRealm 的 doGetAuthorizationInfo 改为 roleService.listRoleNames
6. /config/**=anon  表示 /config/路径下的不需要权限

### 七、基于URL配置权限，进行权限维护
项目见：[shiro7_ssm3](https://github.com/vihem/shiro_demo/tree/master/shiro7_ssm3)

通过URL配置来灵活设置权限，而不是非要在Controller里通过注解来做了
1. PermissionService.java
   增加了两个方法 needInterceptor，listPermissionURLs
   ```java
   /**
    * 判断依据是如果访问的某个url,在权限系统里存在，就要进行拦截。 如果不存在，就放行了。
    * 这一种策略，也可以切换成另一个，即，访问的地址如果不存在于权限系统中，就提示没有拦截。 
    * 这两种做法没有对错之分，取决于业务上希望如何制定权限策略。
    */
   @Override
   public boolean needInterceptor(String requestURI) {
       List<Permission> permissions = this.list();
       for (Permission p : permissions){
           if (p.getUrl().equals(requestURI)){
               return true;
           }
       }
       return false;
   }
   /**
    * 获取某个用户所拥有的 权限地址url 集合
    */
   @Override
   public Set<String> listPermissionURLs(String username) {
       // 1. 查询所有的角色
       List<Role> roles = roleService.listRoles(username);
       // 2. 根据 roleId->rid，查询所有的权限id
       List<RolePermission> rolePermissions = new ArrayList<>();
       for (Role role : roles) {
           RolePermissionExample example = new RolePermissionExample();
           example.createCriteria().andRidEqualTo(role.getId());
           List<RolePermission> rps = rolePermissionMapper.selectByExample(example);
           rolePermissions.addAll(rps);
       }

       // 3. 获取权限表 中对应的 url字段值： /addProduct /deleteProduct。。。
       Set<String> result = new HashSet<>();
       for (RolePermission rolePermission : rolePermissions){
           Permission p = permissionMapper.selectByPrimaryKey(rolePermission.getPid());
           result.add(p.getUrl());
       }
       return result;// 返回： /addProduct /deleteProduct。。。
   }
   ```
2. URLPathMatchingFilter 继承了 PathMatchingFilter，PathMatchingFilter 是 shiro 内置过滤器。
   基本思路如下：
    1. 如果没登录就跳转到登录
    2. 如果当前访问路径没有在权限系统里维护，则允许访问
    3. 当前用户所拥有的权限如果不包含当前的访问地址，则跳转到/unauthorized，否则就允许访问
   ```java
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
   ```

3. applicationContext-shiro.xml 声明 URLPathMatchingFilter 过滤器

### 八、shiro 使用 spring boot + mybatis + jsp
项目见：[shiro8_sb](https://github.com/vihem/shiro_demo/tree/master/shiro8_sb)

1. 使用 ShiroConfiguration 代替 applicationContext-shiro.xml
   ```java
   @Configuration
   public class ShiroConfiguration {
       // 保证实现了Shiro内部lifecycle函数的bean执行;
       // 管理shiro一些bean的生命周期
       @Bean
       public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
           return new LifecycleBeanPostProcessor();
       }
   
       /**
        * ShiroFilterFactoryBean 处理拦截资源文件问题。
        * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，因为在
        * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
        * Filter Chain定义说明
        *      1、一个URL可以配置多个Filter，使用逗号分隔
        *      2、当设置多个过滤器时，全部验证通过，才视为通过
        *      3、部分过滤器可指定参数，如perms，roles
        */
       @Bean
       public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager){
           // 1. 自定义拦截器
           Map<String, Filter> customisedFilter = new HashMap<>();
           customisedFilter.put("url", getURLPathMatchingFilter());
   
           // 2. 定义拦截器规则
           Map<String, String> map = new LinkedHashMap<>();
           map.put("/login", "anon");
           map.put("/index", "anon");
           map.put("/static/**", "anon");
           map.put("/config/**", "anon");
           map.put("/doLogout", "logout");
           map.put("/**", "url");
           
           // 3. 配置 shiro过滤器bean 的相关规则
           ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
           //      必须设置 SecurityManager
           shiroFilterFactoryBean.setSecurityManager(securityManager);
           //      如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
           shiroFilterFactoryBean.setLoginUrl("/login");
           //      登录成功后要跳转的链接 /index
           shiroFilterFactoryBean.setSuccessUrl("/index");
           //      未授权界面 /unauthorized
           shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
           //      装配自定义的过滤器
           shiroFilterFactoryBean.setFilters(customisedFilter);
           //      配置拦截器规则
           shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
   
           return shiroFilterFactoryBean;
       }
   
       /**
        * 需要注意一点，URLPathMatchingFilter 并没有用@Bean管理起来。 
        * 原因是Shiro的bug, 这个也是过滤器，ShiroFilterFactoryBean 也是过滤器，
        * 当他们都出现的时候，默认的什么 anon,authc,logout过滤器就失效了。所以不能把他声明为@Bean。
        */
   //    @Bean
       public URLPathMatchingFilter getURLPathMatchingFilter(){
           return new URLPathMatchingFilter();
       }
       
       @Bean
       public SecurityManager securityManager(){
           DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
           securityManager.setRealm(getDatabaseRealm());
           return securityManager;
       }
       @Bean
       public DatabaseRealm getDatabaseRealm(){
           DatabaseRealm myShiroRealm = new DatabaseRealm();
           myShiroRealm.setCredentialsMatcher(hashedCredentialsMatcher());
           return myShiroRealm;
       }
       /**
        * 凭证匹配器
        * （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了
        *  所以我们需要修改下doGetAuthenticationInfo中的代码;）
        */
       @Bean
       public HashedCredentialsMatcher hashedCredentialsMatcher(){
           HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
           hashedCredentialsMatcher.setHashAlgorithmName("md5");//散列算法:这里使用MD5算法;
           hashedCredentialsMatcher.setHashIterations(2);//散列的次数，比如散列两次，相当于 md5(md5(""));
           return hashedCredentialsMatcher;
       }
   
       /**
        *  开启shiro aop注解支持.
        *  使用代理方式;所以需要开启代码支持;
        */
       @Bean
       public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
           AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
           advisor.setSecurityManager(securityManager);
           return advisor;
       }
   }
   ```
2.  上面 URLPathMatchingFilter 没有被声明为@Bean，所以 URLPathMatchingFilter 就没有被Spring管理起来，那么也就无法在里面注入 PermissionService类了。
    但是在业务上 URLPathMatchingFilter 里面又必须使用PermissionService类，
    所以就借助SpringContextUtils 这个工具类，来获取PermissionService的实例。
    ```java
    @Component
    public class SpringContextUtils implements ApplicationContextAware {
        private static ApplicationContext context;
    
        public void setApplicationContext(ApplicationContext context) throws BeansException {
            SpringContextUtils.context = context;
        }
    
        public static ApplicationContext getContext(){
            return context;
        }
    } 
    ```

3. 对应的，在URLPathMatchingFilter 添加
   `if (null == permissionService){permissionService = SpringContextUtils.getContext().getBean(PermissionService.class);}`
4. 实际启动方式：使用maven启动，maven -> 项目 -> Plugins -> spring-boot -> spring-boot:run

### 九、使用 spring boot + mybatis +  html
把上一节的jsp，改为thymeleaf，是spring boot更为常用的模式。
见项目：[shiro8_sb_thymeleaf](https://github.com/vihem/shiro_demo/tree/master/shiro8_sb_thymeleaf)


---
若有不正之处，请谅解和批评指正，谢谢~
转载请标明：
[https://blog.csdn.net/vihem/article/details/121153003](https://blog.csdn.net/vihem/article/details/121153003)